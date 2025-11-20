"""
AI analysis functions using Cybersecurity AI (CAI) framework
"""

import json
import os
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

# Handle imports based on execution context
if __name__ == "__main__":
    # When run directly, add parent directory to path for absolute imports
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    from backend.storage import (
        ai_analyses_storage,
        get_scan,
    )
    from backend.projects import (
        get_project,
        get_scans_by_project,
    )
    from backend.data_collection import collect_scan_data_for_analysis
else:
    # When imported as module, use relative imports
    from .storage import (
        ai_analyses_storage,
        get_scan,
    )
    from .projects import (
        get_project,
        get_scans_by_project,
    )
    from .data_collection import collect_scan_data_for_analysis


"""
AI analysis functions using Google ADK
"""


# Google ADK imports
try:
    from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
    from google.adk.models.lite_llm import LiteLlm
    from google.adk.runners import Runner
    from google.adk.sessions.in_memory_session_service import InMemorySessionService
    from google.adk.tools import google_search
    from google.genai import types as genai_types

    import agentops

    ADK_AVAILABLE = True
    AGENTOPS_API_KEY = os.getenv("AGENTOPS_API_KEY")
    if AGENTOPS_API_KEY:
        agentops.init(
            api_key=AGENTOPS_API_KEY,
            default_tags=["google adk"],
        )
except ImportError:
    LlmAgent = None  # type: ignore
    LiteLlm = None  # type: ignore
    LoopAgent = None  # type: ignore
    ParallelAgent = None  # type: ignore
    SequentialAgent = None  # type: ignore
    Runner = None  # type: ignore
    InMemorySessionService = None  # type: ignore
    google_search = None  # type: ignore
    genai_types = None  # type: ignore
    ADK_AVAILABLE = False
    print("Warning: google-adk not available. AI analysis features will be disabled.")


DEFAULT_AGENT_MODEL = os.getenv(
    "AI_ANALYSIS_MODEL", "openrouter/deepseek/deepseek-r1:free"
)
OPENROUTER_API_BASE = os.getenv(
    "OPENROUTER_API_BASE", "https://openrouter.ai/api/v1"
)

try:
    QA_CONFIDENCE_TARGET = float(
        os.getenv("AI_ANALYSIS_QA_TARGET_CONFIDENCE", "0.85")
    )
except ValueError:
    QA_CONFIDENCE_TARGET = 0.85

AGENT_PIPELINE_SUMMARY = [
    {
        "key": "contextualizer_agent",
        "type": "llm",
        "depends_on": [],
        "purpose": "Normalize raw scan telemetry into deterministic context for downstream agents.",
    },
    {
        "key": "insight_parallel",
        "type": "parallel",
        "depends_on": ["contextualizer_agent"],
        "children": ["prioritization_agent", "supply_chain_agent"],
        "purpose": "Fan-out prioritized risk analysis and supply-chain graphing simultaneously.",
    },
    {
        "key": "remediation_loop",
        "type": "loop",
        "depends_on": ["insight_parallel"],
        "children": ["remediation_agent", "qa_review_agent"],
        "max_iterations": 2,
        "purpose": "Iteratively fuse QA feedback into remediation planning until confidence converges.",
    },
    {
        "key": "executive_summary_agent",
        "type": "llm",
        "depends_on": ["remediation_loop"],
        "purpose": "Cohesively narrate risk posture, plan-of-record, and KPIs for stakeholders.",
    },
    {
        "key": "cybersecurity_pipeline",
        "type": "sequential",
        "depends_on": [
            "contextualizer_agent",
            "insight_parallel",
            "remediation_loop",
            "executive_summary_agent",
        ],
        "purpose": "Top-level sequential orchestrator that enforces stage ordering across the program.",
    },
]

AGENT_BLUEPRINTS = {
    "contextualizer": {
        "name": "contextualizer_agent",
        "description": "Normalizes scan telemetry into structured supply-chain context.",
        "state_key": "contextual_summary",
        "instruction": """You operate as the Contextualizer inside a Google ADK multi-agent cell.
Condense any vulnerability or SBOM telemetry into a compact JSON payload with sections:
- environment_overview (assets, tiers, business criticality)
- exposure_hotspots (top 3-5 problem clusters with supporting evidence)
- exploit_signals (EPSS, public exploits, attacker interest)
- telemetry_gaps (missing data you need escalated)
Stability matters: keep key names identical for downstream agents.
- Use the Google Search tool to get more information about the vulnerabilities and supply-chain components.""",
    },
    "prioritization": {
        "name": "prioritization_agent",
        "description": "Calculates risk-weighted backlog ordering for remediation planning.",
        "state_key": "prioritization_report",
        "instruction": """You are the Risk Prioritization officer. Analyze contextual summaries plus raw telemetry.
Blend CVSS, EPSS, exploit chatter, asset blast radius, and compliance urgency.
Return a backlog capped at 10 entries with fields:
rank, item_id (CVE/package/contextual alias), priority_score (0-100), rationale, suggested_owner, and near-term_action.
Reference the Contextualizer keys to stay aligned.""",
    },
    "supply_chain": {
        "name": "supply_chain_agent",
        "description": "Explains upstream/downstream dependency impact and propagation risk.",
        "state_key": "supply_chain_report",
        "instruction": """You are the Supply Chain graph analyst.
Correlate prioritized findings with dependency graphs, SBOM metadata, and pipeline stages.
Highlight: upstream source weaknesses, downstream blast radius, transitive exposures, and build/distribution controls.
Output adjacency insights plus controls to harden the chain.""",
    },
    "remediation": {
        "name": "remediation_agent",
        "description": "Designs actionable remediation and mitigation program.",
        "state_key": "remediation_plan",
        "instruction": """You lead remediation execution.
Use the prioritized backlog and supply-chain map to produce a phased plan:
- quick_wins (fast actions, <7 days)
- strategic_fixes (architecture/process work)
- compensating_controls (if fixes blocked)
Tie every action to backlog IDs and include effort/owner/timebox hints.""",
    },
    "qa_reviewer": {
        "name": "qa_review_agent",
        "description": "Independent reviewer that validates agent coherence and uncovers gaps.",
        "state_key": "qa_review",
        "instruction": """You perform independent QA/compliance review.
Cross-check all upstream agent outputs, note contradictions, missing evidence, risky assumptions, and verification tasks.
Emit JSON with keys: gaps, assumptions, verification_steps, confidence (0-1).""",
    },
    "executive_summary": {
        "name": "executive_summary_agent",
        "description": "Synthesizes a stakeholder-ready narrative and KPIs.",
        "state_key": "executive_summary",
        "instruction": """You are the executive synthesis agent.
Produce a concise narrative that stitches together context, prioritization, supply-chain blast radius, remediation plan, and QA findings.
Include a KPI scoreboard with: exposure_count, high_risk_assets, expected_risk_reduction, remediation_velocity_signal.
Audience: security leadership + engineering program managers.""",
    },
}

AGENT_STATE_KEY_BY_NAME = {
    cfg["name"]: cfg["state_key"]
    for cfg in AGENT_BLUEPRINTS.values()
    if cfg.get("state_key")
}

AGENT_DEPENDENCIES: Dict[str, List[str]] = {
    "prioritization_agent": ["contextual_summary"],
    "supply_chain_agent": ["contextual_summary", "prioritization_report"],
    "remediation_agent": [
        "contextual_summary",
        "prioritization_report",
        "supply_chain_report",
    ],
    "qa_review_agent": [
        "contextual_summary",
        "prioritization_report",
        "supply_chain_report",
        "remediation_plan",
    ],
    "executive_summary_agent": [
        "contextual_summary",
        "prioritization_report",
        "supply_chain_report",
        "remediation_plan",
        "qa_review",
    ],
}


def _build_lite_llm(api_key: str, model_name: Optional[str] = None) -> LiteLlm:
    return LiteLlm(
        model=model_name or DEFAULT_AGENT_MODEL,
        api_key=api_key,
        api_base=OPENROUTER_API_BASE,
    )


def _create_agent(blueprint: Dict[str, str], api_key: str) -> LlmAgent:
    toolset = [google_search] if google_search else []
    return LlmAgent(
        name=blueprint["name"],
        model=_build_lite_llm(api_key),
        instruction=blueprint["instruction"],
        description=blueprint["description"],
        tools=toolset,
    )


def _execute_agent(
    agent: Optional[LlmAgent],
    prompt: str,
    session_state: Optional[Dict[str, Any]] = None,
) -> str:
    return _run_agent_with_runner(agent, prompt, session_state=session_state)


def _build_workflow_agents(agent_map: Dict[str, LlmAgent]) -> Dict[str, Any]:
    """
    Compose Sequential, Parallel, and Loop workflow agents.
    """
    if not (SequentialAgent and ParallelAgent and LoopAgent):
        return {}

    required_keys = [
        "contextualizer",
        "prioritization",
        "supply_chain",
        "remediation",
        "qa_reviewer",
        "executive_summary",
    ]
    if any(key not in agent_map for key in required_keys):
        return {}

    insight_parallel = ParallelAgent(
        name="insight_parallel",
        sub_agents=[
            agent_map["prioritization"],
            agent_map["supply_chain"],
        ],
    )

    remediation_loop = LoopAgent(
        name="remediation_loop",
        sub_agents=[
            agent_map["remediation"],
            agent_map["qa_reviewer"],
        ],
        max_iterations=2,
    )

    pipeline = SequentialAgent(
        name="cybersecurity_pipeline",
        sub_agents=[
            agent_map["contextualizer"],
            insight_parallel,
            remediation_loop,
            agent_map["executive_summary"],
        ],
    )

    return {
        "insight_parallel": insight_parallel,
        "remediation_loop": remediation_loop,
        "pipeline": pipeline,
    }


def _extract_confidence(qa_result: str) -> float:
    if not qa_result:
        return 0.0
    try:
        parsed = json.loads(qa_result)
        confidence_value = parsed.get("confidence")
        if isinstance(confidence_value, (int, float)):
            return max(0.0, min(1.0, float(confidence_value)))
        if isinstance(confidence_value, str):
            return max(0.0, min(1.0, float(confidence_value)))
    except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
        pass

    match = re.search(
        r"confidence[^0-9]*([0-9]*\\.?[0-9]+)",
        qa_result,
        flags=re.IGNORECASE,
    )
    if match:
        try:
            return max(0.0, min(1.0, float(match.group(1))))
        except ValueError:
            pass

    return 0.0


def _wait_for_dependencies(
    state: Dict[str, Any],
    dependencies: List[str],
    timeout_seconds: float = 30.0,
) -> None:
    if not dependencies:
        return
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if all(state.get(dependency) for dependency in dependencies):
            return
        time.sleep(0.05)


def _collect_agent_response(events) -> str:
    final_parts: List[str] = []
    fallback_parts: List[str] = []
    tool_responses: List[str] = []

    for event in events:
        if event.get_function_responses():
            for response in event.get_function_responses():
                try:
                    tool_responses.append(json.dumps(response.response))
                except (TypeError, ValueError, AttributeError):
                    tool_responses.append(str(response.response))

        if event.content and event.content.parts:
            text_segments = [
                (part.text or "").strip()
                for part in event.content.parts
                if getattr(part, "text", None)
            ]
            if text_segments:
                fallback_parts.append("\n".join(s for s in text_segments if s))

        if event.is_final_response() and event.content and event.content.parts:
            for part in event.content.parts:
                if getattr(part, "text", None):
                    final_parts.append(part.text.strip())

    if final_parts:
        return "\n\n".join(segment for segment in final_parts if segment).strip()
    if fallback_parts:
        return fallback_parts[-1].strip()
    if tool_responses:
        return "\n\n".join(tool_responses).strip()
    return "No response generated."


def _run_agent_with_runner(
    agent: Optional[LlmAgent],
    prompt: str,
    session_state: Optional[Dict[str, Any]] = None,
) -> str:
    if not agent:
        return "Error: Agent not initialized."
    if not (Runner and InMemorySessionService and genai_types):
        return "Error: Runner dependencies unavailable."
    try:
        session_service = InMemorySessionService()
        app_name = f"ai_analysis_app_{agent.name}"
        session_id = f"{agent.name}_{uuid.uuid4().hex}"
        user_id = "ai-analysis-user"

        session_service.create_session_sync(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            state=session_state or {},
        )

        runner = Runner(
            agent=agent,
            app_name=app_name,
            session_service=session_service,
        )
        message = genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=prompt)],
        )

        events = runner.run(
            user_id=user_id,
            session_id=session_id,
            new_message=message,
        )
        return _collect_agent_response(events)
    except Exception as exc:
        return f"Error: {exc}"


def _execute_workflow_agent(
    agent_node: Any,
    state: Dict[str, Any],
    prompt_builders: Dict[str, Callable[[Dict[str, Any]], str]],
    state_key_lookup: Dict[str, str],
    agent_outputs: Dict[str, str],
    lock: Lock,
) -> None:
    if LlmAgent and isinstance(agent_node, LlmAgent):
        dependencies = AGENT_DEPENDENCIES.get(agent_node.name, [])
        if dependencies:
            _wait_for_dependencies(state, dependencies)
        builder = prompt_builders.get(agent_node.name)
        if not builder:
            raise ValueError(
                f"No prompt builder registered for agent {agent_node.name}")
        prompt = builder(state)
        result = _execute_agent(agent_node, prompt, session_state=state.copy())
        agent_outputs[agent_node.name] = result
        state_key = state_key_lookup.get(agent_node.name)
        if state_key:
            with lock:
                state[state_key] = result
                if state_key == "qa_review":
                    state["qa_confidence"] = _extract_confidence(result)
        return

    if SequentialAgent and isinstance(agent_node, SequentialAgent):
        for child in getattr(agent_node, "sub_agents", []) or []:
            _execute_workflow_agent(
                child,
                state,
                prompt_builders,
                state_key_lookup,
                agent_outputs,
                lock,
            )
        return

    if ParallelAgent and isinstance(agent_node, ParallelAgent):
        sub_agents = getattr(agent_node, "sub_agents", []) or []
        if not sub_agents:
            return
        with ThreadPoolExecutor(max_workers=len(sub_agents)) as executor:
            futures = [
                executor.submit(
                    _execute_workflow_agent,
                    child,
                    state,
                    prompt_builders,
                    state_key_lookup,
                    agent_outputs,
                    lock,
                )
                for child in sub_agents
            ]
            for future in futures:
                future.result()
        return

    if LoopAgent and isinstance(agent_node, LoopAgent):
        sub_agents = getattr(agent_node, "sub_agents", []) or []
        max_iterations = getattr(agent_node, "max_iterations", 1) or 1
        max_iterations = int(max_iterations)
        for iteration in range(max_iterations):
            with lock:
                state["remediation_iteration"] = iteration + 1
            for child in sub_agents:
                _execute_workflow_agent(
                    child,
                    state,
                    prompt_builders,
                    state_key_lookup,
                    agent_outputs,
                    lock,
                )
            if state.get("qa_confidence", 0.0) >= state.get(
                "qa_target_confidence", QA_CONFIDENCE_TARGET
            ):
                break
        return

    raise ValueError(
        f"Unsupported workflow node type: {getattr(agent_node, 'name', type(agent_node).__name__)}"
    )


def _run_workflow_pipeline(
    pipeline_agent: SequentialAgent,
    state: Dict[str, Any],
    agent_outputs: Dict[str, str],
) -> None:
    prompt_builders = PROMPT_BUILDERS
    state_key_lookup = AGENT_STATE_KEY_BY_NAME
    state.setdefault("qa_target_confidence", QA_CONFIDENCE_TARGET)
    lock = Lock()
    _execute_workflow_agent(
        pipeline_agent, state, prompt_builders, state_key_lookup, agent_outputs, lock
    )


def initialize_ai_agents():
    """
    Initialize AI agents using Google ADK with OpenRouter

    Returns:
        Dictionary containing initialized agents or None if ADK is not available
    """
    if not ADK_AVAILABLE:
        return None

    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        print("Warning: OPENROUTER_API_KEY not set. AI analysis features will be disabled.")
        return None

    try:
        agents = {
            key: _create_agent(blueprint, api_key)
            for key, blueprint in AGENT_BLUEPRINTS.items()
        }

        workflow_agents = _build_workflow_agents(agents)
        agents.update(workflow_agents)

        # Maintain backwards-compatible keys for existing consumers
        agents.setdefault("prioritization", agents.get("prioritization"))
        agents.setdefault("supply_chain", agents.get("supply_chain"))
        agents.setdefault("remediation", agents.get("remediation"))

        return agents

    except Exception as e:
        print(f"Error initializing AI agents: {e}")
        return None


def _build_contextualizer_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    data_json = state.get("data_json", "")
    return f"""You are preparing the shared situational awareness package for project '{project_name}'.
Normalize the raw scan payload below into JSON with the keys: environment_overview, exposure_hotspots,
exploit_signals, telemetry_gaps. Keep the response concise but information-dense.

Raw scan bundle:
{data_json}
"""


def _build_prioritization_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    data_json = state.get("data_json", "")
    context_summary = state.get("contextual_summary", "(context pending)")
    return f"""Project: {project_name}
Contextualizer output:
{context_summary}

Raw scan bundle:
{data_json}

Task:
- Produce a backlog limited to the top 10 issues referencing CVE/package identifiers.
- Each entry must include rank, item_id, priority_score (0-100), rationale, suggested_owner, near_term_action.
- Tie recommendations back to business impact, exploitability, and supply-chain criticality.
"""


def _build_supply_chain_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    context_summary = state.get("contextual_summary", "(context pending)")
    prioritization_result = state.get(
        "prioritization_report", "(prioritization pending)")
    data_json = state.get("data_json", "")
    return f"""Project: {project_name}
Context summary:
{context_summary}

Prioritized backlog:
{prioritization_result}

Raw scan bundle:
{data_json}

Task:
- Map upstream source components, downstream consumers, and transitive exposure paths for each top risk.
- Highlight where compromised dependencies could traverse CI/CD, artifact storage, or runtime deployments.
- Recommend targeted controls per dependency cluster (SBOM validation, signing, provenance, etc.).
"""


def _build_remediation_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    context_summary = state.get("contextual_summary", "(context pending)")
    prioritization_result = state.get(
        "prioritization_report", "(prioritization pending)")
    supply_chain_result = state.get(
        "supply_chain_report", "(supply-chain pending)")
    qa_feedback = state.get("qa_review", "")
    iteration = state.get("remediation_iteration", 1)
    data_json = state.get("data_json", "")
    return f"""Project: {project_name}

Context summary:
{context_summary}

Prioritized backlog:
{prioritization_result}

Supply-chain blast radius:
{supply_chain_result}

Latest QA feedback (use it to refine plan iteration {iteration}):
{qa_feedback or 'No QA feedback yet.'}

Raw scan bundle (for reference):
{data_json}

Task:
- Produce an actionable plan grouped into quick_wins (<7 days), structured_fix (medium), and compensating_controls.
- Reference backlog ranks/item_ids for traceability.
- Include owner_hint and expected_timebox (days) for every action.
- Call out dependencies or prerequisites explicitly.
"""


def _build_qa_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    context_summary = state.get("contextual_summary", "(context pending)")
    prioritization_result = state.get(
        "prioritization_report", "(prioritization pending)")
    supply_chain_result = state.get(
        "supply_chain_report", "(supply-chain pending)")
    remediation_result = state.get("remediation_plan", "(remediation pending)")
    return f"""You are the QA/compliance reviewer for project '{project_name}'.

Inputs:
- Context: {context_summary}
- Prioritization: {prioritization_result}
- Supply-chain: {supply_chain_result}
- Remediation: {remediation_result}

Task:
Return JSON with keys gaps, assumptions, verification_steps, confidence (0-1).
Focus on contradictions, missing telemetry, policy blockers, and data that needs follow-up.
"""


def _build_executive_summary_prompt(state: Dict[str, Any]) -> str:
    project_name = state.get("project_name", "unknown project")
    context_summary = state.get("contextual_summary", "(context pending)")
    prioritization_result = state.get(
        "prioritization_report", "(prioritization pending)")
    supply_chain_result = state.get(
        "supply_chain_report", "(supply-chain pending)")
    remediation_result = state.get("remediation_plan", "(remediation pending)")
    qa_review_result = state.get("qa_review", "(qa pending)")
    scan_overview = json.dumps(
        state.get("scan_overview", {}), indent=2, ensure_ascii=False
    )
    return f"""You own the executive-ready summary for project '{project_name}'.
Summarize the outputs from every agent into:
1. Narrative (2-3 paragraphs) covering context, key risks, supply-chain exposure, remediation status.
2. KPI scoreboard with exposure_count, high_risk_assets, expected_risk_reduction, remediation_velocity_signal.
3. Commitments & QA follow-ups (reference QA reviewer output).

Scan overview:
{scan_overview}

Context:
{context_summary}

Prioritization:
{prioritization_result}

Supply-chain:
{supply_chain_result}

Remediation plan:
{remediation_result}

QA review:
{qa_review_result}
"""


PROMPT_BUILDERS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "contextualizer_agent": _build_contextualizer_prompt,
    "prioritization_agent": _build_prioritization_prompt,
    "supply_chain_agent": _build_supply_chain_prompt,
    "remediation_agent": _build_remediation_prompt,
    "qa_review_agent": _build_qa_prompt,
    "executive_summary_agent": _build_executive_summary_prompt,
}


def run_ai_analysis(project_name: str, selected_scan_ids: Optional[List[str]] = None) -> Dict:
    """
    Run AI analysis on selected scans from a project

    Args:
        project_name: Name of the project to analyze
        selected_scan_ids: Optional list of scan IDs to analyze. If None, analyzes all scans in the project.

    Returns:
        Dictionary with analysis results or error information
    """
    # Check if project exists
    project = get_project(project_name)
    if not project:
        return {
            "success": False,
            "error": f"Project '{project_name}' not found. Please create the project first."
        }

    # Check if selected scans are provided
    if selected_scan_ids:
        # Validate that selected scans exist and belong to the project
        project_scan_ids = set(project.get("scan_ids", []))
        valid_scan_ids = [
            sid for sid in selected_scan_ids if sid in project_scan_ids and get_scan(sid)]

        if not valid_scan_ids:
            return {
                "success": False,
                "error": f"No valid scans selected. Please select scans that belong to project '{project_name}'."
            }
        scans = [get_scan(sid) for sid in valid_scan_ids]
    else:
        # Use all scans in the project
        scans = get_scans_by_project(project_name)
        if not scans:
            return {
                "success": False,
                "error": f"Project '{project_name}' has no scans. Please assign scans to the project first."
            }

    # Initialize agents
    agents = initialize_ai_agents()
    if not agents:
        return {
            "success": False,
            "error": "AI agents not available. Please ensure google-adk is installed and OPENROUTER_API_KEY is set."
        }

    try:
        # Collect scan data for selected scans
        scan_data = collect_scan_data_for_analysis(
            project_name, selected_scan_ids)

        # Prepare data for agents (convert to JSON string for better context)
        data_summary = {
            "project_name": project_name,
            "total_scans": len(scan_data["scans"]),
            "scans": []
        }

        for scan_info in scan_data["scans"]:
            scan_summary = {
                "scan_id": scan_info["scan_id"],
                "scan_type": scan_info["scan_type"],
                "target": scan_info["target"],
                "vulnerability_count": scan_info["vulnerability_count"],
                "cve_count": len(scan_info["cve_details"]),
                "cve_details": scan_info["cve_details"]
            }
            data_summary["scans"].append(scan_summary)

        # Convert to JSON string for agent input
        data_json = json.dumps(data_summary, indent=2, ensure_ascii=False)

        pipeline_agent = agents.get("pipeline") or agents.get(
            "cybersecurity_pipeline")
        if not pipeline_agent:
            return {
                "success": False,
                "error": "AI workflow pipeline not available. Please verify google-adk supports workflow agents.",
            }

        state: Dict[str, Any] = {
            "project_name": project_name,
            "data_json": data_json,
            "scan_overview": data_summary,
            "qa_target_confidence": QA_CONFIDENCE_TARGET,
        }
        agent_outputs: Dict[str, str] = {}

        _run_workflow_pipeline(pipeline_agent, state, agent_outputs)

        analysis_results = {
            "project_name": project_name,
            "analyzed_at": datetime.now().isoformat(),
            "scan_overview": data_summary,
            "contextual_summary": state.get("contextual_summary"),
            "prioritization": state.get("prioritization_report"),
            "supply_chain": state.get("supply_chain_report"),
            "remediation": state.get("remediation_plan"),
            "qa_review": state.get("qa_review"),
            "qa_confidence": state.get("qa_confidence"),
            "executive_summary": state.get("executive_summary"),
            "agent_outputs": agent_outputs,
            "pipeline_topology": AGENT_PIPELINE_SUMMARY,
            "remediation_iterations": state.get("remediation_iteration"),
        }

        # Store analysis results
        ai_analyses_storage.append(analysis_results)

        return {
            "success": True,
            "results": analysis_results
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Error running AI analysis: {str(e)}"
        }


def get_ai_analyses_by_project(project_name: str) -> List[Dict]:
    """
    Get all AI analyses for a project

    Args:
        project_name: Name of the project

    Returns:
        List of analysis dictionaries, sorted by analyzed_at (newest first)
    """
    analyses = [
        analysis for analysis in ai_analyses_storage
        if analysis.get("project_name") == project_name
    ]

    # Sort by analyzed_at (newest first)
    try:
        analyses.sort(key=lambda x: x.get("analyzed_at", ""), reverse=True)
    except Exception:
        pass

    return analyses
