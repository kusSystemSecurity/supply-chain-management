"""
AI analysis functions using Cybersecurity AI (CAI) framework
"""

import agentops
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from agno.workflow import Loop, Parallel, Step, Workflow
from agno.workflow.types import StepInput, StepOutput

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
AI analysis functions powered by the Agno multi-agent workflow runtime.
"""


AGENTOPS_API_KEY = os.getenv("AGENTOPS_API_KEY")
if AGENTOPS_API_KEY:
    agentops.init(
        api_key=AGENTOPS_API_KEY,
    )


def _to_float(value: Optional[str], default: float) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _to_int(value: Optional[str], default: int) -> int:
    try:
        parsed_value = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed_value = default
    return max(parsed_value, 1)


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


AI_ANALYSIS_MODEL_ID = os.getenv(
    "AI_ANALYSIS_MODEL", "x-ai/grok-4.1-fast:free")
AI_ANALYSIS_MODEL_MAX_TOKENS = _to_int(
    os.getenv("AI_ANALYSIS_MODEL_MAX_TOKENS", "3200"), 3200)
AI_ANALYSIS_QA_TARGET_CONFIDENCE = _to_float(
    os.getenv("AI_ANALYSIS_QA_TARGET_CONFIDENCE", "0.85"), 0.85)
AI_ANALYSIS_MAX_REMEDIATION_ITERATIONS = _to_int(
    os.getenv("AI_ANALYSIS_MAX_REMEDIATION_ITERATIONS", "2"), 2)

_CONTEXTUALIZER_STEP_NAME = "Contextualizer Agent"
_PRIORITIZATION_STEP_NAME = "Prioritization Agent"
_SUPPLY_CHAIN_STEP_NAME = "Supply Chain Agent"
_PARALLEL_STEP_NAME = "Insight Parallel"
_MERGE_STEP_NAME = "Insight Synthesizer"
_REMEDIATION_STEP_NAME = "Remediation Agent"
_QA_STEP_NAME = "QA Review Agent"
_REMEDIATION_LOOP_NAME = "Remediation Loop"
_EXEC_SUMMARY_STEP_NAME = "Executive Summary Agent"

_workflow: Optional[Workflow] = None

CONTEXTUALIZER_INSTRUCTIONS = """
You are contextualizer_agent (contextual_summary stage) for a software supply-chain security program.
Work off the JSON telemetry embedded in the user's message (bounded by <scan_data> tags).
1. Normalize the telemetry into four sections: environment_overview, exposure_hotspots, exploit_signals, telemetry_gaps.
2. Reference scan IDs, targets, and vulnerability counts where relevant.
3. Highlight trends rather than restating raw data.
Output markdown with the following section headers:
## Environment Overview
## Exposure Hotspots
## Exploit Signals
## Telemetry Gaps
""".strip()

PRIORITIZATION_INSTRUCTIONS = """
You are prioritization_agent (prioritization_report stage).
Input context contains the normalized summary from contextualizer_agent.
Produce a backlog (max 10 items) sorted by risk_score (0-100) that teams can act on immediately.
For each backlog item include:
- backlog_id (e.g., P1, P2)
- title
- risk_score (0-100)
- rationale (why it matters)
- suggested_owner (team or role)
- next_action (tactical step for the next 7 days)
Return markdown using a table or bullet list where each item is clearly delimited.
""".strip()

SUPPLY_CHAIN_INSTRUCTIONS = """
You are supply_chain_agent (supply_chain_report stage).
Use the prioritized backlog provided in the previous step.
For each backlog_id, map:
- upstream_dependencies and downstream_dependencies that expand blast radius,
- potential blast_radius narrative,
- existing_controls and proposed_controls for each dependency path.
Return markdown with a section per backlog_id titled `## Backlog ID - <id>`.
Keep the analysis concise but specific enough for partner teams to reason about impact.
""".strip()

REMEDIATION_INSTRUCTIONS = """
You are remediation_agent (remediation_plan stage).
You receive synthesized insight that blends prioritization and supply-chain context.
Produce three sections:
1. Quick Wins (can ship within 2 weeks) referencing backlog IDs.
2. Strategic Fixes (multi-quarter initiatives) referencing backlog IDs.
3. Compensating Controls for any residual risk.
Each recommendation must include owner/timebox hints (team + timeframe) and measurable success criteria.
""".strip()

QA_REVIEW_INSTRUCTIONS = f"""
You are qa_review_agent (qa_review stage) ensuring the remediation plan is shippable.
Evaluate completeness, assumptions, and evidence quality.
Respond with VALID JSON only (no markdown) using this schema:
{{
  "gaps": ["Describe concrete missing elements"],
  "assumptions": ["List key assumptions the plan made"],
  "verification_steps": ["List how to verify remediation success"],
  "feedback_summary": "One paragraph summary",
  "confidence": 0.0,
  "should_continue": true
}}
Confidence must be a float between 0 and 1. Set should_continue to false when confidence ≥ {AI_ANALYSIS_QA_TARGET_CONFIDENCE:.2f}
or no additional remediation changes are required.
""".strip()

EXECUTIVE_SUMMARY_INSTRUCTIONS = """
You are executive_summary_agent (executive_summary stage).
Create a stakeholder-ready narrative that references:
- Key backlog items and their expected blast radius reduction.
- Expected risk reduction percentage.
- High-risk assets affected.
- Remediation velocity signal (slow/steady/fast) with rationale.
Conclude with a KPI table covering: exposure_count, high_risk_assets, expected_risk_reduction, remediation_velocity_signal.
""".strip()


def _build_model() -> OpenRouter:
    """
    Create a configured OpenRouter model instance.
    """
    return OpenRouter(
        id=AI_ANALYSIS_MODEL_ID,
        max_tokens=AI_ANALYSIS_MODEL_MAX_TOKENS,
    )


def _build_agent(name: str, description: str, instructions: str) -> Agent:
    """
    Convenience helper to instantiate Agno agents with consistent defaults.
    """
    return Agent(
        name=name,
        description=description,
        model=_build_model(),
        instructions=instructions,
        markdown=True,
        add_datetime_to_context=True,
    )


def _step_output_to_str(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, (dict, list)):
        return json.dumps(content, indent=2, ensure_ascii=False)
    return str(content)


def _merge_parallel_insights(step_input: StepInput, **_: Any) -> StepOutput:
    """
    Combine prioritization and supply-chain agent outputs into one narrative.
    """
    parallel_output = step_input.get_step_output(_PARALLEL_STEP_NAME)
    if not parallel_output or not parallel_output.steps:
        return StepOutput(content="No insights available for remediation planning yet.")

    sections: List[str] = ["## Consolidated Insight Packet"]
    for child in parallel_output.steps:
        child_name = child.step_name or "Insight"
        child_body = _step_output_to_str(child.content).strip()
        if not child_body:
            child_body = "No content produced."
        sections.append(f"### {child_name}\n{child_body}")

    return StepOutput(content="\n\n".join(sections))


def _parse_json_content(raw_content: Any) -> Optional[Dict[str, Any]]:
    """
    Attempt to coerce agent output into a JSON object (handles fenced code blocks).
    """
    if raw_content is None:
        return None

    if isinstance(raw_content, dict):
        return raw_content

    text = str(raw_content).strip()
    if not text:
        return None

    if text.startswith("```"):
        # Remove code fences
        text = text.strip("`")
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start: end + 1]

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None

    try:
        return json.loads(text[start: end + 1])
    except json.JSONDecodeError:
        return None


def _qa_loop_should_stop(iteration_results: List[StepOutput]) -> bool:
    """
    End the remediation loop when QA confidence meets the configured threshold
    or when QA explicitly sets should_continue to False.
    """
    qa_output = next(
        (res for res in iteration_results if res.step_name == _QA_STEP_NAME), None)
    if not qa_output:
        return False

    payload = _parse_json_content(qa_output.content)
    if not payload:
        return False

    confidence = _coerce_float(payload.get("confidence"))
    should_continue_flag = payload.get("should_continue")

    if isinstance(should_continue_flag, bool) and should_continue_flag is False:
        return True

    return confidence >= AI_ANALYSIS_QA_TARGET_CONFIDENCE


def _find_step_outputs(step_outputs: List[StepOutput], target_name: str) -> List[StepOutput]:
    """
    Recursively collect all StepOutputs that match the provided name.
    """
    matches: List[StepOutput] = []
    for output in step_outputs:
        if output.step_name == target_name:
            matches.append(output)
        if output.steps:
            matches.extend(_find_step_outputs(output.steps, target_name))
    return matches


def _build_analysis_prompt(project_name: str, data_json: str, total_scans: int) -> str:
    return (
        f"Project: {project_name}\n"
        f"Total scans selected: {total_scans}\n"
        f"Generated at: {datetime.utcnow().isoformat()}Z\n\n"
        "<scan_data>\n"
        f"{data_json}\n"
        "</scan_data>\n"
        "Each agent in the workflow receives these details. Perform your specialized task."
    )


def _extract_qa_feedback(step_results: List[StepOutput]) -> Dict[str, Any]:
    qa_outputs = _find_step_outputs(step_results, _QA_STEP_NAME)
    if not qa_outputs:
        return {"content": None, "confidence": None, "iterations": 0}

    latest = qa_outputs[-1]
    payload = _parse_json_content(latest.content) or {}
    return {
        "content": _step_output_to_str(latest.content) if latest.content is not None else None,
        "confidence": _coerce_float(payload.get("confidence")) if payload.get("confidence") is not None else None,
        "iterations": len(qa_outputs),
    }


def _extract_latest_content(step_results: List[StepOutput], step_name: str) -> Optional[str]:
    matches = _find_step_outputs(step_results, step_name)
    if not matches:
        return None
    return _step_output_to_str(matches[-1].content).strip() or None


def initialize_ai_agents() -> Workflow:
    """
    Lazily build and cache the Agno workflow so imports remain lightweight.
    """
    global _workflow
    if _workflow is not None:
        return _workflow

    contextualizer_agent = _build_agent(
        name=_CONTEXTUALIZER_STEP_NAME,
        description="Normalizes raw telemetry into a structured context packet.",
        instructions=CONTEXTUALIZER_INSTRUCTIONS,
    )
    prioritization_agent = _build_agent(
        name=_PRIORITIZATION_STEP_NAME,
        description="Ranks backlog items with risk scores and owners.",
        instructions=PRIORITIZATION_INSTRUCTIONS,
    )
    supply_chain_agent = _build_agent(
        name=_SUPPLY_CHAIN_STEP_NAME,
        description="Maps upstream/downstream dependencies and blast radius.",
        instructions=SUPPLY_CHAIN_INSTRUCTIONS,
    )
    remediation_agent = _build_agent(
        name=_REMEDIATION_STEP_NAME,
        description="Drafts tactical and strategic remediation actions.",
        instructions=REMEDIATION_INSTRUCTIONS,
    )
    qa_review_agent = _build_agent(
        name=_QA_STEP_NAME,
        description="Provides QA guardrails with structured confidence scoring.",
        instructions=QA_REVIEW_INSTRUCTIONS,
    )
    executive_summary_agent = _build_agent(
        name=_EXEC_SUMMARY_STEP_NAME,
        description="Translates the workflow output into an executive-ready narrative.",
        instructions=EXECUTIVE_SUMMARY_INSTRUCTIONS,
    )

    _workflow = Workflow(
        name="cybersecurity_pipeline",
        description="Contextualizer → Insight Parallel → Remediation Loop → Executive Summary",
        steps=[
            Step(name=_CONTEXTUALIZER_STEP_NAME, agent=contextualizer_agent),
            Parallel(
                Step(name=_PRIORITIZATION_STEP_NAME,
                     agent=prioritization_agent),
                Step(name=_SUPPLY_CHAIN_STEP_NAME, agent=supply_chain_agent),
                name=_PARALLEL_STEP_NAME,
            ),
            Step(name=_MERGE_STEP_NAME, executor=_merge_parallel_insights),
            Loop(
                steps=[
                    Step(name=_REMEDIATION_STEP_NAME, agent=remediation_agent),
                    Step(name=_QA_STEP_NAME, agent=qa_review_agent),
                ],
                name=_REMEDIATION_LOOP_NAME,
                max_iterations=AI_ANALYSIS_MAX_REMEDIATION_ITERATIONS,
                end_condition=_qa_loop_should_stop,
            ),
            Step(name=_EXEC_SUMMARY_STEP_NAME, agent=executive_summary_agent),
        ],
    )

    return _workflow


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

        if not os.getenv("OPENROUTER_API_KEY"):
            return {
                "success": False,
                "error": "OPENROUTER_API_KEY is not configured. Set it before running AI analysis.",
            }

        # Convert to JSON string for agent input
        data_json = json.dumps(data_summary, indent=2, ensure_ascii=False)

        workflow = initialize_ai_agents()
        workflow_input = _build_analysis_prompt(
            project_name=project_name,
            data_json=data_json,
            total_scans=len(data_summary["scans"]),
        )

        workflow_response = workflow.run(input=workflow_input)
        step_results = workflow_response.step_results or []

        contextual_summary = _extract_latest_content(
            step_results, _CONTEXTUALIZER_STEP_NAME)
        prioritization_report = _extract_latest_content(
            step_results, _PRIORITIZATION_STEP_NAME)
        supply_chain_report = _extract_latest_content(
            step_results, _SUPPLY_CHAIN_STEP_NAME)
        remediation_plan = _extract_latest_content(
            step_results, _REMEDIATION_STEP_NAME)
        executive_summary = _extract_latest_content(
            step_results, _EXEC_SUMMARY_STEP_NAME)
        qa_feedback = _extract_qa_feedback(step_results)

        analysis_results = {
            "project_name": project_name,
            "scans": data_summary["scans"],
            "scan_metadata": data_summary,
            "scan_data_json": data_json,
            "contextual_summary": contextual_summary,
            "prioritization": prioritization_report,
            "supply_chain": supply_chain_report,
            "remediation": remediation_plan,
            "qa_review": qa_feedback.get("content"),
            "qa_confidence": qa_feedback.get("confidence"),
            "qa_iterations": qa_feedback.get("iterations"),
            "executive_summary": executive_summary,
            "workflow_run_id": workflow_response.run_id,
            "analyzed_at": datetime.now().isoformat(),
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
