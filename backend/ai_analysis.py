"""
AI analysis functions using Agno multi-agent workflow runtime.
"""

import json
import os
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from agno.workflow.types import StepInput, StepOutput
from agno.workflow import Loop, Parallel, Step, Workflow
from agno.os import AgentOS
from agno.db.postgres import PostgresDb
from agno.vectordb.pgvector import PgVector
from agno.knowledge.knowledge import Knowledge
from agno.tools.duckduckgo import DuckDuckGoTools
# from agno.tools.mcp import MCPTools
from agno.models.openrouter import OpenRouter
from agno.agent import Agent

from dotenv import load_dotenv

# Database connection
db_url = "postgresql+psycopg://ai:ai@localhost:5532/ai"

# Create Postgres-backed memory store
db = PostgresDb(db_url=db_url)

# Create Postgres-backed vector store
vector_db = PgVector(
    db_url=db_url,
    table_name="agno_docs",
)
knowledge = Knowledge(
    name="Agno Docs",
    contents_db=db,
    vector_db=vector_db,
)

load_dotenv()

if TYPE_CHECKING:
    from fastapi import FastAPI

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

_agent_registry: Optional[Dict[str, Agent]] = None
_workflow: Optional[Workflow] = None
_agent_os: Optional[AgentOS] = None
_agent_os_app: Optional["FastAPI"] = None

CONTEXTUALIZER_INSTRUCTIONS = """
You are contextualizer_agent (contextual_summary stage) for a software supply-chain security program.
Work off the scan telemetry embedded in the user's message (bounded by <scan_data> tags).
Use DuckDuckGoTools to search for more information about the scan.

Scan data includes:
- Vulnerabilities (CVEs) with CVSS scores (extract Base Score, Impact metrics C/I/A, Attack Vector, Complexity, User Interaction, Authentication)
- EPSS scores (Exploit Prediction Scoring System) when available
- Secret detection results (API keys, tokens, credentials)
- License compliance issues
- Misconfigurations (if scanned)
- Package/dependency information with installed vs fixed versions

**Extract for Risk Calculation**:
For each CVE, collect the following if available:
- CVSS v3.x Base Score and Vector String (parse AV, AC, PR, UI, S, C, I, A values)
- CVSS Impact Sub-score (Confidentiality, Integrity, Availability impact)
- EPSS score (0.0-1.0 probability)
- Exploitation indicators: Public exploit availability, CISA KEV listing, exploit-db references
- Vulnerability category/type: Code execution (RCE, SQLi, Command Injection), Memory corruption, DoS, Info disclosure, etc.
- Exposure factors: 
  * Number of affected products/images
  * Internet-facing vs internal services
  * Mentions in security advisories, blogs, social media
  * Detection surface (remotely exploitable vs local)

1. Normalize the telemetry into four sections:
   - environment_overview: Scan targets (repos/images), total findings, severity distribution
   - exposure_hotspots: Critical/High CVEs with rich context (CVSS, EPSS, exploit status, vulnerability type)
   - exploit_signals: CVEs with public exploits, high EPSS (>0.4), in CISA KEV, high-risk categories (RCE/SQLi)
   - telemetry_gaps: Missing EPSS data, incomplete CVSS vectors, unscanned assets

2. Reference scan IDs, target identifiers (image:tag or repo path), and vulnerability counts by severity.
3. Highlight actionable trends: fixable vs unfixable vulnerabilities, secret types, recurring vulnerable packages.
4. Flag zero-day vulnerabilities (CVEs published within last 30 days) and secrets with high exposure risk.
5. For each high-priority CVE, include a structured block with: CVE-ID, CVSS Base, CVSS Vector, EPSS, Vulnerability Type, Affected Products, Exposure Context

Output markdown with the following section headers:
## Environment Overview
## Exposure Hotspots
## Exploit Signals
## Telemetry Gaps
""".strip()

PRIORITIZATION_INSTRUCTIONS = """
You are prioritization_agent (prioritization_report stage).
Input context contains the normalized  scan summary from contextualizer_agent.

**Risk Score Calculation Methodology**:
Calculate Risk Score (1-25) = Impact Score (1-5) × Likelihood Score (1-5)

**Impact Score (1-5)** - Based on CVSS Impact Metrics:
Extract Confidentiality (C), Integrity (I), Availability (A) impact values from CVSS vector:
- Score 5: All three (C/I/A) are HIGH
- Score 4: Two HIGH impacts or one HIGH + two MEDIUM
- Score 3: One HIGH or two MEDIUM impacts
- Score 2: One MEDIUM impact
- Score 1: Only LOW impacts
(Adjust based on asset criticality: multiply by 1.2x for production systems, 0.8x for dev/test)

**Likelihood Score (1-5)** - Multi-factor Assessment:
Calculate a composite likelihood percentage (0-100%) first, then map to 1-5 scale:
- 80-100% = Score 5 (Very High)
- 60-79% = Score 4 (High)
- 40-59% = Score 3 (Medium)
- 20-39% = Score 2 (Low)
- 0-19% = Score 1 (Very Low)

**Likelihood Factors** (weighted combination):

1. **EPSS Score** (Weight: HIGH - 30% contribution)
   - EPSS ≥ 0.7: +30 points
   - EPSS 0.4-0.69: +20 points
   - EPSS 0.1-0.39: +10 points
   - EPSS < 0.1: +5 points
   - Missing EPSS: +5 points (assume low but not zero)
   - NOTE: Low EPSS does NOT mean low risk; other factors compensate

2. **Exploitation Evidence** (Weight: MEDIUM - 25% contribution)
   - Public exploit exists (ExploitDB, Metasploit, GitHub PoCs): +25 points
   - In CISA KEV catalog: +25 points
   - Mentioned in exploit/threat intel sources: +15 points
   - Weaponized malware campaigns: +25 points
   - No exploitation evidence: +0 points

3. **Vulnerability Type/Category** (Weight: VERY HIGH - 30% contribution)
   - Remote Code Execution (RCE): +30 points
   - SQL Injection / Command Injection: +30 points
   - Authentication Bypass / Privilege Escalation: +25 points
   - Memory Corruption (Buffer Overflow, Use-After-Free): +20 points
   - Cross-Site Scripting (XSS) / CSRF: +15 points
   - Information Disclosure: +10 points
   - Denial of Service: +10 points
   - Other/Unknown: +5 points

4. **Exposure Context** (Weight: MEDIUM - 15% contribution)
   - Affects multiple products/images (≥5): +10 points
   - Affects 2-4 products: +7 points
   - Single product: +3 points
   - Internet-facing service: +5 points
   - Remotely exploitable (AV:N in CVSS): +5 points
   - Mentioned in 10+ sources (blogs, advisories, social): +10 points
   - Mentioned in 3-9 sources: +5 points
   - Mentioned in 1-2 sources: +2 points
   - No mentions: +0 points

5. **CVSS Exploitability Metrics** (Weight: INCLUDED in above, but verify)
   - Attack Vector Network (AV:N): Already boosted by Exposure
   - Low Attack Complexity (AC:L): Increases likelihood
   - No Privileges Required (PR:N): Increases likelihood
   - No User Interaction (UI:N): Increases likelihood
   - (These are factored into CVSS Base Score but validate for edge cases)

**Calculation Example**:
CVE-2024-1234 in nginx:1.20
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Score 9.8)
- Impact: C:H, I:H, A:H → Impact Score = 5
- EPSS: 0.85 → +30 (HIGH contribution)
- Exploitation: Public exploit exists, in CISA KEV → +25 (MEDIUM contribution)
- Vuln Type: RCE → +30 (VERY HIGH contribution)
- Exposure: Affects 8 production images, internet-facing, mentioned in 15 sources → +10+5+5+10 = +30 (MEDIUM contribution)
- **Likelihood %: 30+25+30+30 = 115% (capped at 100%) → Likelihood Score = 5**
- **Risk Score = 5 × 5 = 25 (CRITICAL)**

**Backlog Generation**:
Produce a backlog (max 10 items) sorted by risk_score (1-25, highest first).

For each backlog item include:
- backlog_id (e.g., P1, P2, ...)
- title (concise: "CVE-2024-XXXXX in package@version" or "Exposed AWS Secret Key")
- risk_score (1-25): Calculated as Impact × Likelihood
- impact_score (1-5): From CVSS C/I/A
- likelihood_score (1-5): From multi-factor assessment
- likelihood_breakdown: "EPSS:0.85(H), Exploit:Yes(M), Type:RCE(VH), Exposure:Multi-product+Internet(M)"
- affected_assets: Specific images/repos/packages
- severity: CRITICAL/HIGH/MEDIUM/LOW (from  Risk Score context)
- rationale: Why it matters (exploit availability, data exposure, compliance impact, blast radius)
- fix_available: YES/NO with version or workaround details
- suggested_owner: Security/DevOps/AppTeam based on finding type
- next_action: Tactical step for next 7 days (upgrade package, rotate secret, apply patch)

**For Secret Exposures**:
Risk Score calculation differs:
- Impact Score: Based on credential privilege level (5=Admin/Root, 4=DB/API, 3=Service, 2=ReadOnly, 1=Public)
- Likelihood Score: Based on exposure context (5=Public repo + Production, 4=Public repo, 3=Private repo + Prod, 2=Private repo, 1=Dev only)

Return markdown table format:
| ID | Title | Risk | Impact | Likelihood | Likelihood Factors | Affected Assets | Fix | Owner | Next Action |

Add a summary paragraph highlighting:
- Total items by risk tier (20-25=Critical, 15-19=High, 10-14=Medium, 5-9=Low, 1-4=Info)
- Most common vulnerability types in backlog
- Average EPSS for top 5 items
""".strip()

SUPPLY_CHAIN_INSTRUCTIONS = """
You are supply_chain_agent (supply_chain_report stage).
Use the prioritized backlog provided in the previous step.

For each backlog_id (focus on Risk Score ≥ 15), analyze:
- upstream_dependencies: Direct and transitive dependencies introducing the vulnerability
- downstream_dependencies: Services/images consuming the affected component
- blast_radius: Number of images/services affected, criticality of impacted systems
- **risk_propagation**: How risk score compounds through dependency chain
  * If parent image has Risk=20 and 5 child images inherit it, aggregate exposure is critical
  * Calculate: Individual Risk × Number of Affected Assets × Asset Criticality Multiplier
- propagation_path: How vulnerability travels (base image → derived images → services)
- existing_controls: Current mitigations (WAF rules, network segmentation, runtime detection)
- proposed_controls: Additional safeguards (version pinning, image signing, secret rotation policies)

For secret exposures, identify:
- Secret scope: Which systems can be accessed with exposed credentials
- Rotation status: Last rotated date (if available), rotation policy compliance
- Detection coverage: Monitored in SIEM/alerting systems

**Risk Amplification Analysis**:
For high-risk items (Risk ≥ 20), explain how likelihood factors compound:
- "CVE-2024-1234 has EPSS 0.9 (exploitation imminent) + public exploit + RCE type + affects 12 internet-facing services = Risk 25"
- "Exposure across multiple products increases attack surface, raising effective likelihood"

Return markdown with a section per backlog_id titled `## Backlog ID - <id> (Risk: X/25)`.
Include a dependency tree visualization (text-based) for critical items.
""".strip()

REMEDIATION_INSTRUCTIONS = """
You are remediation_agent (remediation_plan stage).
You receive synthesized insight blending prioritization and supply-chain context from  scans.

Produce three sections:

1. **Quick Wins** (ship within 2 weeks):
   - Package upgrades with available patches (specify version: pkg@1.2.3 → pkg@1.2.4)
   - Secret rotation/revocation with specific credential types
   - Base image updates (FROM alpine:3.18 → alpine:3.19)
   - Reference backlog IDs, include exact commands/Dockerfile changes

2. **Strategic Fixes** (multi-quarter initiatives):
   - Dependency refactoring (remove vulnerable libraries)
   - Architecture changes (isolate high-risk components)
   - Policy enforcement (automated secret scanning in CI/CD)
   - Reference backlog IDs with milestone breakdown

3. **Compensating Controls** (for unfixable/accepted risks):
   - Runtime protection (WAF rules, RASP)
   - Network controls (firewall rules, segmentation)
   - Monitoring/alerting enhancements
   - Acceptance criteria for residual risk

Each recommendation must include:
- Owner: Specific team (Platform/Security/App Team X)
- Timeframe: Specific dates or sprint numbers
- Success criteria: Measurable outcomes (zero CRITICAL CVEs, all secrets rotated, scan results green)
- Validation: How to verify (re-scan with , penetration test, audit log review)
""".strip()

QA_REVIEW_INSTRUCTIONS = f"""
You are qa_review_agent (qa_review stage) ensuring the remediation plan is shippable.
Evaluate completeness against  scan characteristics and risk scoring methodology:

**Risk Score Validation Checklist**:
- All Risk Score ≥ 20 items have immediate remediation actions (within 48-72 hours)
- Risk Score 15-19 items have remediation plans (within 1-2 weeks)
- Impact and Likelihood scores are justified with specific factors (CVSS, EPSS, exploit status, vuln type, exposure)
- Likelihood breakdown includes all relevant factors (not just EPSS or CVSS alone)
- High EPSS (>0.7) items are prioritized even if CVSS is moderate
- RCE/SQLi vulnerabilities are in top 5 regardless of EPSS
- Multi-product exposures have coordinated remediation plans
- Secret exposures with Impact ≥ 4 have rotation/revocation within 24 hours

**Verification Checklist**:
- All CRITICAL/HIGH risk findings (Risk ≥ 15) have remediation actions
- Secret exposures have rotation/revocation plans with timelines
- Fixable vulnerabilities specify exact package version upgrades
- Unfixable vulnerabilities have compensating controls with risk acceptance documentation
- Base image updates are tested for compatibility
- Re-scan validation steps are documented

Respond with VALID JSON only (no markdown):
{{
  "gaps": ["Concrete missing elements like 'CVE-2024-XXXX (Risk:25) has no immediate action plan'"],
  "assumptions": ["e.g., 'Assumes EPSS score will remain stable', 'Assumes no 0-day exploit emergence'"],
  "verification_steps": ["e.g., 'Re-run trivy scan to confirm Risk Score drops below 15', 'Verify EPSS monitoring for top 5 CVEs'"],
  "risk_score_concerns": ["Items where calculated risk may be under/overestimated"],
  "trivy_coverage": ["Images/repos requiring additional scanning"],
  "false_positive_risk": ["Findings that may need manual verification"],
  "feedback_summary": "One paragraph summary",
  "confidence": 0.0,
  "should_continue": true
}}
Confidence: 0-1 float. Set should_continue=false when confidence ≥ {AI_ANALYSIS_QA_TARGET_CONFIDENCE:.2f}.
""".strip()

EXECUTIVE_SUMMARY_INSTRUCTIONS = """
You are executive_summary_agent (executive_summary stage).
Create a stakeholder-ready narrative referencing  scan results, risk scoring, and remediation plans:

**Executive Narrative** (2-3 paragraphs):
- Current risk posture: Total vulnerabilities by risk tier (Critical 20-25, High 15-19, Medium 10-14, Low 5-9)
- Key backlog items with risk scores and likelihood drivers (EPSS, exploitation, vulnerability type, exposure)
- Expected risk reduction: Percentage drop in high-risk findings (Risk ≥ 15) after remediation
- High-risk assets: Production images, public-facing services with Risk ≥ 20
- Remediation velocity signal: 
  * fast (>80% of Risk ≥15 items fixable in 2 weeks) 
  * steady (50-80%) 
  * slow (<50%, requires strategic fixes)

**KPI Dashboard Table**:
| Metric | Current | Post-Remediation | Change |
|--------|---------|------------------|--------|
| Risk Score 20-25 (Critical) | X | Y | -Z% |
| Risk Score 15-19 (High) | X | Y | -Z% |
| Average Risk Score (Top 10) | X.X | Y.Y | -Z.Z |
| High EPSS (>0.7) CVEs | X | Y | -Z% |
| RCE/SQLi Vulnerabilities | X | Y | -Z% |
| Exposed Secrets (Impact ≥4) | X | Y | -Z% |
| Internet-Facing Exposures | X | Y | -Z% |
| Mean Time to Remediate (MTTR) | X days | Target: Y days | - |

**Risk Heatmap** (text representation by Likelihood × Impact):
```
Impact ↑
  5 |  [P1]  [P2]        [P3]
  4 |        [P4]  [P5]
  3 |              [P6]  [P7]
  2 |                    [P8]
  1 |                          [P9]
    +---------------------------→ Likelihood
      1     2     3     4     5
```
- CRITICAL (Risk 20-25): [List top 3 with CVE-ID, EPSS, Vuln Type, Affected Assets]
- HIGH (Risk 15-19): [Summary count + common factors]
- Compliance: [License issues, policy violations from ]

**Likelihood Factor Summary**:
- X% of high-risk items have public exploits
- Average EPSS for Critical tier: 0.XX
- Y items are RCE/SQLi (inherently high-risk categories)
- Z items affect multiple products, amplifying exposure

Conclude with a timeline Gantt chart (text-based) showing quick wins vs strategic fixes, sorted by risk score.
""".strip()


def _build_model() -> OpenRouter:
    """
    Create a configured OpenRouter model instance.
    """
    return OpenRouter(
        id=AI_ANALYSIS_MODEL_ID,
        max_tokens=AI_ANALYSIS_MODEL_MAX_TOKENS,
    )


def _build_agent(name: str, description: str, instructions: str, tools: Optional[List[Any]] = None) -> Agent:
    """
    Convenience helper to instantiate Agno agents with consistent defaults.
    """
    return Agent(
        name=name,
        description=description,
        model=_build_model(),
        instructions=instructions,
        tools=tools if tools else [],
        knowledge=knowledge,
        db=db,
        enable_user_memories=True,
        add_datetime_to_context=True,
        add_history_to_context=True,
        num_history_runs=1,
        markdown=True,
    )


def _get_agent_registry() -> Dict[str, Agent]:
    """
    Lazily instantiate and cache the reusable agent instances.
    """
    global _agent_registry
    if _agent_registry is not None:
        return _agent_registry

    _agent_registry = {
        _CONTEXTUALIZER_STEP_NAME: _build_agent(
            name=_CONTEXTUALIZER_STEP_NAME,
            description="Normalizes raw telemetry into a structured context packet.",
            instructions=CONTEXTUALIZER_INSTRUCTIONS,
            tools=[DuckDuckGoTools()],
        ),
        _PRIORITIZATION_STEP_NAME: _build_agent(
            name=_PRIORITIZATION_STEP_NAME,
            description="Ranks backlog items with risk scores and owners.",
            instructions=PRIORITIZATION_INSTRUCTIONS,
        ),
        _SUPPLY_CHAIN_STEP_NAME: _build_agent(
            name=_SUPPLY_CHAIN_STEP_NAME,
            description="Maps upstream/downstream dependencies and blast radius.",
            instructions=SUPPLY_CHAIN_INSTRUCTIONS,
        ),
        _REMEDIATION_STEP_NAME: _build_agent(
            name=_REMEDIATION_STEP_NAME,
            description="Drafts tactical and strategic remediation actions.",
            instructions=REMEDIATION_INSTRUCTIONS,
        ),
        _QA_STEP_NAME: _build_agent(
            name=_QA_STEP_NAME,
            description="Provides QA guardrails with structured confidence scoring.",
            instructions=QA_REVIEW_INSTRUCTIONS,
        ),
        _EXEC_SUMMARY_STEP_NAME: _build_agent(
            name=_EXEC_SUMMARY_STEP_NAME,
            description="Translates the workflow output into an executive-ready narrative.",
            instructions=EXECUTIVE_SUMMARY_INSTRUCTIONS,
            tools=[DuckDuckGoTools()],
        ),
    }

    return _agent_registry


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

    agent_registry = _get_agent_registry()
    contextualizer_agent = agent_registry[_CONTEXTUALIZER_STEP_NAME]
    prioritization_agent = agent_registry[_PRIORITIZATION_STEP_NAME]
    supply_chain_agent = agent_registry[_SUPPLY_CHAIN_STEP_NAME]
    remediation_agent = agent_registry[_REMEDIATION_STEP_NAME]
    qa_review_agent = agent_registry[_QA_STEP_NAME]
    executive_summary_agent = agent_registry[_EXEC_SUMMARY_STEP_NAME]

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


def initialize_agent_os() -> AgentOS:
    """
    Initialize AgentOS with the cybersecurity workflow so it can be served via FastAPI.
    """
    global _agent_os
    if _agent_os is not None:
        return _agent_os

    if not os.getenv("OPENROUTER_API_KEY"):
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. Set it before starting the AI analysis AgentOS."
        )

    workflow = initialize_ai_agents()
    agent_registry = _get_agent_registry()
    _agent_os = AgentOS(
        id=os.getenv("AI_ANALYSIS_AGENT_OS_ID", "supply-chain-ai-analysis-os"),
        name=os.getenv("AI_ANALYSIS_AGENT_OS_NAME",
                       "Supply Chain AI Analysis OS"),
        description="AgentOS exposing the multi-agent cybersecurity analysis workflow.",
        workflows=[workflow],
        agents=list(agent_registry.values()),
    )
    return _agent_os


def get_agent_os_app() -> "FastAPI":
    """
    Build (or return cached) FastAPI app backed by AgentOS.
    """
    global _agent_os_app
    if _agent_os_app is not None:
        return _agent_os_app

    agent_os = initialize_agent_os()
    _agent_os_app = agent_os.get_app()
    return _agent_os_app


def serve_agent_os(
    host: Optional[str] = None, port: Optional[int] = None, reload: bool = False, **kwargs: Any
) -> None:
    """
    Convenience helper to start the AgentOS server (mirrors the AgentOS Demo snippet).
    """
    agent_os = initialize_agent_os()
    fastapi_app = get_agent_os_app()
    resolved_host = host or os.getenv("AI_ANALYSIS_AGENT_OS_HOST", "0.0.0.0")
    resolved_port = port or _to_int(
        os.getenv("AI_ANALYSIS_AGENT_OS_PORT", "7777"), 7777)

    agent_os.serve(
        app=fastapi_app,
        host=resolved_host,
        port=resolved_port,
        reload=reload,
        **kwargs,
    )


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


if __name__ == "__main__":
    serve_agent_os()
