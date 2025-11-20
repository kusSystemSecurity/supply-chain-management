# AI Analysis Architecture (Archived)

This document preserves the structure of the retired Google ADK-based AI
analysis workflow that previously lived in `backend/ai_analysis.py`. The code
has been removed for compliance reasons, but the design is kept here for
reference in case the capability is revisited.

## Workflow Topology
- **Contextualizer → Insight Parallel → Remediation Loop → Executive Summary**  
  A `SequentialAgent` (`cybersecurity_pipeline`) enforced the stage order.
- **Insight Parallel** fanned out `prioritization_agent` and
  `supply_chain_agent` concurrently via a `ParallelAgent`.
- **Remediation Loop** wrapped `remediation_agent` and `qa_review_agent` inside a
  `LoopAgent` capped at two iterations or until QA confidence exceeded the
  configured threshold.

## Agent Catalog
- **contextualizer_agent** (`contextual_summary`): normalized scan telemetry into
  `environment_overview`, `exposure_hotspots`, `exploit_signals`,
  `telemetry_gaps`. Could call Google Search when available.
- **prioritization_agent** (`prioritization_report`): produced a backlog of up to
  10 ranked items with risk scores, owners, and near-term actions.
- **supply_chain_agent** (`supply_chain_report`): mapped upstream/downstream
  dependencies, blast radius, and controls for each prioritized risk.
- **remediation_agent** (`remediation_plan`): emitted quick wins, strategic
  fixes, and compensating controls tied back to backlog IDs plus owner/timebox
  hints.
- **qa_review_agent** (`qa_review`): generated JSON describing gaps, assumptions,
  verification steps, and a `confidence` value from 0-1 which gated the loop.
- **executive_summary_agent** (`executive_summary`): produced the stakeholder
  narrative and KPI scoreboard (exposure_count, high_risk_assets,
  expected_risk_reduction, remediation_velocity_signal).

## State & Dependency Model
- Agent state keys were defined in `AGENT_STATE_KEY_BY_NAME`; downstream agents
  waited on required keys listed in `AGENT_DEPENDENCIES`.
- Shared state also held `qa_confidence`, `qa_target_confidence`,
  `remediation_iteration`, and the JSON-serialized scan bundle.
- `_wait_for_dependencies` polled the shared state with a 30-second timeout to
  sequence agents executed in parallel.

## Data Inputs
- `collect_scan_data_for_analysis(project_name, selected_scan_ids)` aggregated
  per-scan metadata (type, target, counts, CVE details).
- This bundle was normalized to UTF-8 JSON (`data_json`) and injected into every
  prompt builder for deterministic context.
- `scan_overview` (dict) plus project metadata were also part of the shared
  state so downstream agents could reason over aggregated metrics.

## Configuration Checklist
- `OPENROUTER_API_KEY`: required for LiteLlm access through OpenRouter.
- `OPENROUTER_API_BASE`: defaulted to `https://openrouter.ai/api/v1`.
- `AI_ANALYSIS_MODEL`: defaulted to `openrouter/deepseek/deepseek-r1:free`.
- `AI_ANALYSIS_QA_TARGET_CONFIDENCE`: float, default `0.85`, used to terminate
  the remediation loop early when QA feedback was satisfactory.
- Optional `AGENTOPS_API_KEY` enabled usage tracing via AgentOps.

## Execution Lifecycle
1. Validate the project and gather the selected scans.
2. Initialize agents (`initialize_ai_agents`) and compose the workflow (sequential,
   parallel, loop nodes) when Google ADK was available.
3. Build prompts per agent via `PROMPT_BUILDERS` using the shared state.
4. Walk the pipeline with `_run_workflow_pipeline`, mutating the shared state as
   each agent completed.
5. Persist the final composite result to `ai_analyses_storage` and return it
   through `run_ai_analysis`.

## Decommissioning Notes
- The runtime integration has been removed from `backend/ai_analysis.py`; the
  module now only exposes stubs that always return a deterministic error.
- API consumers should surface the stub message or guard the endpoints until a
  replacement strategy is defined.
- When/if reinstated, start from the architecture described above or import the
  archived prompts directly from version control history.

