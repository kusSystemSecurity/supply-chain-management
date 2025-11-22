# AI Analysis Architecture (Agno Runtime)

The current AI analysis pipeline is implemented with the [Agno](https://www.agno.com/)
workflow runtime (`agno==2.2.13`). The workflow lives in `backend/ai_analysis.py`
and is orchestrated through a single cached `Workflow` instance constructed by
`initialize_ai_agents()`.

## Workflow Topology
- **Contextualizer → Insight Parallel → Insight Synthesizer → Remediation Loop → Executive Summary**
  - A `Workflow` enforces the stage order.
  - **Insight Parallel** fans out `prioritization_agent` and `supply_chain_agent`
    concurrently via a `Parallel` node.
  - **Insight Synthesizer** is a custom Python step that merges the parallel outputs
    into a consolidated packet for the remediation loop.
  - **Remediation Loop** wraps `remediation_agent` and `qa_review_agent` inside an
    Agno `Loop` capped by `AI_ANALYSIS_MAX_REMEDIATION_ITERATIONS` or until QA
    confidence meets `AI_ANALYSIS_QA_TARGET_CONFIDENCE`.

## Agent Catalog
- **contextualizer_agent** (`contextual_summary`): normalizes raw telemetry into
  `environment_overview`, `exposure_hotspots`, `exploit_signals`, `telemetry_gaps`.
- **prioritization_agent** (`prioritization_report`): emits up to ten backlog
  items with risk scores, suggested owners, and next actions.
- **supply_chain_agent** (`supply_chain_report`): maps upstream/downstream
  dependencies, blast radius, and current/proposed controls per backlog item.
- **insight_synthesizer** (custom function step): merges prioritization and
  supply-chain findings into a single markdown packet for downstream agents.
- **remediation_agent** (`remediation_plan`): produces quick wins, strategic fixes,
  and compensating controls tied to backlog IDs plus owner/timebox hints.
- **qa_review_agent** (`qa_review`): outputs JSON describing gaps, assumptions,
  verification steps, `confidence` (0-1), and `should_continue` flag which gates the loop.
- **executive_summary_agent** (`executive_summary`): produces the stakeholder narrative
  and KPI scoreboard (`exposure_count`, `high_risk_assets`, `expected_risk_reduction`,
  `remediation_velocity_signal`).

## State & Dependency Model
- Agno automatically threads `StepInput.previous_step_outputs`. The contextualizer
  provides the base input; parallel steps read the contextual summary; the synthesizer
  emits the combined packet consumed by the loop.
- Shared metadata persisted with the result:
  - `scan_metadata` and `scan_data_json`
  - `workflow_run_id`
  - `qa_confidence` and `qa_iterations`
- QA loop termination occurs when either `confidence >= AI_ANALYSIS_QA_TARGET_CONFIDENCE`
  or the QA agent explicitly sets `should_continue` to `false`.

## Data Inputs
- `collect_scan_data_for_analysis(project_name, selected_scan_ids)` aggregates per-scan
  metadata (type, target, counts, CVE details).
- The bundle is serialized to UTF-8 JSON (`scan_data_json`) and injected into the
  workflow input. Every agent receives the same `<scan_data>...</scan_data>` block.

## Configuration Checklist
- `OPENROUTER_API_KEY`: required for calling OpenRouter-hosted models through Agno.
- `AI_ANALYSIS_MODEL` (default `openrouter/deepseek/deepseek-r1:free`).
- `AI_ANALYSIS_MODEL_MAX_TOKENS` (default `3200`).
- `AI_ANALYSIS_QA_TARGET_CONFIDENCE` (default `0.85`).
- `AI_ANALYSIS_MAX_REMEDIATION_ITERATIONS` (default `2`).
- Optional `AGENTOPS_API_KEY` enables usage tracing via AgentOps.

## Execution Lifecycle
1. Validate the project and selected scan IDs.
2. Collect scan metadata and render deterministic JSON context.
3. Lazily initialize the Agno workflow (`initialize_ai_agents`).
4. Run the workflow with `_build_analysis_prompt`, capturing `step_results`.
5. Extract section outputs plus QA metadata and persist to `ai_analyses_storage`.
6. Surface results through the FastAPI endpoints and the React AI Analysis view.

