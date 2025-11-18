"""
AI analysis functions using Agent-based architecture
Agent 간 데이터 흐름 및 독립성 보장
"""

import os
import sys
import json
from typing import List, Dict, Optional, Any
from datetime import datetime

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


# Google ADK imports
try:
    from google.adk.agents import LlmAgent
    from google.adk.models.lite_llm import LiteLlm
    ADK_AVAILABLE = True
except ImportError:
    ADK_AVAILABLE = False
    print("Warning: google-adk not available. AI analysis features will be disabled.")


def initialize_ai_agents():
    """
    Initialize AI agents using Google ADK with OpenRouter
    
    Agent 구조:
    - Parser: Trivy 원본 JSON → 정규화된 데이터 + 통계 (완전 독립)
    - Analyzer: 정규화된 취약점 → P0/P1/P2/P3 재분류 + 분석 리포트 (Parser 의존)
    - Red Team: P0/P1 취약점 → 익스플로잇 검증 결과 (Analyzer 의존)
    - Blue Team: 전체 분석 결과 → 방어 전략 + 규칙 (Analyzer 의존)
    - Patcher: 패치 가능 취약점 → 패치 스크립트 + 계획 (Analyzer 의존)
    - Reporter: 모든 Phase 결과 → 4종 보고서 (완전 독립, 모든 Agent 결과 수집)

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
        model_config = LiteLlm(
            model="openrouter/deepseek/deepseek-r1:free",
            api_key=api_key,
            api_base="https://openrouter.ai/api/v1"
        )

        # Parser Agent - Trivy 원본 JSON을 정규화된 데이터 + 통계로 변환
        parser_prompt = """You are a vulnerability data parser specializing in normalizing Trivy scan results.
Your task is to:
1. Parse Trivy raw JSON output
2. Normalize vulnerability data structure
3. Extract and calculate statistics:
   - Total vulnerability count by severity
   - CVE distribution
   - Package-level aggregation
   - Scan metadata

Output format:
{
    "normalized_vulnerabilities": [...],
    "statistics": {
        "total_count": int,
        "by_severity": {...},
        "by_cve": {...},
        "by_package": {...}
    },
    "metadata": {...}
}"""

        parser_agent = LlmAgent(
            name="parser_agent",
            model=model_config,
            instruction=parser_prompt,
            description="Parses and normalizes Trivy scan results with statistics"
        )

        # Analyzer Agent - 정규화된 취약점을 P0/P1/P2/P3로 재분류 + 분석 리포트
        analyzer_prompt = """You are a cybersecurity analyst specializing in vulnerability risk assessment.
Your task is to:
1. Reclassify vulnerabilities into P0/P1/P2/P3 priority levels:
   - P0: Critical, actively exploited, immediate action required
   - P1: High severity, likely to be exploited soon
   - P2: Medium severity, requires attention
   - P3: Low severity, monitor
2. Generate comprehensive analysis report:
   - Risk assessment
   - Exploitability analysis
   - Business impact
   - Attack surface analysis

Output format:
{
    "reclassified_vulnerabilities": {
        "P0": [...],
        "P1": [...],
        "P2": [...],
        "P3": [...]
    },
    "analysis_report": {
        "risk_summary": str,
        "exploitability_assessment": str,
        "business_impact": str,
        "recommendations": [...]
    }
}"""

        analyzer_agent = LlmAgent(
            name="analyzer_agent",
            model=model_config,
            instruction=analyzer_prompt,
            description="Reclassifies vulnerabilities and generates analysis reports"
        )

        # Red Team Agent - P0/P1 취약점에 대한 익스플로잇 검증
        red_team_prompt = """You are a red team security expert specializing in exploit verification.
Your task is to:
1. Analyze P0/P1 vulnerabilities for exploitability
2. Verify if exploits exist and are publicly available
3. Test attack vectors and scenarios
4. Provide proof-of-concept exploit details
5. Assess real-world attack feasibility

Focus on:
- Exploit availability (Metasploit, ExploitDB, GitHub PoCs)
- Attack complexity
- Required conditions for exploitation
- Impact if successfully exploited

Output format:
{
    "exploit_verification": {
        "verified_exploitable": [...],
        "potentially_exploitable": [...],
        "not_exploitable": [...]
    },
    "exploit_details": {
        "cve_id": str,
        "exploit_available": bool,
        "exploit_sources": [...],
        "attack_scenario": str,
        "poc_available": bool
    },
    "verification_report": str
}"""

        red_team_agent = LlmAgent(
            name="red_team_agent",
            model=model_config,
            instruction=red_team_prompt,
            description="Verifies exploitability of high-priority vulnerabilities"
        )

        # Blue Team Agent - 전체 분석 결과에 대한 방어 전략 + 규칙
        blue_team_prompt = """You are a blue team security expert specializing in defense strategies.
Your task is to:
1. Analyze all vulnerabilities and create defense strategies
2. Generate detection rules (SIEM, IDS/IPS signatures)
3. Provide mitigation controls
4. Create monitoring and alerting recommendations
5. Design incident response playbooks

Focus on:
- Network-level defenses
- Host-level protections
- Application security controls
- Detection signatures (Snort, Suricata, YARA)
- WAF rules
- Monitoring queries (Splunk, ELK)

Output format:
{
    "defense_strategies": {
        "network": [...],
        "host": [...],
        "application": [...]
    },
    "detection_rules": {
        "siem": [...],
        "ids_ips": [...],
        "yara": [...],
        "waf": [...]
    },
    "monitoring": {
        "alerts": [...],
        "dashboards": [...],
        "queries": [...]
    },
    "incident_response": {
        "playbooks": [...],
        "containment": [...],
        "remediation": [...]
    }
}"""

        blue_team_agent = LlmAgent(
            name="blue_team_agent",
            model=model_config,
            instruction=blue_team_prompt,
            description="Creates defense strategies and detection rules"
        )

        # Patcher Agent - 패치 가능 취약점에 대한 패치 스크립트 + 계획
        patcher_prompt = """You are a security patching specialist.
Your task is to:
1. Identify patchable vulnerabilities
2. Generate patch scripts (automated remediation)
3. Create patching plan with:
   - Patch availability and versions
   - Rollback procedures
   - Testing requirements
   - Deployment schedule
   - Risk assessment
4. Provide workaround options for unpatched vulnerabilities

Output format:
{
    "patchable_vulnerabilities": [...],
    "patch_scripts": {
        "cve_id": str,
        "script": str,
        "script_type": str,  # bash, ansible, terraform, etc.
        "rollback_script": str
    },
    "patching_plan": {
        "phases": [...],
        "testing_requirements": [...],
        "deployment_schedule": {...},
        "risk_assessment": str
    },
    "workarounds": {
        "cve_id": str,
        "workaround": str,
        "effectiveness": str
    }
}"""

        patcher_agent = LlmAgent(
            name="patcher_agent",
            model=model_config,
            instruction=patcher_prompt,
            description="Generates patch scripts and remediation plans"
        )

        # Reporter Agent - 모든 Phase 결과를 종합하여 4종 보고서 생성
        reporter_prompt = """You are a security report generator.
Your task is to synthesize all analysis phases into comprehensive reports:
1. Executive Summary Report (C-level)
2. Technical Deep Dive Report (Security Team)
3. Remediation Action Plan (DevOps/Engineering)
4. Compliance & Risk Report (Compliance Team)

Each report should include:
- Executive Summary: Business impact, risk overview, recommendations
- Technical Deep Dive: Detailed vulnerability analysis, exploit details, technical findings
- Remediation Plan: Step-by-step patching guide, timelines, priorities
- Compliance Report: Regulatory implications, compliance gaps, audit trail

Output format:
{
    "executive_summary": {
        "overview": str,
        "risk_level": str,
        "key_findings": [...],
        "business_impact": str,
        "recommendations": [...],
        "timeline": str
    },
    "technical_deep_dive": {
        "vulnerability_details": [...],
        "exploit_analysis": [...],
        "attack_scenarios": [...],
        "technical_recommendations": [...]
    },
    "remediation_plan": {
        "priority_matrix": {...},
        "action_items": [...],
        "timeline": {...},
        "resources_required": [...]
    },
    "compliance_report": {
        "regulatory_impact": [...],
        "compliance_gaps": [...],
        "audit_trail": [...],
        "remediation_tracking": [...]
    }
}"""

        reporter_agent = LlmAgent(
            name="reporter_agent",
            model=model_config,
            instruction=reporter_prompt,
            description="Generates comprehensive security reports from all analysis phases"
        )

        return {
            "parser": parser_agent,
            "analyzer": analyzer_agent,
            "red_team": red_team_agent,
            "blue_team": blue_team_agent,
            "patcher": patcher_agent,
            "reporter": reporter_agent,
        }

    except Exception as e:
        print(f"Error initializing AI agents: {e}")
        return None


def _build_agent_dependency_graph() -> Dict[str, List[str]]:
    """
    Agent 의존성 그래프 정의
    
    Returns:
        Dictionary mapping agent names to their dependencies
        예: {'analyzer': ['parser'], 'red_team': ['analyzer'], ...}
        
    Note:
        - 필수 의존성: 의존 Agent가 완료되어야 실행 가능
        - 선택적 의존성: 의존 Agent가 없어도 실행 가능 (Reporter는 모든 결과를 수집하지만 독립 실행 가능)
    """
    return {
        "parser": [],  # 완전 독립
        "analyzer": ["parser"],  # Parser 결과 선호 (없으면 원본 데이터 사용 가능)
        "red_team": ["analyzer"],  # Analyzer 결과 필요 (필수)
        "blue_team": ["analyzer"],  # Analyzer 결과 필요 (필수)
        "patcher": ["analyzer"],  # Analyzer 결과 필요 (필수)
        "reporter": [],  # 완전 독립 (모든 결과 수집하지만 선택적 의존성)
    }


def _topological_sort_agents(
    agents_to_run: List[str],
    dependency_graph: Dict[str, List[str]]
) -> List[List[str]]:
    """
    위상 정렬을 사용하여 Agent 실행 순서 결정
    같은 레벨의 Agent들은 병렬 실행 가능
    
    Args:
        agents_to_run: 실행할 Agent 목록
        dependency_graph: Agent 의존성 그래프
    
    Returns:
        레벨별로 그룹화된 Agent 목록 (각 레벨은 병렬 실행 가능)
        예: [['parser'], ['analyzer'], ['red_team', 'blue_team', 'patcher'], ['reporter']]
    """
    # 실행할 Agent만 필터링
    filtered_graph = {
        agent: [dep for dep in deps if dep in agents_to_run]
        for agent, deps in dependency_graph.items()
        if agent in agents_to_run
    }
    
    # 위상 정렬
    in_degree = {agent: len(filtered_graph.get(agent, [])) for agent in agents_to_run}
    levels = []
    remaining = set(agents_to_run)
    
    while remaining:
        # 현재 레벨: 의존성이 모두 해결된 Agent들
        current_level = [
            agent for agent in remaining
            if in_degree.get(agent, 0) == 0
        ]
        
        if not current_level:
            # 순환 의존성 감지 (이론적으로 발생하지 않아야 함)
            remaining_list = list(remaining)
            levels.append(remaining_list)
            break
        
        levels.append(current_level)
        remaining -= set(current_level)
        
        # 의존성 업데이트
        for agent in current_level:
            for dependent in filtered_graph:
                if agent in filtered_graph[dependent]:
                    in_degree[dependent] = in_degree.get(dependent, 0) - 1
    
    return levels


def run_ai_analysis(
    project_name: str, 
    selected_scan_ids: Optional[List[str]] = None,
    agents_to_run: Optional[List[str]] = None
) -> Dict:
    """
    Orchestrator: Run AI analysis on selected scans from a project
    
    Agent 간 데이터 흐름:
    - Orchestrator → Parser: Trivy 원본 JSON
    - Parser → Analyzer: 정규화된 데이터 + 통계
    - Analyzer → Red Team: P0/P1 취약점만
    - Analyzer → Blue Team: 전체 분석 결과
    - Analyzer → Patcher: 패치 가능 취약점만
    - All Agents → Reporter: 모든 Phase 결과
    
    각 Agent의 독립성:
    - 완전 독립: Parser, Reporter (다른 Agent 결과 불필요)
    - 조건부 독립: Red Team, Blue Team, Patcher (Analyzer 결과 필요)
    
    실행 순서는 의존성 그래프 기반으로 동적으로 결정됩니다.
    같은 레벨의 Agent들은 병렬 실행 가능합니다.
    
    Args:
        project_name: Name of the project to analyze
        selected_scan_ids: Optional list of scan IDs to analyze. If None, analyzes all scans in the project.
        agents_to_run: Optional list of agent names to run. If None, runs all agents.
                      Valid values: ['parser', 'analyzer', 'red_team', 'blue_team', 'patcher', 'reporter']

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

    # Default: run all agents if not specified
    if agents_to_run is None:
        agents_to_run = ["parser", "analyzer", "red_team", "blue_team", "patcher", "reporter"]
    
    # Validate agent names
    valid_agents = {"parser", "analyzer", "red_team", "blue_team", "patcher", "reporter"}
    agents_to_run = [a for a in agents_to_run if a in valid_agents]
    
    if not agents_to_run:
        return {
            "success": False,
            "error": "No valid agents specified to run."
        }

    # 의존성 그래프 기반으로 실행 순서 결정
    dependency_graph = _build_agent_dependency_graph()
    execution_levels = _topological_sort_agents(agents_to_run, dependency_graph)

    try:
        # Collect scan data for selected scans
        scan_data = collect_scan_data_for_analysis(project_name, selected_scan_ids)

        # Prepare Trivy raw JSON data for Parser
        trivy_raw_data = {
            "project_name": project_name,
            "scans": []
        }
        
        for scan_info in scan_data["scans"]:
            trivy_raw_data["scans"].append({
                "scan_id": scan_info["scan_id"],
                "scan_type": scan_info["scan_type"],
                "target": scan_info["target"],
                "raw_json": scan_info["raw_json"]  # Trivy 원본 JSON
            })

        trivy_json = json.dumps(trivy_raw_data, indent=2, ensure_ascii=False)

        # Initialize results structure
        analysis_results = {
            "project_name": project_name,
            "analyzed_at": datetime.now().isoformat(),
            "phases": {
                "parser": None,
                "analyzer": None,
                "red_team": None,
                "blue_team": None,
                "patcher": None,
                "reporter": None,
            },
            "errors": {},
            "execution_order": [level for level in execution_levels]  # 실행 순서 기록
        }

        # Agent 실행 결과 저장용
        agent_results = {}

        # 레벨별로 Agent 실행 (같은 레벨은 병렬 실행 가능, 현재는 순차 실행)
        for level_idx, level in enumerate(execution_levels):
            for agent_name in level:
                if agent_name not in agents_to_run:
                    continue
                
                try:
                    # 각 Agent별 실행 로직
                    if agent_name == "parser":
                        parser_prompt = f"""Parse and normalize the following Trivy scan results:

{trivy_json}

Extract normalized vulnerability data and calculate comprehensive statistics."""
                        
                        result = agents["parser"].run(parser_prompt)
                        agent_results["parser"] = str(result)
                        analysis_results["phases"]["parser"] = str(result)
                    
                    elif agent_name == "analyzer":
                        # Parser 결과가 있으면 사용, 없으면 원본 데이터 사용
                        if agent_results.get("parser"):
                            analyzer_input = f"""Analyze the following normalized vulnerability data:

{agent_results["parser"]}

Reclassify vulnerabilities into P0/P1/P2/P3 priority levels and generate analysis report."""
                        else:
                            # Parser 없이 실행하는 경우 원본 데이터 사용
                            analyzer_input = f"""Analyze the following vulnerability scan data:

{json.dumps(scan_data, indent=2, ensure_ascii=False)}

Reclassify vulnerabilities into P0/P1/P2/P3 priority levels and generate analysis report."""
                        
                        result = agents["analyzer"].run(analyzer_input)
                        agent_results["analyzer"] = str(result)
                        analysis_results["phases"]["analyzer"] = str(result)
                    
                    elif agent_name == "red_team":
                        # Analyzer 결과 확인
                        if not agent_results.get("analyzer"):
                            analysis_results["errors"]["red_team"] = "Skipped: Analyzer phase required but not completed"
                            continue
                        
                        red_team_prompt = f"""Analyze the following P0/P1 high-priority vulnerabilities for exploitability:

{agent_results["analyzer"]}

Focus only on P0 and P1 vulnerabilities. Verify exploit availability and provide attack scenarios."""
                        
                        result = agents["red_team"].run(red_team_prompt)
                        agent_results["red_team"] = str(result)
                        analysis_results["phases"]["red_team"] = str(result)
                    
                    elif agent_name == "blue_team":
                        # Analyzer 결과 확인
                        if not agent_results.get("analyzer"):
                            analysis_results["errors"]["blue_team"] = "Skipped: Analyzer phase required but not completed"
                            continue
                        
                        blue_team_prompt = f"""Create defense strategies and detection rules based on the following vulnerability analysis:

{agent_results["analyzer"]}

Generate comprehensive defense strategies, detection rules, and monitoring recommendations."""
                        
                        result = agents["blue_team"].run(blue_team_prompt)
                        agent_results["blue_team"] = str(result)
                        analysis_results["phases"]["blue_team"] = str(result)
                    
                    elif agent_name == "patcher":
                        # Analyzer 결과 확인
                        if not agent_results.get("analyzer"):
                            analysis_results["errors"]["patcher"] = "Skipped: Analyzer phase required but not completed"
                            continue
                        
                        patcher_prompt = f"""Generate patch scripts and remediation plans for patchable vulnerabilities:

{agent_results["analyzer"]}

Identify patchable vulnerabilities and create automated patch scripts with rollback procedures."""
                        
                        result = agents["patcher"].run(patcher_prompt)
                        agent_results["patcher"] = str(result)
                        analysis_results["phases"]["patcher"] = str(result)
                    
                    elif agent_name == "reporter":
                        # 모든 Phase 결과를 종합 (선택적 의존성)
                        all_phases_data = {
                            "parser": agent_results.get("parser"),
                            "analyzer": agent_results.get("analyzer"),
                            "red_team": agent_results.get("red_team"),
                            "blue_team": agent_results.get("blue_team"),
                            "patcher": agent_results.get("patcher"),
                        }
                        
                        reporter_prompt = f"""Generate comprehensive security reports from all analysis phases:

{json.dumps(all_phases_data, indent=2, ensure_ascii=False)}

Create 4 types of reports:
1. Executive Summary Report (C-level)
2. Technical Deep Dive Report (Security Team)
3. Remediation Action Plan (DevOps/Engineering)
4. Compliance & Risk Report (Compliance Team)"""
                        
                        result = agents["reporter"].run(reporter_prompt)
                        agent_results["reporter"] = str(result)
                        analysis_results["phases"]["reporter"] = str(result)
                
                except Exception as e:
                    error_msg = f"{agent_name} Agent error: {str(e)}"
                    analysis_results["errors"][agent_name] = error_msg
                    print(error_msg)
                    # 에러 발생해도 다음 Agent 계속 실행

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
