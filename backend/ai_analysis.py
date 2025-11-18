"""
AI analysis functions using Cybersecurity AI (CAI) framework
"""

import os
import sys
import json
from typing import List, Dict, Optional
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



"""
AI analysis functions using Google ADK
"""


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
        # Prioritization Agent - Analyzes vulnerability priority
        prioritization_prompt = """You are a cybersecurity expert specializing in vulnerability prioritization.
Your task is to analyze vulnerability scan data and prioritize vulnerabilities based on:
1. CVSS scores
2. EPSS (Exploit Prediction Scoring System) scores
3. Severity levels
4. Package criticality
5. Attack surface exposure

Provide a clear prioritization ranking with reasoning for each vulnerability."""

        prioritization_agent = LlmAgent(
            name="prioritization_agent",
            model=LiteLlm(
                model="openrouter/deepseek/deepseek-r1:free",
                api_key=api_key,
                api_base="https://openrouter.ai/api/v1"
            ),
            instruction=prioritization_prompt,
            description="Prioritizes vulnerabilities based on risk and exploitability"
        )

        # Supply Chain Agent - Analyzes supply chain impact
        supply_chain_prompt = """You are a supply chain security expert.
Your task is to analyze how vulnerabilities affect the software supply chain:
1. Dependency relationships
2. Transitive vulnerabilities
3. Impact on downstream components
4. Supply chain attack vectors
5. Remediation complexity

Provide insights on supply chain risks and dependencies."""

        supply_chain_agent = LlmAgent(
            name="supply_chain_agent",
            model=LiteLlm(
                model="openrouter/deepseek/deepseek-r1:free",
                api_key=api_key,
                api_base="https://openrouter.ai/api/v1"
            ),
            instruction=supply_chain_prompt,
            description="Analyzes supply chain security impact and dependencies"
        )

        # Remediation Agent - Provides remediation guidance
        remediation_prompt = """You are a security remediation specialist.
Your task is to provide actionable remediation guidance:
1. Patch availability and versions
2. Workaround options
3. Configuration changes
4. Mitigation strategies
5. Implementation steps

Provide clear, actionable remediation steps for each vulnerability."""

        remediation_agent = LlmAgent(
            name="remediation_agent",
            model=LiteLlm(
                model="openrouter/deepseek/deepseek-r1:free",
                api_key=api_key,
                api_base="https://openrouter.ai/api/v1"
            ),
            instruction=remediation_prompt,
            description="Provides remediation guidance and mitigation strategies"
        )

        return {
            "prioritization": prioritization_agent,
            "supply_chain": supply_chain_agent,
            "remediation": remediation_agent,
        }

    except Exception as e:
        print(f"Error initializing AI agents: {e}")
        return None


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

        # Run analysis with each agent
        analysis_results = {
            "project_name": project_name,
            "analyzed_at": datetime.now().isoformat(),
            "prioritization": None,
            "supply_chain": None,
            "remediation": None,
        }

        # Prioritization analysis
        try:
            prioritization_prompt = f"""Analyze the following vulnerability scan data and provide prioritization recommendations:

{data_json}

Focus on:
- Which vulnerabilities should be addressed first
- Risk-based prioritization
- Exploitability assessment
- Business impact considerations"""

            prioritization_result = agents["prioritization"].run(
                prioritization_prompt)
            analysis_results["prioritization"] = str(prioritization_result)
        except Exception as e:
            analysis_results["prioritization"] = f"Error: {str(e)}"

        # Supply chain analysis
        try:
            supply_chain_prompt = f"""Analyze the supply chain security implications of the following vulnerability data:

{data_json}

Focus on:
- Dependency relationships
- Transitive vulnerabilities
- Supply chain attack vectors
- Impact on downstream components"""

            supply_chain_result = agents["supply_chain"].run(
                supply_chain_prompt)
            analysis_results["supply_chain"] = str(supply_chain_result)
        except Exception as e:
            analysis_results["supply_chain"] = f"Error: {str(e)}"

        # Remediation analysis
        try:
            remediation_prompt = f"""Provide remediation guidance for the following vulnerabilities:

{data_json}

Focus on:
- Available patches and updates
- Workaround options
- Configuration changes
- Step-by-step remediation instructions"""

            remediation_result = agents["remediation"].run(remediation_prompt)
            analysis_results["remediation"] = str(remediation_result)
        except Exception as e:
            analysis_results["remediation"] = f"Error: {str(e)}"

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
