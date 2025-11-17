"""
AI analysis functions using Cybersecurity AI (CAI) framework
"""

import os
import json
from typing import List, Dict, Optional
from datetime import datetime

# CAI imports
try:
    from cai import CAI
    from cai.tools import VulnerabilityAssessment, ThreatIntelligence, RemediationGuidance
    CAI_AVAILABLE = True
except ImportError:
    CAI_AVAILABLE = False
    print("Warning: CAI framework not available. AI analysis features will be disabled.")
    print("Install with: pip install cai-framework")

from .storage import (
    ai_analyses_storage,
    get_scan,
)
from .projects import (
    get_project,
    get_scans_by_project,
)
from .data_collection import collect_scan_data_for_analysis


def initialize_cai_agent():
    """
    Initialize Cybersecurity AI (CAI) agent optimized for security analysis

    Returns:
        CAI agent instance or None if CAI is not available
    """
    if not CAI_AVAILABLE:
        return None

    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        print("Warning: OPENROUTER_API_KEY not set. AI analysis features will be disabled.")
        return None

    try:
        # Initialize CAI with security-optimized tools and model
        # CAI uses specialized security tools for vulnerability assessment
        cai_agent = CAI(
            model="openrouter/deepseek/deepseek-r1",  # Security-optimized model
            api_key=api_key,
            api_base="https://openrouter.ai/api/v1",
            tools=[
                VulnerabilityAssessment(),  # For vulnerability prioritization and analysis
                ThreatIntelligence(),       # For supply chain and threat analysis
                RemediationGuidance()      # For remediation recommendations
            ],
            # Security-optimized configuration
            config={
                "security_mode": "strict",
                "enable_guardrails": True,
                "prioritize_security": True,
                "comprehensive_analysis": True,
            }
        )

        return cai_agent

    except Exception as e:
        print(f"Error initializing CAI agent: {e}")
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

    # Initialize CAI agent
    cai_agent = initialize_cai_agent()
    if not cai_agent:
        return {
            "success": False,
            "error": "CAI agent not available. Please ensure cai-framework is installed and OPENROUTER_API_KEY is set."
        }

    try:
        # Collect scan data for selected scans
        scan_data = collect_scan_data_for_analysis(
            project_name, selected_scan_ids)

        # Prepare comprehensive security analysis data
        security_analysis_data = {
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
                "cve_details": scan_info["cve_details"],
                "raw_json": scan_info.get("raw_json", {})
            }
            security_analysis_data["scans"].append(scan_summary)

        # Convert to JSON string for CAI analysis
        data_json = json.dumps(security_analysis_data,
                               indent=2, ensure_ascii=False)

        # CAI Security-Optimized Analysis Flow
        # CAI performs comprehensive security analysis in a single optimized flow
        analysis_prompt = f"""Perform comprehensive security analysis on the following vulnerability scan data:

{data_json}

As a Cybersecurity AI expert, provide a complete security assessment including:

1. **Vulnerability Prioritization**:
   - Risk-based prioritization using CVSS, EPSS scores, and severity levels
   - Exploitability assessment and attack surface analysis
   - Business impact considerations
   - Critical path identification

2. **Supply Chain Security Analysis**:
   - Dependency relationship mapping
   - Transitive vulnerability assessment
   - Supply chain attack vector identification
   - Impact on downstream components and services
   - Dependency risk scoring

3. **Remediation Guidance**:
   - Available patches and version updates
   - Workaround options and mitigations
   - Configuration changes and hardening steps
   - Step-by-step remediation instructions
   - Risk reduction strategies

Provide structured, actionable security insights optimized for immediate threat response."""

        # Execute CAI security-optimized analysis
        try:
            cai_result = cai_agent.assess(analysis_prompt)

            # CAI returns comprehensive security analysis
            # Parse the result into structured components
            result_text = str(cai_result) if cai_result else ""

            # Store comprehensive analysis results
            analysis_results = {
                "project_name": project_name,
                "analyzed_at": datetime.now().isoformat(),
                "prioritization": result_text,  # CAI provides integrated prioritization
                "supply_chain": result_text,     # CAI provides integrated supply chain analysis
                "remediation": result_text,      # CAI provides integrated remediation guidance
                "cai_analysis": result_text      # Full CAI comprehensive analysis
            }

        except Exception as e:
            # Fallback error handling
            analysis_results = {
                "project_name": project_name,
                "analyzed_at": datetime.now().isoformat(),
                "prioritization": f"Error: {str(e)}",
                "supply_chain": f"Error: {str(e)}",
                "remediation": f"Error: {str(e)}",
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
            "error": f"Error running CAI security analysis: {str(e)}"
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
