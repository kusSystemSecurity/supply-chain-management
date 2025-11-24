"""
Chat agent implementation using Agno
"""

import os
import json
from typing import List, Dict, Optional, Any
from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from dotenv import load_dotenv

from .storage import (
    get_all_scans,
    get_scan,
    get_vulnerabilities_by_scan,
    projects_storage,
    scans_storage,
    vulnerabilities_storage,
    ai_analyses_storage
)

load_dotenv()

# Model configuration
CHAT_MODEL_ID = os.getenv("CHAT_MODEL_ID", "x-ai/grok-4.1-fast:free")


def get_scans_summary() -> str:
    """
    Get a summary of all scans.
    Returns a JSON string with scan details.
    """
    scans = get_all_scans()
    summary = []
    for scan in scans:
        summary.append({
            "id": scan["id"],
            "type": scan["scan_type"],
            "target": scan["target"],
            "status": scan["status"],
            "vulnerabilities": scan["vulnerability_count"],
            "project": scan.get("project_name")
        })
    return json.dumps(summary, indent=2)


def get_scan_details_tool(scan_id: str) -> str:
    """
    Get detailed information about a specific scan, including vulnerabilities.
    Args:
        scan_id: The ID of the scan.
    """
    scan = get_scan(scan_id)
    if not scan:
        return f"Scan with ID {scan_id} not found."
    
    vulns = get_vulnerabilities_by_scan(scan_id)
    
    # Summarize vulnerabilities to avoid token limits
    vuln_summary = []
    for v in vulns[:20]: # Limit to top 20
        vuln_summary.append({
            "cve": v["cve_id"],
            "severity": v["severity"],
            "package": f"{v['package_name']}@{v['package_version']}",
            "title": v.get("cve_api_details", {}).get("vulnerability", {}).get("title", "N/A")
        })
        
    result = {
        "scan": scan,
        "vulnerabilities_count": len(vulns),
        "top_vulnerabilities": vuln_summary
    }
    return json.dumps(result, indent=2)


def get_projects_summary() -> str:
    """
    Get a summary of all projects.
    """
    return json.dumps(projects_storage, indent=2)


def get_ai_analyses_summary() -> str:
    """
    Get a summary of all AI analyses.
    """
    return json.dumps(ai_analyses_storage, indent=2)


def create_chat_agent() -> Agent:
    """
    Create and return the chat agent.
    """
    return Agent(
        name="SecureChain Chatbot",
        model=OpenRouter(id=CHAT_MODEL_ID),
        description="You are a helpful security assistant for the SecureChain platform. You have access to scan results and vulnerability data.",
        instructions="""
        You are the AI assistant for SecureChain, a supply chain security platform.
        Your goal is to help users understand their security posture, analyze scan results, and find vulnerabilities.
        
        You have access to the following tools:
        - get_scans_summary: Lists all scans with high-level details.
        - get_scan_details_tool: Gets detailed info for a specific scan, including top vulnerabilities.
        - get_projects_summary: Lists all projects.
        - get_ai_analyses_summary: Lists all AI analyses.

        When answering:
        1. Be concise and helpful.
        2. Use markdown for formatting (tables, lists, code blocks).
        3. If a user asks about a specific scan, look it up.
        4. If a user asks about "critical" issues, filter the data accordingly.
        5. Always base your answers on the data returned by the tools.
        """,
        tools=[get_scans_summary, get_scan_details_tool, get_projects_summary, get_ai_analyses_summary],
        markdown=True,
        add_datetime_to_context=True,
    )

chat_agent = create_chat_agent()

def chat_with_agent(message: str, history: List[Dict[str, str]] = None) -> str:
    """
    Send a message to the agent and get a response.
    """
    # Note: Agno agents manage their own history if session_id is used, 
    # but for this simple stateless API, we might just pass the message.
    # If we wanted to support history, we'd need to format it for the agent or use a session.
    # For now, we'll just send the current message, or append history to the prompt if needed.
    
    # Simple stateless interaction for now
    response = chat_agent.run(message)
    return response.content
