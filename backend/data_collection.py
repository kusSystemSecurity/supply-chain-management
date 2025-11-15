"""
Data collection functions for AI analysis
"""

from typing import List, Dict, Optional

from .projects import get_scans_by_project, get_project
from .storage import get_scan, get_vulnerabilities_by_scan


def collect_scan_data_for_analysis(project_name: str, selected_scan_ids: Optional[List[str]] = None) -> Dict:
    """
    Collect scan data (raw JSON and CVE details) for a project

    Args:
        project_name: Name of the project
        selected_scan_ids: Optional list of scan IDs to analyze. If None, analyzes all scans in the project.

    Returns:
        Dictionary containing structured scan data:
        {
            "project_name": str,
            "scans": [
                {
                    "scan_id": str,
                    "scan_type": str,
                    "target": str,
                    "raw_json": dict,  # Trivy result_json
                    "cve_details": [
                        {
                            "cve_id": str,
                            "cve_api_details": dict  # From CVEDetails API
                        }
                    ]
                }
            ]
        }
    """
    if selected_scan_ids:
        # Use selected scans only
        scans = [get_scan(scan_id)
                 for scan_id in selected_scan_ids if get_scan(scan_id)]
        # Filter to only include scans that belong to the project
        project = get_project(project_name)
        if project:
            project_scan_ids = set(project.get("scan_ids", []))
            scans = [s for s in scans if s.get("id") in project_scan_ids]
    else:
        # Use all scans in the project
        scans = get_scans_by_project(project_name)

    collected_data = {
        "project_name": project_name,
        "scans": [],
    }

    for scan in scans:
        scan_id = scan.get("id")
        if not scan_id:
            continue

        # Get raw JSON from scan
        raw_json = scan.get("result_json")

        # Get all vulnerabilities for this scan
        vulnerabilities = get_vulnerabilities_by_scan(scan_id)

        # Collect CVE details
        cve_details = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            cve_api_details = vuln.get("cve_api_details")

            if cve_id and cve_api_details:
                cve_details.append({
                    "cve_id": cve_id,
                    "cve_api_details": cve_api_details,
                    "package_name": vuln.get("package_name"),
                    "package_version": vuln.get("package_version"),
                    "severity": vuln.get("severity"),
                    "cvss_score": vuln.get("cvss_score"),
                    "epss_score": vuln.get("epss_score"),
                })

        scan_data = {
            "scan_id": scan_id,
            "scan_type": scan.get("scan_type"),
            "target": scan.get("target"),
            "raw_json": raw_json,
            "cve_details": cve_details,
            "vulnerability_count": scan.get("vulnerability_count", 0),
        }

        collected_data["scans"].append(scan_data)

    return collected_data

