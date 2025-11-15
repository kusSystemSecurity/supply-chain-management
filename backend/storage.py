"""
Storage and CRUD operations for scans and vulnerabilities
"""

from typing import List, Dict, Optional
from datetime import datetime
import uuid

from .models import ScanStatus


# ============= In-Memory Storage =============

# Simple in-memory storage (replace with database in production)
scans_storage: List[Dict] = []
vulnerabilities_storage: List[Dict] = []
projects_storage: List[Dict] = []
ai_analyses_storage: List[Dict] = []


# ============= Scan Operations =============


def create_scan(scan_type: str, target: str, project_name: Optional[str] = None) -> Dict:
    """Create a new scan"""
    scan_id = str(uuid.uuid4())
    scan = {
        "id": scan_id,
        "scan_type": scan_type,
        "target": target,
        "status": ScanStatus.PENDING.value,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "vulnerability_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "result_json": None,  # Store original Trivy JSON output
        "project_name": project_name,  # Project assignment
    }
    scans_storage.append(scan)
    return scan


def get_scan(scan_id: str) -> Optional[Dict]:
    """Get scan by ID"""
    for scan in scans_storage:
        if scan["id"] == scan_id:
            return scan
    return None


def get_all_scans() -> List[Dict]:
    """Get all scans"""
    return scans_storage.copy()


def update_scan_status(
    scan_id: str, status: str, vulnerability_count: int = 0, result_json: dict = None
):
    """Update scan status"""
    scan = get_scan(scan_id)
    if scan:
        scan["status"] = status
        if status == ScanStatus.COMPLETED.value:
            scan["completed_at"] = datetime.now().isoformat()
            scan["vulnerability_count"] = vulnerability_count
        if result_json is not None:
            scan["result_json"] = result_json


# ============= Vulnerability Operations =============


def add_vulnerability(
    scan_id: str,
    cve_id: str,
    package_name: str = None,
    package_version: str = None,
    severity: str = None,
    cvss_score: float = None,
    epss_score: float = None,
    cve_api_details: dict = None,
):
    """Add vulnerability to storage"""
    vuln = {
        "id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "cve_id": cve_id,
        "package_name": package_name,
        "package_version": package_version,
        "severity": severity or "UNKNOWN",
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "epss_predicted": False,
        "cve_api_details": cve_api_details,  # Store raw CVEDetails API response
    }
    vulnerabilities_storage.append(vuln)
    return vuln


def get_vulnerabilities_by_scan(scan_id: str) -> List[Dict]:
    """Get all vulnerabilities for a scan"""
    return [v for v in vulnerabilities_storage if v["scan_id"] == scan_id]


def update_vulnerability_with_cve_details(cve_id: str, cve_api_details: dict):
    """
    Update existing vulnerability with CVE API details

    Args:
        cve_id: CVE ID to update
        cve_api_details: Raw CVE API response data
    """
    for vuln in vulnerabilities_storage:
        if vuln.get("cve_id") == cve_id:
            vuln["cve_api_details"] = cve_api_details
            print(f"Updated vulnerability {cve_id} with API details")
            break

