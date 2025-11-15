"""
Vulnerability-related API routes
"""

from fastapi import APIRouter, HTTPException
from typing import List

from ...schemas.vulnerability import Vulnerability, VulnerabilityListResponse
from ... import get_vulnerabilities_by_scan, get_scan

router = APIRouter()


@router.get("/scan/{scan_id}", response_model=VulnerabilityListResponse)
async def get_vulnerabilities_by_scan_id(scan_id: str):
    """Get all vulnerabilities for a scan"""
    # Verify scan exists
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulnerabilities = get_vulnerabilities_by_scan(scan_id)
    return VulnerabilityListResponse(
        vulnerabilities=[Vulnerability(**dict(v)) for v in vulnerabilities],
        total=len(vulnerabilities),
        scan_id=scan_id,
    )


@router.get("/{vulnerability_id}", response_model=Vulnerability)
async def get_vulnerability_by_id(vulnerability_id: str):
    """Get vulnerability by ID"""
    from ...storage import vulnerabilities_storage

    for vuln in vulnerabilities_storage:
        if vuln.get("id") == vulnerability_id:
            return Vulnerability(**dict(vuln))

    raise HTTPException(status_code=404, detail="Vulnerability not found")

