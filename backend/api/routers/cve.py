"""
CVE-related API routes
"""

from fastapi import APIRouter, HTTPException
from typing import Dict

from ... import fetch_cve_details, update_vulnerability_with_cve_details

router = APIRouter()


@router.get("/{cve_id}")
async def get_cve_details(cve_id: str):
    """Get CVE details from CVEDetails API"""
    result = fetch_cve_details(cve_id)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch CVE details"))

    # Store in vulnerabilities if exists
    update_vulnerability_with_cve_details(cve_id, result.get("data", {}))

    return result.get("data", {})

