"""
Scan-related API routes
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List

from ...schemas.scan import Scan, ScanCreate, ScanListResponse
from ... import (
    create_scan,
    get_scan,
    get_all_scans,
    update_scan_status,
    ScanStatus,
)
from ...trivy import (
    check_trivy_installed,
    install_trivy,
    run_trivy_scan,
    parse_trivy_vulnerabilities,
)
from ...storage import vulnerabilities_storage

router = APIRouter()


@router.get("/", response_model=ScanListResponse)
async def list_scans():
    """Get all scans"""
    scans = get_all_scans()
    # Convert dict to Scan model, handling enum values
    scan_models = []
    for scan in scans:
        scan_dict = dict(scan)
        scan_models.append(Scan(**scan_dict))
    return ScanListResponse(scans=scan_models, total=len(scan_models))


@router.get("/{scan_id}", response_model=Scan)
async def get_scan_by_id(scan_id: str):
    """Get scan by ID"""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Scan(**dict(scan))


@router.post("/", response_model=Scan, status_code=201)
async def create_new_scan(scan_data: ScanCreate, background_tasks: BackgroundTasks):
    """Create a new scan"""
    # Create scan record
    scan = create_scan(
        scan_type=scan_data.scan_type.value,
        target=scan_data.target,
        project_name=scan_data.project_name,
    )

    # Run scan in background
    background_tasks.add_task(run_scan_task, scan["id"], scan_data.scan_type.value, scan_data.target)

    return Scan(**dict(scan))


def run_scan_task(scan_id: str, scan_type: str, target: str):
    """Background task to run Trivy scan"""
    try:
        # Update scan status to running
        update_scan_status(scan_id, ScanStatus.RUNNING.value)

        # Check if Trivy is available
        if not check_trivy_installed():
            if not install_trivy():
                update_scan_status(scan_id, ScanStatus.FAILED.value)
                return

        # Run Trivy scan
        scan_result = run_trivy_scan(scan_type, target)

        if not scan_result["success"]:
            update_scan_status(scan_id, ScanStatus.FAILED.value)
            return

        # Parse vulnerabilities
        trivy_data = scan_result["data"]
        vulnerabilities = parse_trivy_vulnerabilities(trivy_data, scan_id)

        # Store vulnerabilities
        for vuln in vulnerabilities:
            vulnerabilities_storage.append(vuln)

        # Get scan to update counts
        scan = get_scan(scan_id)
        if scan:
            scan["critical_count"] = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
            scan["high_count"] = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
            scan["medium_count"] = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
            scan["low_count"] = sum(1 for v in vulnerabilities if v["severity"] == "LOW")
            scan["vulnerability_count"] = len(vulnerabilities)

        # Mark scan as completed
        update_scan_status(
            scan_id,
            ScanStatus.COMPLETED.value,
            len(vulnerabilities),
            trivy_data,
        )
    except Exception as e:
        update_scan_status(scan_id, ScanStatus.FAILED.value)
        print(f"Error running scan {scan_id}: {e}")

