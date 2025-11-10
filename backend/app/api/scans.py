"""Scan management API endpoints"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict
from enum import Enum
import logging
import uuid

from app.database import get_db
from app import crud
from app.models.database import Scan as ScanModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanTypeEnum(str, Enum):
    """Scan type enumeration"""
    GIT_REPO = "git_repo"
    CONTAINER = "container"
    VM = "vm"
    SBOM = "sbom"
    K8S = "k8s"


class ScanRequest(BaseModel):
    """Scan request model"""
    scan_type: ScanTypeEnum = Field(..., description="Type of scan to perform")
    target: str = Field(..., description="Target to scan (URL, image name, path)")
    options: Optional[Dict] = Field(default={}, description="Additional scan options")


class ScanResponse(BaseModel):
    """Scan response model"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Current scan status")
    message: Optional[str] = Field(None, description="Status message")


class ScanDetail(BaseModel):
    """Detailed scan information"""
    id: str
    scan_type: str
    target: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    vulnerability_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    model_config = ConfigDict(from_attributes=True)


class VulnerabilitySummary(BaseModel):
    """Vulnerability summary"""
    id: str
    cve_id: str
    package_name: Optional[str]
    package_version: Optional[str]
    severity: str
    cvss_score: Optional[float]
    epss_score: Optional[float]
    epss_predicted: bool = False

    model_config = ConfigDict(from_attributes=True)


@router.post("/trigger", response_model=ScanResponse)
async def trigger_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger a new security scan

    This endpoint initiates a scan based on the specified type and target.
    The scan runs asynchronously in the background.
    """
    try:
        # Create scan record in database
        scan = crud.create_scan(
            db=db,
            scan_type=scan_request.scan_type.value,
            target=scan_request.target,
            options=scan_request.options
        )

        # TODO: Add background task to actually run the scan
        # background_tasks.add_task(run_scan_task, scan.id, scan_request)

        logger.info(f"Created scan {scan.id} for {scan_request.target}")

        return ScanResponse(
            scan_id=str(scan.id),
            status="pending",
            message=f"Scan initiated for {scan_request.target}"
        )

    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Get scan details and results

    Returns detailed information about a specific scan including
    vulnerability counts and status.
    """
    try:
        # Parse UUID
        try:
            scan_uuid = uuid.UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        # Get scan from database
        scan = crud.get_scan(db, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get severity counts
        severity_counts = crud.count_vulnerabilities_by_severity(db, scan_uuid)

        return ScanDetail(
            id=str(scan.id),
            scan_type=scan.scan_type,
            target=scan.target,
            status=scan.status,
            started_at=scan.started_at.isoformat(),
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            vulnerability_count=sum(severity_counts.values()),
            critical_count=severity_counts.get("CRITICAL", 0),
            high_count=severity_counts.get("HIGH", 0),
            medium_count=severity_counts.get("MEDIUM", 0),
            low_count=severity_counts.get("LOW", 0)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[ScanDetail])
async def list_scans(
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    List all scans with optional filtering

    Returns a list of scans, optionally filtered by status and type.
    """
    try:
        # Get scans from database
        scans = crud.get_scans(
            db=db,
            status=status,
            scan_type=scan_type,
            limit=limit,
            offset=offset
        )

        # Convert to response format
        result = []
        for scan in scans:
            scan_uuid = scan.id
            severity_counts = crud.count_vulnerabilities_by_severity(db, scan_uuid)

            result.append(ScanDetail(
                id=str(scan.id),
                scan_type=scan.scan_type,
                target=scan.target,
                status=scan.status,
                started_at=scan.started_at.isoformat(),
                completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
                vulnerability_count=sum(severity_counts.values()),
                critical_count=severity_counts.get("CRITICAL", 0),
                high_count=severity_counts.get("HIGH", 0),
                medium_count=severity_counts.get("MEDIUM", 0),
                low_count=severity_counts.get("LOW", 0)
            ))

        return result

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilitySummary])
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get all vulnerabilities for a specific scan

    Returns a list of vulnerabilities discovered in the scan.
    """
    try:
        # Parse UUID
        try:
            scan_uuid = uuid.UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        # Check if scan exists
        scan = crud.get_scan(db, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get vulnerabilities from database
        vulnerabilities = crud.get_vulnerabilities_by_scan(
            db=db,
            scan_id=scan_uuid,
            severity=severity
        )

        result = [
            VulnerabilitySummary(
                id=str(v.id),
                cve_id=v.cve_id or "Unknown",
                package_name=v.package_name,
                package_version=v.package_version,
                severity=v.severity or "UNKNOWN",
                cvss_score=v.cvss_score,
                epss_score=v.epss_score,
                epss_predicted=v.epss_predicted or False
            )
            for v in vulnerabilities
        ]

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """Delete a scan and all its vulnerabilities"""
    try:
        # Parse UUID
        try:
            scan_uuid = uuid.UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        # Delete scan
        success = crud.delete_scan(db, scan_uuid)
        if not success:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"message": f"Scan {scan_id} deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
