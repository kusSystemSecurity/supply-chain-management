"""
Project-related API routes
"""

from fastapi import APIRouter, HTTPException
from typing import List

from ...schemas.project import Project, ProjectCreate, ProjectListResponse, AssignScanRequest
from ...schemas.scan import Scan
from ... import (
    create_project,
    get_project,
    get_all_projects,
    assign_scan_to_project,
    get_scans_by_project,
    get_scan,
)

router = APIRouter()


@router.get("/", response_model=ProjectListResponse)
async def list_projects():
    """Get all projects"""
    projects = get_all_projects()
    return ProjectListResponse(
        projects=[Project(**dict(p)) for p in projects],
        total=len(projects),
    )


@router.get("/{project_name}", response_model=Project)
async def get_project_by_name(project_name: str):
    """Get project by name"""
    project = get_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return Project(**dict(project))


@router.post("/", response_model=Project, status_code=201)
async def create_new_project(project_data: ProjectCreate):
    """Create a new project"""
    project = create_project(project_data.name)
    return Project(**dict(project))


@router.post("/assign-scan", response_model=dict)
async def assign_scan_to_project_endpoint(request: AssignScanRequest):
    """Assign a scan to a project"""
    success = assign_scan_to_project(request.scan_id, request.project_name)
    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to assign scan {request.scan_id} to project {request.project_name}",
        )
    return {"message": "Scan assigned successfully", "scan_id": request.scan_id, "project_name": request.project_name}


@router.get("/{project_name}/scans", response_model=List[Scan])
async def get_project_scans(project_name: str):
    """Get all scans for a project"""
    project = get_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scans = get_scans_by_project(project_name)
    return [Scan(**dict(scan)) for scan in scans]

