"""
Project management functions
"""

from typing import List, Dict, Optional
from datetime import datetime

from .storage import (
    projects_storage,
    get_scan,
)


def create_project(project_name: str) -> Dict:
    """
    Create a new project

    Args:
        project_name: Name of the project

    Returns:
        Dictionary with project information
    """
    # Check if project already exists
    existing_project = get_project(project_name)
    if existing_project:
        return existing_project

    project = {
        "name": project_name,
        "created_at": datetime.now().isoformat(),
        "scan_ids": [],
    }
    projects_storage.append(project)
    return project


def get_project(project_name: str) -> Optional[Dict]:
    """
    Get project by name

    Args:
        project_name: Name of the project

    Returns:
        Project dictionary or None if not found
    """
    for project in projects_storage:
        if project.get("name") == project_name:
            return project
    return None


def get_all_projects() -> List[Dict]:
    """Get all projects"""
    return projects_storage.copy()


def assign_scan_to_project(scan_id: str, project_name: str) -> bool:
    """
    Assign a scan to a project

    Args:
        scan_id: ID of the scan
        project_name: Name of the project

    Returns:
        True if successful, False otherwise
    """
    # Get or create project
    project = get_project(project_name)
    if not project:
        project = create_project(project_name)

    # Update scan's project_name
    scan = get_scan(scan_id)
    if not scan:
        return False

    scan["project_name"] = project_name

    # Add scan_id to project if not already present
    if scan_id not in project["scan_ids"]:
        project["scan_ids"].append(scan_id)

    return True


def get_scans_by_project(project_name: str) -> List[Dict]:
    """
    Get all scans for a project

    Args:
        project_name: Name of the project

    Returns:
        List of scan dictionaries
    """
    project = get_project(project_name)
    if not project:
        return []

    scans = []
    for scan_id in project.get("scan_ids", []):
        scan = get_scan(scan_id)
        if scan:
            scans.append(scan)

    return scans

