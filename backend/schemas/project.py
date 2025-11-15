"""
Project-related Pydantic schemas
"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel


class ProjectBase(BaseModel):
    """Base project schema"""
    name: str


class ProjectCreate(ProjectBase):
    """Schema for creating a project"""
    pass


class Project(ProjectBase):
    """Schema for project response"""
    created_at: str  # ISO format string
    scan_ids: List[str] = []

    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    """Schema for project list response"""
    projects: List[Project]
    total: int


class AssignScanRequest(BaseModel):
    """Schema for assigning scan to project"""
    scan_id: str
    project_name: str

