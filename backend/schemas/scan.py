"""
Scan-related Pydantic schemas
"""

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from ..models import ScanType, ScanStatus


class ScanBase(BaseModel):
    """Base scan schema"""
    scan_type: ScanType
    target: str
    project_name: Optional[str] = None


class ScanCreate(ScanBase):
    """Schema for creating a scan"""
    pass


class ScanUpdate(BaseModel):
    """Schema for updating a scan"""
    status: Optional[ScanStatus] = None
    vulnerability_count: Optional[int] = None
    result_json: Optional[Dict[str, Any]] = None


class Scan(ScanBase):
    """Schema for scan response"""
    id: str
    status: str  # Use str to handle enum values
    started_at: str  # ISO format string
    completed_at: Optional[str] = None  # ISO format string
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    result_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for scan list response"""
    scans: list[Scan]
    total: int

