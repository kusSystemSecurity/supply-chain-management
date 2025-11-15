"""
AI Analysis-related Pydantic schemas
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class AIAnalysisRequest(BaseModel):
    """Schema for AI analysis request"""
    project_name: str
    selected_scan_ids: Optional[List[str]] = None


class AIAnalysisResult(BaseModel):
    """Schema for AI analysis result"""
    prioritization: Optional[str] = None
    supply_chain: Optional[str] = None
    remediation: Optional[str] = None


class AIAnalysis(BaseModel):
    """Schema for AI analysis response"""
    project_name: str
    analyzed_at: str  # ISO format string
    prioritization: Optional[str] = None
    supply_chain: Optional[str] = None
    remediation: Optional[str] = None

    class Config:
        from_attributes = True


class AIAnalysisListResponse(BaseModel):
    """Schema for AI analysis list response"""
    analyses: List[AIAnalysis]
    total: int

