"""
AI Analysis-related Pydantic schemas
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class AIAnalysisRequest(BaseModel):
    """Schema for AI analysis request"""
    project_name: str
    selected_scan_ids: Optional[List[str]] = None


class AIAnalysisResult(BaseModel):
    """Schema for AI analysis result"""

    contextual_summary: Optional[str] = None
    prioritization: Optional[str] = None
    supply_chain: Optional[str] = None
    remediation: Optional[str] = None
    qa_review: Optional[str] = None
    qa_confidence: Optional[float] = None
    qa_iterations: Optional[int] = None
    executive_summary: Optional[str] = None


class AIAnalysis(BaseModel):
    """Schema for AI analysis response"""

    project_name: str
    analyzed_at: str  # ISO format string
    scans: Optional[List[Dict[str, Any]]] = None
    scan_metadata: Optional[Dict[str, Any]] = None
    scan_data_json: Optional[str] = None
    workflow_run_id: Optional[str] = None
    contextual_summary: Optional[str] = None
    prioritization: Optional[str] = None
    supply_chain: Optional[str] = None
    remediation: Optional[str] = None
    qa_review: Optional[str] = None
    qa_confidence: Optional[float] = None
    qa_iterations: Optional[int] = None
    executive_summary: Optional[str] = None

    class Config:
        from_attributes = True


class AIAnalysisListResponse(BaseModel):
    """Schema for AI analysis list response"""
    analyses: List[AIAnalysis]
    total: int
