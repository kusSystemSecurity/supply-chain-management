"""
Pydantic schemas for API request/response models
"""

from .scan import Scan, ScanCreate, ScanUpdate
from .vulnerability import Vulnerability, VulnerabilityDetail
from .project import Project, ProjectCreate
from .ai_analysis import AIAnalysis, AIAnalysisRequest, AIAnalysisResult

__all__ = [
    "Scan",
    "ScanCreate",
    "ScanUpdate",
    "Vulnerability",
    "VulnerabilityDetail",
    "Project",
    "ProjectCreate",
    "AIAnalysis",
    "AIAnalysisRequest",
    "AIAnalysisResult",
]

