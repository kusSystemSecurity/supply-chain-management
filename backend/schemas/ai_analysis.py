"""
AI Analysis-related Pydantic schemas
Agent 기반 구조 반영
"""

from typing import Optional, List, Dict
from datetime import datetime
from pydantic import BaseModel


class AIAnalysisRequest(BaseModel):
    """Schema for AI analysis request"""
    project_name: str
    selected_scan_ids: Optional[List[str]] = None
    agents_to_run: Optional[List[str]] = None  # 선택적 Agent 실행


class AIAnalysisPhases(BaseModel):
    """Schema for AI analysis phases results"""
    parser: Optional[str] = None  # 정규화된 데이터 + 통계
    analyzer: Optional[str] = None  # P0/P1/P2/P3 재분류 + 분석 리포트
    red_team: Optional[str] = None  # 익스플로잇 검증 결과
    blue_team: Optional[str] = None  # 방어 전략 + 규칙
    patcher: Optional[str] = None  # 패치 스크립트 + 계획
    reporter: Optional[str] = None  # 4종 보고서


class AIAnalysis(BaseModel):
    """Schema for AI analysis response"""
    project_name: str
    analyzed_at: str  # ISO format string
    phases: AIAnalysisPhases  # 각 Agent Phase 결과
    errors: Optional[Dict[str, str]] = None  # 각 Agent별 에러 정보

    class Config:
        from_attributes = True


class AIAnalysisListResponse(BaseModel):
    """Schema for AI analysis list response"""
    analyses: List[AIAnalysis]
    total: int

