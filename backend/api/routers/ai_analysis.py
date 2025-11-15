"""
AI Analysis-related API routes
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Optional

from ...schemas.ai_analysis import (
    AIAnalysis,
    AIAnalysisRequest,
    AIAnalysisListResponse,
)
from ... import (
    run_ai_analysis,
    get_ai_analyses_by_project,
    get_project,
)

router = APIRouter()


@router.post("/run", response_model=AIAnalysis)
async def run_analysis(request: AIAnalysisRequest, background_tasks: BackgroundTasks):
    """Run AI analysis on a project"""
    # Verify project exists
    project = get_project(request.project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Run analysis in background
    result = run_ai_analysis(request.project_name, request.selected_scan_ids)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Analysis failed"))

    analysis_result = result.get("results", {})
    return AIAnalysis(**dict(analysis_result))


@router.get("/project/{project_name}", response_model=AIAnalysisListResponse)
async def get_project_analyses(project_name: str):
    """Get all AI analyses for a project"""
    # Verify project exists
    project = get_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    analyses = get_ai_analyses_by_project(project_name)
    return AIAnalysisListResponse(
        analyses=[AIAnalysis(**dict(a)) for a in analyses],
        total=len(analyses),
    )


@router.get("/project/{project_name}/latest", response_model=AIAnalysis)
async def get_latest_analysis(project_name: str):
    """Get the latest AI analysis for a project"""
    # Verify project exists
    project = get_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    analyses = get_ai_analyses_by_project(project_name)
    if not analyses:
        raise HTTPException(status_code=404, detail="No analyses found for this project")

    return AIAnalysis(**dict(analyses[0]))

