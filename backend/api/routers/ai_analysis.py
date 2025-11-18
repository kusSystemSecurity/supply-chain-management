"""
AI Analysis-related API routes
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Optional

from ...schemas.ai_analysis import (
    AIAnalysis,
    AIAnalysisRequest,
    AIAnalysisListResponse,
    AIAnalysisPhases,
)
from ... import (
    run_ai_analysis,
    get_ai_analyses_by_project,
    get_project,
)

router = APIRouter()


@router.post("/run", response_model=AIAnalysis)
async def run_analysis(request: AIAnalysisRequest, background_tasks: BackgroundTasks):
    """Run AI analysis on a project with optional agent selection"""
    # Verify project exists
    project = get_project(request.project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Run analysis with optional agent selection
    result = run_ai_analysis(
        request.project_name, 
        request.selected_scan_ids,
        request.agents_to_run
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Analysis failed"))

    analysis_result = result.get("results", {})
    # Convert phases dict to AIAnalysisPhases object
    if "phases" in analysis_result:
        analysis_result["phases"] = AIAnalysisPhases(**analysis_result["phases"])
    return AIAnalysis(**dict(analysis_result))


@router.get("/project/{project_name}", response_model=AIAnalysisListResponse)
async def get_project_analyses(project_name: str):
    """Get all AI analyses for a project"""
    # Verify project exists
    project = get_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    analyses = get_ai_analyses_by_project(project_name)
    # Convert phases dict to AIAnalysisPhases object for each analysis
    converted_analyses = []
    for a in analyses:
        analysis_dict = dict(a)
        if "phases" in analysis_dict and isinstance(analysis_dict["phases"], dict):
            analysis_dict["phases"] = AIAnalysisPhases(**analysis_dict["phases"])
        converted_analyses.append(AIAnalysis(**analysis_dict))
    
    return AIAnalysisListResponse(
        analyses=converted_analyses,
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

    # Convert phases dict to AIAnalysisPhases object
    analysis_dict = dict(analyses[0])
    if "phases" in analysis_dict and isinstance(analysis_dict["phases"], dict):
        analysis_dict["phases"] = AIAnalysisPhases(**analysis_dict["phases"])
    return AIAnalysis(**analysis_dict)

