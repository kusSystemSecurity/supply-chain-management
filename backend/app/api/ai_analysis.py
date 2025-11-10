"""AI analysis API endpoints"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum
import logging
import uuid

from app.database import get_db
from app import crud

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai-analysis"])


class AgentTypeEnum(str, Enum):
    """AI agent type enumeration"""
    PRIORITIZATION = "prioritization"
    SUPPLY_CHAIN = "supply_chain"
    REMEDIATION = "remediation"


class AnalysisRequest(BaseModel):
    """AI analysis request model"""
    scan_id: str = Field(..., description="Scan ID to analyze")
    agents: List[AgentTypeEnum] = Field(..., description="AI agents to run")
    context: Optional[Dict] = Field(default={}, description="Additional context")


class AnalysisResponse(BaseModel):
    """AI analysis response model"""
    analysis_id: str = Field(..., description="Unique analysis identifier")
    status: str = Field(..., description="Analysis status")
    message: Optional[str] = Field(None, description="Status message")


class AnalysisDetail(BaseModel):
    """Detailed analysis information"""
    id: str
    scan_id: str
    agent_type: str
    output_data: Dict
    tokens_used: Optional[int] = None
    processing_time_ms: Optional[int] = None

    class Config:
        from_attributes = True


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_scan(
    analysis_request: AnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    Run AI agents on scan results

    Initiates AI analysis using the specified agents.
    Available agents: prioritization, supply_chain, remediation
    """
    try:
        # Parse scan UUID
        try:
            scan_uuid = uuid.UUID(analysis_request.scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        # Validate scan exists
        scan = crud.get_scan(db, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Create AI analysis records for each agent
        analysis_ids = []
        for agent in analysis_request.agents:
            analysis = crud.create_ai_analysis(
                db=db,
                scan_id=scan_uuid,
                agent_type=agent.value,
                input_data=analysis_request.context
            )
            analysis_ids.append(str(analysis.id))

        # TODO: Add background task to run AI agents
        # background_tasks.add_task(run_ai_agents, analysis_ids)

        logger.info(f"Created {len(analysis_ids)} AI analyses for scan {analysis_request.scan_id}")

        return AnalysisResponse(
            analysis_id=analysis_ids[0] if analysis_ids else "",
            status="processing",
            message=f"Analysis initiated with {len(analysis_request.agents)} agents"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """
    Get AI analysis results

    Returns the results from AI agent analysis including
    prioritization, supply chain impact, and remediation plans.
    """
    try:
        # Parse UUID
        try:
            analysis_uuid = uuid.UUID(analysis_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid analysis ID format")

        # Get analysis from database
        analysis = crud.get_ai_analysis(db, analysis_uuid)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        return AnalysisDetail(
            id=str(analysis.id),
            scan_id=str(analysis.scan_id),
            agent_type=analysis.agent_type,
            output_data=analysis.output_data or {},
            tokens_used=analysis.tokens_used,
            processing_time_ms=analysis.processing_time_ms
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/prioritize")
async def prioritize_vulnerability(
    cve_id: str,
    context: Optional[Dict] = None
):
    """
    Run prioritization agent on a single CVE

    Returns priority score, likelihood, business impact,
    and actionable recommendations.
    """
    try:
        from app.agents.prioritization import PrioritizationAgent
        from app.config import settings

        # Mock vulnerability data (in production, fetch from database)
        vuln_data = {
            "cve_id": cve_id,
            "cvss_score": 7.5,
            "epss_score": 0.05,
            "epss_percentile": 0.75,
            "risk_score": 15,
            "is_code_execution": False,
            "exploit_exists": False,
            "is_in_cisa_kev": False,
            "severity": "HIGH"
        }

        # Initialize agent
        agent = PrioritizationAgent(api_key=settings.anthropic_api_key)

        # Run prioritization
        result = await agent.prioritize_vulnerability(vuln_data, context)

        return result

    except Exception as e:
        logger.error(f"Error during prioritization: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/supply-chain")
async def analyze_supply_chain_impact(scan_ids: List[str]):
    """
    Run supply chain analysis across multiple scans

    Identifies overlapping vulnerabilities, dependency chains,
    and consolidated remediation strategies.
    """
    try:
        from app.agents.supply_chain import SupplyChainAgent
        from app.config import settings

        # Mock scan data (in production, fetch from database)
        scans = []
        for scan_id in scan_ids:
            scans.append({
                "scan_type": "git_repo",
                "target": f"scan_{scan_id}",
                "vulnerabilities": []
            })

        # Initialize agent
        agent = SupplyChainAgent(api_key=settings.anthropic_api_key)

        # Run analysis
        result = await agent.analyze_supply_chain(scans)

        return result

    except Exception as e:
        logger.error(f"Error during supply chain analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation")
async def generate_remediation_plan(
    cve_id: str,
    context: Optional[Dict] = None
):
    """
    Generate detailed remediation plan for a vulnerability

    Returns step-by-step instructions including commands,
    configuration changes, testing procedures, and rollback plans.
    """
    try:
        from app.agents.remediation import RemediationAgent
        from app.config import settings

        # Mock vulnerability data (in production, fetch from database)
        vuln_data = {
            "cve_id": cve_id,
            "package_name": "example-package",
            "package_version": "1.0.0",
            "fixed_version": "1.0.1",
            "severity": "HIGH"
        }

        # Initialize agent
        agent = RemediationAgent(api_key=settings.anthropic_api_key)

        # Generate remediation plan
        result = await agent.generate_remediation(vuln_data, context)

        return result

    except Exception as e:
        logger.error(f"Error generating remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
