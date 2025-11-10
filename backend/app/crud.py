"""CRUD operations for database models"""
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import uuid

from app.models.database import Scan, Vulnerability, AIAnalysis, ScanStatus
import logging

logger = logging.getLogger(__name__)


# ============= SCAN CRUD =============

def create_scan(
    db: Session,
    scan_type: str,
    target: str,
    options: dict = None
) -> Scan:
    """Create a new scan"""
    scan = Scan(
        id=uuid.uuid4(),
        scan_type=scan_type,
        target=target,
        status=ScanStatus.PENDING.value,
        started_at=datetime.utcnow(),
        result_json=options or {}
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(f"Created scan {scan.id} for {target}")
    return scan


def get_scan(db: Session, scan_id: uuid.UUID) -> Optional[Scan]:
    """Get scan by ID"""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_scans(
    db: Session,
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 20,
    offset: int = 0
) -> List[Scan]:
    """Get scans with optional filters"""
    query = db.query(Scan)

    if status:
        query = query.filter(Scan.status == status)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)

    query = query.order_by(desc(Scan.started_at))
    query = query.limit(limit).offset(offset)

    return query.all()


def update_scan_status(
    db: Session,
    scan_id: uuid.UUID,
    status: str,
    error_message: Optional[str] = None,
    result_json: Optional[dict] = None
) -> Optional[Scan]:
    """Update scan status"""
    scan = get_scan(db, scan_id)
    if not scan:
        return None

    scan.status = status
    if error_message:
        scan.error_message = error_message
    if result_json:
        scan.result_json = result_json
    if status == ScanStatus.COMPLETED.value:
        scan.completed_at = datetime.utcnow()

    db.commit()
    db.refresh(scan)
    logger.info(f"Updated scan {scan_id} status to {status}")
    return scan


def delete_scan(db: Session, scan_id: uuid.UUID) -> bool:
    """Delete a scan and all its vulnerabilities"""
    scan = get_scan(db, scan_id)
    if not scan:
        return False

    db.delete(scan)
    db.commit()
    logger.info(f"Deleted scan {scan_id}")
    return True


# ============= VULNERABILITY CRUD =============

def create_vulnerability(
    db: Session,
    scan_id: uuid.UUID,
    cve_id: str,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    severity: Optional[str] = None,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    epss_predicted: bool = False,
    cve_details: Optional[dict] = None
) -> Vulnerability:
    """Create a new vulnerability"""
    vuln = Vulnerability(
        id=uuid.uuid4(),
        scan_id=scan_id,
        cve_id=cve_id,
        package_name=package_name,
        package_version=package_version,
        severity=severity,
        cvss_score=cvss_score,
        epss_score=epss_score,
        epss_predicted=epss_predicted,
        cve_details=cve_details or {}
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def bulk_create_vulnerabilities(
    db: Session,
    scan_id: uuid.UUID,
    vulnerabilities: List[dict]
) -> List[Vulnerability]:
    """Create multiple vulnerabilities efficiently"""
    vuln_objects = []

    for vuln_data in vulnerabilities:
        vuln = Vulnerability(
            id=uuid.uuid4(),
            scan_id=scan_id,
            cve_id=vuln_data.get('cve_id'),
            package_name=vuln_data.get('package_name'),
            package_version=vuln_data.get('package_version'),
            severity=vuln_data.get('severity'),
            cvss_score=vuln_data.get('cvss_score'),
            epss_score=vuln_data.get('epss_score'),
            epss_predicted=vuln_data.get('epss_predicted', False),
            cve_details=vuln_data.get('cve_details', {})
        )
        vuln_objects.append(vuln)

    db.bulk_save_objects(vuln_objects)
    db.commit()
    logger.info(f"Created {len(vuln_objects)} vulnerabilities for scan {scan_id}")

    return vuln_objects


def get_vulnerability(db: Session, vuln_id: uuid.UUID) -> Optional[Vulnerability]:
    """Get vulnerability by ID"""
    return db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()


def get_vulnerabilities_by_scan(
    db: Session,
    scan_id: uuid.UUID,
    severity: Optional[str] = None
) -> List[Vulnerability]:
    """Get all vulnerabilities for a scan"""
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)

    if severity:
        query = query.filter(Vulnerability.severity == severity)

    return query.all()


def get_vulnerabilities_by_cve(
    db: Session,
    cve_id: str
) -> List[Vulnerability]:
    """Get all vulnerabilities with specific CVE ID"""
    return db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).all()


def update_vulnerability(
    db: Session,
    vuln_id: uuid.UUID,
    **kwargs
) -> Optional[Vulnerability]:
    """Update vulnerability fields"""
    vuln = get_vulnerability(db, vuln_id)
    if not vuln:
        return None

    for key, value in kwargs.items():
        if hasattr(vuln, key):
            setattr(vuln, key, value)

    db.commit()
    db.refresh(vuln)
    return vuln


def count_vulnerabilities_by_severity(
    db: Session,
    scan_id: uuid.UUID
) -> dict:
    """Count vulnerabilities by severity for a scan"""
    vulnerabilities = get_vulnerabilities_by_scan(db, scan_id)

    counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0
    }

    for vuln in vulnerabilities:
        severity = vuln.severity or 'UNKNOWN'
        if severity in counts:
            counts[severity] += 1
        else:
            counts['UNKNOWN'] += 1

    return counts


# ============= AI ANALYSIS CRUD =============

def create_ai_analysis(
    db: Session,
    scan_id: uuid.UUID,
    agent_type: str,
    input_data: Optional[dict] = None,
    output_data: Optional[dict] = None,
    tokens_used: Optional[int] = None,
    processing_time_ms: Optional[int] = None
) -> AIAnalysis:
    """Create a new AI analysis"""
    analysis = AIAnalysis(
        id=uuid.uuid4(),
        scan_id=scan_id,
        agent_type=agent_type,
        input_data=input_data or {},
        output_data=output_data or {},
        tokens_used=tokens_used,
        processing_time_ms=processing_time_ms
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    logger.info(f"Created AI analysis {analysis.id} for scan {scan_id}")
    return analysis


def get_ai_analysis(db: Session, analysis_id: uuid.UUID) -> Optional[AIAnalysis]:
    """Get AI analysis by ID"""
    return db.query(AIAnalysis).filter(AIAnalysis.id == analysis_id).first()


def get_ai_analyses_by_scan(
    db: Session,
    scan_id: uuid.UUID,
    agent_type: Optional[str] = None
) -> List[AIAnalysis]:
    """Get all AI analyses for a scan"""
    query = db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan_id)

    if agent_type:
        query = query.filter(AIAnalysis.agent_type == agent_type)

    query = query.order_by(desc(AIAnalysis.created_at))
    return query.all()


def update_ai_analysis(
    db: Session,
    analysis_id: uuid.UUID,
    output_data: Optional[dict] = None,
    tokens_used: Optional[int] = None,
    processing_time_ms: Optional[int] = None
) -> Optional[AIAnalysis]:
    """Update AI analysis with results"""
    analysis = get_ai_analysis(db, analysis_id)
    if not analysis:
        return None

    if output_data:
        analysis.output_data = output_data
    if tokens_used:
        analysis.tokens_used = tokens_used
    if processing_time_ms:
        analysis.processing_time_ms = processing_time_ms

    db.commit()
    db.refresh(analysis)
    logger.info(f"Updated AI analysis {analysis_id}")
    return analysis


# ============= UTILITY FUNCTIONS =============

def get_scan_summary(db: Session, scan_id: uuid.UUID) -> Optional[dict]:
    """Get comprehensive scan summary including vulnerabilities and AI analyses"""
    scan = get_scan(db, scan_id)
    if not scan:
        return None

    vulnerabilities = get_vulnerabilities_by_scan(db, scan_id)
    severity_counts = count_vulnerabilities_by_severity(db, scan_id)
    ai_analyses = get_ai_analyses_by_scan(db, scan_id)

    return {
        'scan': scan,
        'total_vulnerabilities': len(vulnerabilities),
        'severity_counts': severity_counts,
        'ai_analyses': ai_analyses
    }


def get_recent_scans(db: Session, limit: int = 10) -> List[Scan]:
    """Get most recent scans"""
    return db.query(Scan).order_by(desc(Scan.started_at)).limit(limit).all()


def search_vulnerabilities(
    db: Session,
    cve_id: Optional[str] = None,
    package_name: Optional[str] = None,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    limit: int = 100
) -> List[Vulnerability]:
    """Search vulnerabilities with filters"""
    query = db.query(Vulnerability)

    if cve_id:
        query = query.filter(Vulnerability.cve_id.like(f"%{cve_id}%"))
    if package_name:
        query = query.filter(Vulnerability.package_name.like(f"%{package_name}%"))
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)

    query = query.order_by(desc(Vulnerability.cvss_score))
    return query.limit(limit).all()
