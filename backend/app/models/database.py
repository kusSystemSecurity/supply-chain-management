"""Database models"""
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, JSON, ForeignKey, Enum,
    TypeDecorator, CHAR
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum


Base = declarative_base()


class UUIDType(TypeDecorator):
    """Platform-independent UUID type.

    Uses PostgreSQL's UUID type, otherwise uses
    String(36) representing the string form of the UUID.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(value))
            else:
                return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return value


class ScanType(str, enum.Enum):
    """Scan type enumeration"""
    GIT_REPO = "git_repo"
    CONTAINER = "container"
    VM = "vm"
    SBOM = "sbom"
    K8S = "k8s"


class ScanStatus(str, enum.Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    """Scan table"""
    __tablename__ = "scans"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    scan_type = Column(String(50), nullable=False)
    target = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, default=ScanStatus.PENDING.value)
    options = Column(JSON, nullable=True)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    result_json = Column(JSON, nullable=True)
    error_message = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    ai_analyses = relationship("AIAnalysis", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    """Vulnerability table"""
    __tablename__ = "vulnerabilities"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUIDType, ForeignKey("scans.id"), nullable=False)
    cve_id = Column(String(20), nullable=False, index=True)
    package_name = Column(String(200), nullable=True)
    package_version = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_predicted = Column(Boolean, default=False)
    cve_details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")


class AgentType(str, enum.Enum):
    """AI Agent type enumeration"""
    PRIORITIZATION = "prioritization"
    SUPPLY_CHAIN = "supply_chain"
    REMEDIATION = "remediation"


class AIAnalysis(Base):
    """AI analysis table"""
    __tablename__ = "ai_analyses"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUIDType, ForeignKey("scans.id"), nullable=False)
    agent_type = Column(String(50), nullable=False)
    input_data = Column(JSON, nullable=True)
    output_data = Column(JSON, nullable=True)
    tokens_used = Column(Integer, nullable=True)
    processing_time_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="ai_analyses")
