"""
Ghost Scanner - Database Models

SQLAlchemy models for the Ghost Scanner application.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from enum import Enum

from app.core.database import Base

class ScanType(str, Enum):
    """Scan type enumeration."""
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"

class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RiskScore(str, Enum):
    """AI risk score enumeration."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Client(Base):
    """Client organization model."""
    __tablename__ = "clients"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    api_key = Column(String(255), unique=True, nullable=False, index=True)
    github_org = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    repositories = relationship("Repository", back_populates="client")
    scans = relationship("Scan", back_populates="client")

class Repository(Base):
    """Repository model."""
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    name = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False, index=True)
    github_repo_id = Column(Integer, unique=True, nullable=True)
    default_branch = Column(String(100), default="main")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    client = relationship("Client", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")

class Scan(Base):
    """Scan execution model."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)
    commit_sha = Column(String(40), nullable=False)
    branch = Column(String(255), nullable=False)
    pull_request_number = Column(Integer, nullable=True)
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)  # Additional scan metadata
    
    # Relationships
    client = relationship("Client", back_populates="scans")
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    """Security finding model."""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Finding details
    rule_id = Column(String(255), nullable=False)
    rule_name = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=True)
    
    # File location
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    
    # Finding content
    secret_value = Column(String(500), nullable=True)  # For secrets findings
    description = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)  # Original scanner output
    
    # AI Analysis
    ai_risk_score = Column(String(50), nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    # Status tracking
    is_false_positive = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    repository = relationship("Repository", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")

class ScanResult(Base):
    """Scan result summary model."""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, unique=True)
    
    # Summary statistics
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # AI Analysis summary
    high_risk_count = Column(Integer, default=0)
    medium_risk_count = Column(Integer, default=0)
    low_risk_count = Column(Integer, default=0)
    
    # Performance metrics
    scan_duration_seconds = Column(Float, nullable=True)
    files_scanned = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan")
