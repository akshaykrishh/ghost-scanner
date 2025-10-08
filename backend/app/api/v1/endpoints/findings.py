"""
Ghost Scanner - Findings Endpoints

API endpoints for managing security findings.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.models.models import Finding
from app.core.exceptions import NotFoundError
import structlog

router = APIRouter()
logger = structlog.get_logger()

class FindingResponse(BaseModel):
    id: int
    repository_id: int
    scan_id: int
    rule_id: str
    rule_name: str
    severity: str
    confidence: Optional[float]
    file_path: str
    line_number: Optional[int]
    column_number: Optional[int]
    secret_value: Optional[str]
    description: Optional[str]
    ai_risk_score: Optional[str]
    ai_confidence: Optional[float]
    ai_explanation: Optional[str]
    ai_remediation: Optional[str]
    is_false_positive: bool
    is_resolved: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    repository_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,
    ai_risk_score: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List findings with optional filtering."""
    query = db.query(Finding)
    
    if repository_id:
        query = query.filter(Finding.repository_id == repository_id)
    
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    
    if severity:
        query = query.filter(Finding.severity == severity)
    
    if ai_risk_score:
        query = query.filter(Finding.ai_risk_score == ai_risk_score)
    
    findings = query.offset(offset).limit(limit).all()
    return findings

@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get finding by ID."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError(f"Finding with ID {finding_id} not found")
    return finding

@router.post("/{finding_id}/mark-false-positive")
async def mark_false_positive(finding_id: int, db: Session = Depends(get_db)):
    """Mark a finding as false positive."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError(f"Finding with ID {finding_id} not found")
    
    finding.is_false_positive = True
    db.commit()
    
    logger.info("Finding marked as false positive", finding_id=finding_id)
    return {"message": "Finding marked as false positive", "finding_id": finding_id}

@router.post("/{finding_id}/resolve")
async def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    """Mark a finding as resolved."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError(f"Finding with ID {finding_id} not found")
    
    finding.is_resolved = True
    finding.resolved_at = datetime.utcnow()
    db.commit()
    
    logger.info("Finding marked as resolved", finding_id=finding_id)
    return {"message": "Finding marked as resolved", "finding_id": finding_id}
