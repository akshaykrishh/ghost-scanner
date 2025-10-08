"""
Ghost Scanner - Scan Endpoints

API endpoints for managing security scans.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.models.models import Scan, Repository, Client, ScanResult
from app.core.exceptions import NotFoundError, ValidationError
from app.services.scan_service import ScanService
from app.services.ai_service import AIService
import structlog

router = APIRouter()
logger = structlog.get_logger()

# Pydantic models for API
class ScanCreate(BaseModel):
    scan_type: str
    commit_sha: str
    branch: str
    pull_request_number: Optional[int] = None
    metadata: Optional[dict] = None
    # New simplified identification
    repo_full_name: Optional[str] = None
    repository_id: Optional[int] = None

class ScanResponse(BaseModel):
    id: int
    repository_id: Optional[int]
    repo_full_name: Optional[str]
    scan_type: str
    commit_sha: str
    branch: str
    pull_request_number: Optional[int]
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]
    metadata_json: Optional[dict]
    
    class Config:
        from_attributes = True

class ScanResultResponse(BaseModel):
    scan_id: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    scan_duration_seconds: Optional[float]
    files_scanned: int
    
    class Config:
        from_attributes = True

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db)
):
    """Create a new security scan."""
    logger.info("Creating new scan", scan_data=scan_data.dict())

    client_id = None
    repository_id = None
    repo_full_name = None

    # Prefer repository_id if provided and valid
    if scan_data.repository_id:
        repository = db.query(Repository).filter(Repository.id == scan_data.repository_id).first()
        if not repository:
            raise NotFoundError(f"Repository with ID {scan_data.repository_id} not found")
        client_id = repository.client_id
        repository_id = repository.id
        repo_full_name = repository.full_name
    elif scan_data.repo_full_name:
        # Simplified flow: no repository lookup required
        repo_full_name = scan_data.repo_full_name
    else:
        raise ValidationError("Either repository_id or repo_full_name must be provided")

    # Create scan
    scan = Scan(
        client_id=client_id,
        repository_id=repository_id,
        repo_full_name=repo_full_name,
        scan_type=scan_data.scan_type,
        commit_sha=scan_data.commit_sha,
        branch=scan_data.branch,
        pull_request_number=scan_data.pull_request_number,
        metadata_json=scan_data.metadata
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    logger.info("Scan created successfully", scan_id=scan.id)
    return scan

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with ID {scan_id} not found")
    
    return scan

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    repository_id: Optional[int] = None,
    repo_full_name: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List scans with optional filtering."""
    query = db.query(Scan)
    
    if repository_id:
        query = query.filter(Scan.repository_id == repository_id)
    if repo_full_name:
        query = query.filter(Scan.repo_full_name == repo_full_name)
    
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.offset(offset).limit(limit).all()
    return scans

@router.get("/{scan_id}/results", response_model=ScanResultResponse)
async def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get scan results summary."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with ID {scan_id} not found")
    
    result = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not result:
        raise NotFoundError(f"Scan results for scan ID {scan_id} not found")
    
    return result

@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Start a scan execution."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with ID {scan_id} not found")
    
    if scan.status != "pending":
        raise ValidationError(f"Scan {scan_id} is not in pending status")
    
    # Update scan status
    scan.status = "running"
    db.commit()
    
    # Start scan in background (this would be handled by Celery in production)
    logger.info("Starting scan execution", scan_id=scan_id)
    
    return {"message": "Scan started successfully", "scan_id": scan_id}

@router.post("/{scan_id}/complete")
async def complete_scan(
    scan_id: int,
    findings_data: dict,
    db: Session = Depends(get_db)
):
    """Complete a scan with findings data."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with ID {scan_id} not found")
    
    # Update scan status
    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    db.commit()
    
    # Process findings and run AI analysis
    findings = findings_data.get("findings", [])
    logger.info("Processing scan findings", scan_id=scan_id, findings_count=len(findings))
    
    # Initialize AI service
    ai_service = AIService()
    
    # Store findings and run AI analysis
    for finding_data in findings:
        try:
            # Run AI analysis
            ai_analysis = ai_service.analyze_finding(finding_data)
            
            # Create Finding record
            from app.models.models import Finding
            finding = Finding(
                repository_id=scan.repository_id,
                repo_full_name=scan.repo_full_name,
                scan_id=scan_id,
                rule_id=finding_data.get("rule_id", "unknown"),
                rule_name=finding_data.get("rule_name", "Unknown Rule"),
                severity=finding_data.get("severity", "medium"),
                confidence=finding_data.get("confidence"),
                file_path=finding_data.get("file_path", ""),
                line_number=finding_data.get("line_number"),
                column_number=finding_data.get("column_number"),
                secret_value=finding_data.get("secret_value"),
                description=finding_data.get("description"),
                raw_data=finding_data,
                # AI Analysis results
                ai_risk_score=ai_analysis.get("ai_risk_score"),
                ai_confidence=ai_analysis.get("ai_confidence"),
                ai_explanation=ai_analysis.get("ai_explanation"),
                ai_remediation=ai_analysis.get("ai_remediation")
            )
            
            db.add(finding)
            
        except Exception as e:
            logger.error("Failed to process finding", error=str(e), finding_data=finding_data)
            # Create finding without AI analysis as fallback
            from app.models.models import Finding
            finding = Finding(
                repository_id=scan.repository_id,
                repo_full_name=scan.repo_full_name,
                scan_id=scan_id,
                rule_id=finding_data.get("rule_id", "unknown"),
                rule_name=finding_data.get("rule_name", "Unknown Rule"),
                severity=finding_data.get("severity", "medium"),
                confidence=finding_data.get("confidence"),
                file_path=finding_data.get("file_path", ""),
                line_number=finding_data.get("line_number"),
                column_number=finding_data.get("column_number"),
                secret_value=finding_data.get("secret_value"),
                description=finding_data.get("description"),
                raw_data=finding_data,
                # AI Analysis failed
                ai_risk_score="unknown",
                ai_confidence=0.0,
                ai_explanation="AI analysis failed",
                ai_remediation="Manual review recommended"
            )
            db.add(finding)
    
    # Commit all findings
    db.commit()
    
    logger.info("Scan completed successfully", scan_id=scan_id, findings_stored=len(findings))
    return {"message": "Scan completed successfully", "scan_id": scan_id}
