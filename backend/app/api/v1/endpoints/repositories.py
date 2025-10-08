"""
Ghost Scanner - Repository Endpoints

API endpoints for managing repositories.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.models.models import Repository
from app.core.exceptions import NotFoundError
import structlog

router = APIRouter()
logger = structlog.get_logger()

class RepositoryResponse(BaseModel):
    id: int
    client_id: int
    name: str
    full_name: str
    github_repo_id: Optional[int]
    default_branch: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

@router.get("/", response_model=List[RepositoryResponse])
async def list_repositories(
    client_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """List repositories with optional client filtering."""
    query = db.query(Repository).filter(Repository.is_active == True)
    
    if client_id:
        query = query.filter(Repository.client_id == client_id)
    
    repositories = query.all()
    return repositories

@router.get("/{repository_id}", response_model=RepositoryResponse)
async def get_repository(repository_id: int, db: Session = Depends(get_db)):
    """Get repository by ID."""
    repository = db.query(Repository).filter(Repository.id == repository_id).first()
    if not repository:
        raise NotFoundError(f"Repository with ID {repository_id} not found")
    return repository
