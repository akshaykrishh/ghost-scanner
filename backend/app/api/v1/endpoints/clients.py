"""
Ghost Scanner - Client Endpoints

API endpoints for managing clients.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.models.models import Client
from app.core.exceptions import NotFoundError
import structlog

router = APIRouter()
logger = structlog.get_logger()

class ClientResponse(BaseModel):
    id: int
    name: str
    github_org: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

@router.get("/", response_model=List[ClientResponse])
async def list_clients(db: Session = Depends(get_db)):
    """List all clients."""
    clients = db.query(Client).filter(Client.is_active == True).all()
    return clients

@router.get("/{client_id}", response_model=ClientResponse)
async def get_client(client_id: int, db: Session = Depends(get_db)):
    """Get client by ID."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise NotFoundError(f"Client with ID {client_id} not found")
    return client
