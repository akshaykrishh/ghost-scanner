"""
Ghost Scanner - Health Check Endpoints

Health check and monitoring endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import get_db
from app.core.config import settings
from app.models.models import Client, Repository
import redis
import structlog

router = APIRouter()
logger = structlog.get_logger()

@router.get("/")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "ghost-scanner-api",
        "version": settings.VERSION
    }

@router.get("/detailed")
async def detailed_health_check(db: Session = Depends(get_db)):
    """Detailed health check including database connectivity."""
    health_status = {
        "status": "healthy",
        "service": "ghost-scanner-api",
        "version": settings.VERSION,
        "checks": {}
    }
    
    # Database check
    try:
        db.execute(text("SELECT 1"))
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        health_status["checks"]["database"] = "unhealthy"
        health_status["status"] = "degraded"
    
    # Redis check
    try:
        redis_client = redis.from_url(settings.REDIS_URL)
        redis_client.ping()
        health_status["checks"]["redis"] = "healthy"
    except Exception as e:
        logger.error("Redis health check failed", error=str(e))
        health_status["checks"]["redis"] = "unhealthy"
        health_status["status"] = "degraded"
    
    return health_status

@router.get("/ready")
async def readiness_check():
    """Readiness check for Kubernetes."""
    return {"status": "ready"}

@router.post("/setup-test-data")
async def setup_test_data(db: Session = Depends(get_db)):
    """Create test client and repository for development."""
    try:
        # Check if test client already exists
        existing_client = db.query(Client).filter(Client.name == "Test Client").first()
        if existing_client:
            client_id = existing_client.id
            logger.info("Test client already exists", client_id=client_id)
        else:
            # Create test client
            test_client = Client(
                name="Test Client",
                api_key="test-api-key-12345",
                github_org="test-org",
                is_active=True
            )
            db.add(test_client)
            db.commit()
            db.refresh(test_client)
            client_id = test_client.id
            logger.info("Created test client", client_id=client_id)
        
        # Check if test repository already exists
        existing_repo = db.query(Repository).filter(Repository.name == "test-repo").first()
        if existing_repo:
            repo_id = existing_repo.id
            logger.info("Test repository already exists", repo_id=repo_id)
        else:
            # Create test repository
            test_repo = Repository(
                client_id=client_id,
                name="test-repo",
                full_name="test-org/test-repo",
                github_repo_id=12345,
                default_branch="main",
                is_active=True
            )
            db.add(test_repo)
            db.commit()
            db.refresh(test_repo)
            repo_id = test_repo.id
            logger.info("Created test repository", repo_id=repo_id)
        
        return {
            "status": "success",
            "message": "Test data created successfully",
            "client_id": client_id,
            "repository_id": repo_id
        }
        
    except Exception as e:
        logger.error("Failed to create test data", error=str(e))
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create test data: {str(e)}")

@router.get("/live")
async def liveness_check():
    """Liveness check for Kubernetes."""
    return {"status": "alive"}
