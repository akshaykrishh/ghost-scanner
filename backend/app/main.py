"""
Ghost Scanner - FastAPI Backend Application

Main application entry point for the Ghost Scanner API.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog
import uvicorn

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.api import api_router
from app.core.exceptions import GhostScannerException
from app.core.middleware import LoggingMiddleware

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Create FastAPI application
app = FastAPI(
    title="Ghost Scanner API",
    description="AI-Enhanced CI/CD Security Scanning Platform",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Security middleware
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# Custom logging middleware
app.add_middleware(LoggingMiddleware)

# Include API routes
app.include_router(api_router, prefix="/api/v1")

# Global exception handler
@app.exception_handler(GhostScannerException)
async def ghost_scanner_exception_handler(request, exc: GhostScannerException):
    logger.error("Ghost Scanner exception", error=str(exc), path=request.url.path)
    raise HTTPException(
        status_code=exc.status_code,
        detail=exc.detail
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "service": "ghost-scanner-api",
        "version": "1.0.0"
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with basic API information."""
    return {
        "message": "Ghost Scanner API",
        "version": "1.0.0",
        "docs": "/docs" if settings.DEBUG else "Documentation disabled in production"
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("Starting Ghost Scanner API", version="1.0.0")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    logger.info("Shutting down Ghost Scanner API")

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
