"""
Ghost Scanner - Core Configuration

Application settings and configuration management.
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os
from pathlib import Path

class Settings(BaseSettings):
    """Application settings."""
    
    # Application
    APP_NAME: str = "Ghost Scanner"
    DEBUG: bool = False
    VERSION: str = "1.0.0"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALLOWED_HOSTS: List[str] = ["*"]
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "postgresql://ghost_scanner:password@localhost:5432/ghost_scanner"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # AI/ML
    OPENAI_API_KEY: Optional[str] = None
    AI_MODEL_NAME: str = "gpt-4"
    AI_MAX_TOKENS: int = 1000
    
    # Scanning Engines
    GITLEAKS_BINARY_PATH: str = "/usr/local/bin/gitleaks"
    DEPENDENCY_CHECK_PATH: str = "/usr/local/bin/dependency-check"
    
    # GitHub Integration
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_PRIVATE_KEY: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    
    # Monitoring
    LOG_LEVEL: str = "INFO"
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    
    # Data Retention
    FINDINGS_RETENTION_DAYS: int = 90
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
settings = Settings()

# Ensure required directories exist
def ensure_directories():
    """Ensure required directories exist."""
    directories = [
        "logs",
        "data",
        "models",
        "temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

# Initialize directories on import
ensure_directories()
