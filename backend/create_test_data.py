#!/usr/bin/env python3
"""
Ghost Scanner - Database Setup Script

Creates initial test data for development and testing.
"""

import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.models.models import Client, Repository
from app.core.config import settings

def create_test_data():
    """Create test client and repository."""
    
    # Create database connection
    engine = create_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Check if test client already exists
        existing_client = db.query(Client).filter(Client.name == "Test Client").first()
        if existing_client:
            print(f"Test client already exists with ID: {existing_client.id}")
            client_id = existing_client.id
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
            print(f"Created test client with ID: {client_id}")
        
        # Check if test repository already exists
        existing_repo = db.query(Repository).filter(Repository.name == "test-repo").first()
        if existing_repo:
            print(f"Test repository already exists with ID: {existing_repo.id}")
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
            print(f"Created test repository with ID: {test_repo.id}")
        
        print("✅ Test data created successfully!")
        print(f"Client ID: {client_id}")
        print(f"Repository ID: {test_repo.id if 'test_repo' in locals() else 'already exists'}")
        
    except Exception as e:
        print(f"❌ Error creating test data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_test_data()
