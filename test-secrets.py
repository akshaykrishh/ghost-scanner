#!/usr/bin/env python3
"""
Test file with various hardcoded secrets for security scanning.
This file is intentionally created to test Ghost Scanner's secrets detection.
"""

# Hardcoded API keys
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database credentials
DATABASE_PASSWORD = "super_secret_password_123"
DB_CONNECTION_STRING = "postgresql://user:mysecretpass@localhost:5432/mydb"

# API tokens
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
SLACK_TOKEN = "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"

# JWT secrets
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-hardcoded"
ENCRYPTION_KEY = "this-is-a-very-long-encryption-key-for-testing-purposes"

# OAuth credentials
CLIENT_ID = "1234567890.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-abcdefghijklmnopqrstuvwxyz"

def connect_to_database():
    """Simulate database connection with hardcoded credentials."""
    password = "admin123"  # Another hardcoded password
    return f"Connected with password: {password}"

def send_notification():
    """Simulate sending notification with hardcoded token."""
    webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    api_key = "sk-1234567890abcdef1234567890abcdef12345678"
    return f"Sent notification using: {api_key}"

if __name__ == "__main__":
    print("This is a test file with intentional security flaws")
    print("DO NOT USE IN PRODUCTION!")
