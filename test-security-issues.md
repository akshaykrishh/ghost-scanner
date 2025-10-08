# Test Repository for Ghost Scanner CI/CD Testing

This repository contains intentional security vulnerabilities for testing Ghost Scanner.

## Files with Security Issues

### 1. Hardcoded Secrets
```python
# config.py - Contains hardcoded API keys (INTENTIONAL FOR TESTING)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
```

### 2. Vulnerable Dependencies
The package.json contains outdated packages with known CVEs for testing dependency scanning.

### 3. Environment Variables
```bash
# .env file (INTENTIONAL FOR TESTING)
SECRET_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
```

## Testing Instructions

1. Create a PR to trigger the Ghost Scanner workflow
2. Check the GitHub Actions logs for scan results
3. Verify findings appear in the Ghost Scanner dashboard
4. Test the AI-powered risk prioritization

## Expected Findings

- Hardcoded API keys (High severity)
- Database credentials (Critical severity)  
- Outdated dependencies with CVEs (Medium severity)
- JWT tokens in code (High severity)
