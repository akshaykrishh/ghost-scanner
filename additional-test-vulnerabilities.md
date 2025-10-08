# Additional Test Security Issues for CI/CD Testing

This file contains additional security vulnerabilities to test the Ghost Scanner CI/CD integration.

## Hardcoded Credentials
```python
# More test credentials (INTENTIONAL FOR TESTING)
DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"
REDIS_PASSWORD = "redis_secret_456"
STRIPE_SECRET_KEY = "sk_test_51234567890abcdef"
```

## API Keys
```javascript
// JavaScript test file with secrets
const config = {
    apiKey: "AIzaSyBvOkBwq90lBdIq_hq_EAqyU1M1Pc8hT8",
    secretKey: "sk_live_51234567890abcdef1234567890abcdef",
    webhookSecret: "whsec_1234567890abcdef1234567890abcdef"
};
```

## Environment Variables
```bash
# .env.test file
SECRET_KEY=super_secret_key_for_testing_123
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## Database Connection Strings
```yaml
# docker-compose.test.yml
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: "postgres_password_123"
      POSTGRES_USER: "admin"
```

This should trigger multiple security findings in the Ghost Scanner CI/CD test.
