# 🚨 Test Security Flaws Branch

This branch contains **intentionally vulnerable code and hardcoded secrets** for testing Ghost Scanner's security detection capabilities.

## ⚠️ WARNING

**DO NOT USE THIS CODE IN PRODUCTION!**

This branch is created solely for testing purposes to verify that Ghost Scanner can detect:
- Hardcoded API keys and secrets
- Database credentials
- JWT secrets and encryption keys
- OAuth credentials
- Webhook URLs with tokens
- Vulnerable dependencies

## 📁 Test Files

- `test-secrets.py` - Python file with hardcoded secrets
- `test-config.js` - JavaScript configuration with API keys
- `test-dependencies.json` - Package.json with vulnerable dependencies
- `test-env-file.env` - Environment file with hardcoded credentials
- `test-yaml-config.yml` - YAML configuration with secrets

## 🎯 Expected Findings

Ghost Scanner should detect:
- **Secrets**: AWS keys, GitHub tokens, database passwords, JWT secrets
- **Dependencies**: Vulnerable versions of lodash, express, jquery, etc.
- **AI Analysis**: Risk assessment and remediation suggestions

## 🧪 Testing Process

1. Create PR from this branch to main
2. GitHub Action should trigger security scan
3. AI analysis should provide risk scores and remediation
4. PR comment should show detailed findings

## 🔒 Security Note

All secrets in this branch are **fake/test values** and should never be used in real applications.
