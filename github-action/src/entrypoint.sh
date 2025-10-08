#!/bin/bash

# Ghost Scanner GitHub Action
# This script runs security scans and sends results to the Ghost Scanner API

set -e

# Configuration
API_BASE_URL="${GHOST_SCANNER_API_URL:-https://api.ghostscanner.com}"
API_KEY="${INPUT_API_KEY}"
SCAN_TYPES="${INPUT_SCAN_TYPES:-secrets,dependencies}"
FAIL_ON_HIGH_RISK="${INPUT_FAIL_ON_HIGH_RISK:-false}"
COMMENT_ON_PR="${INPUT_COMMENT_ON_PR:-true}"
INCLUDE_AI_ANALYSIS="${INPUT_INCLUDE_AI_ANALYSIS:-true}"
GITHUB_TOKEN="${GITHUB_TOKEN}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run secrets scan
run_secrets_scan() {
    # Check if gitleaks is available
    if command -v gitleaks &> /dev/null; then
        log_info "Using Gitleaks for secrets scanning"
        gitleaks detect --source . --format json --no-git || echo "[]"
    else
        log_warn "Gitleaks not available, using pattern-based scanning"
        # Simple pattern-based secrets detection
        python3 -c "
import json
import re
import os
import sys

try:
    findings = []
    patterns = {
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"\\']?([a-zA-Z0-9]{20,})[\"\\']?',
        'aws_key': r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*[\"\\']?(AKIA[0-9A-Z]{16})[\"\\']?',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\"\\']?([^\"\\']{8,})[\"\\']?'
    }

    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(('.py', '.js', '.ts', '.json', '.env', '.yml', '.yaml')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern_name, pattern in patterns.items():
                            for match in re.finditer(pattern, content):
                                findings.append({
                                    'rule_id': f'pattern_{pattern_name}',
                                    'rule_name': f'Potential {pattern_name.replace(\"_\", \" \").title()}',
                                    'severity': 'medium',
                                    'file_path': file_path,
                                    'line_number': content[:match.start()].count('\n') + 1,
                                    'description': f'Potential {pattern_name} detected'
                                })
                except:
                    pass

    print(json.dumps(findings))
except Exception as e:
    print('[]')
"
    fi
}

# Function to run dependency scan
run_dependency_scan() {
    findings="[]"
    
    # Check for package.json
    if [ -f "package.json" ]; then
        log_info "Scanning package.json for vulnerabilities"
        # Simple vulnerable package detection
        python3 -c "
import json
import sys

try:
    with open('package.json', 'r') as f:
        data = json.load(f)
    
    dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
    vulnerable_packages = ['lodash', 'moment', 'jquery']
    
    findings = []
    for package in dependencies:
        if package in vulnerable_packages:
            findings.append({
                'rule_id': f'vulnerable_{package}',
                'rule_name': f'Vulnerable Package: {package}',
                'severity': 'medium',
                'file_path': 'package.json',
                'description': f'Package {package} may have known vulnerabilities'
            })
    
    print(json.dumps(findings))
except Exception as e:
    print('[]')
"
    fi
    
    # Check for requirements.txt
    if [ -f "requirements.txt" ]; then
        log_info "Scanning requirements.txt for vulnerabilities"
        python3 -c "
import json
import sys

try:
    with open('requirements.txt', 'r') as f:
        lines = f.readlines()
    
    vulnerable_packages = ['django', 'flask', 'requests']
    findings = []
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if line and not line.startswith('#'):
            package = line.split('==')[0].split('>=')[0].split('<=')[0]
            if package in vulnerable_packages:
                findings.append({
                    'rule_id': f'vulnerable_{package}',
                    'rule_name': f'Vulnerable Package: {package}',
                    'severity': 'medium',
                    'file_path': 'requirements.txt',
                    'line_number': line_num,
                    'description': f'Package {package} may have known vulnerabilities'
                })
    
    print(json.dumps(findings))
except Exception as e:
    print('[]')
"
    fi
    
    echo "$findings"
}

# Function to post PR comment
post_pr_comment() {
    local results_response="$1"
    
    # Create comment body
    local comment_body="## 🔍 Ghost Scanner Security Analysis

### Summary
- **Total Findings**: $(echo "$results_response" | jq -r '.total_findings // 0')
- **Critical**: $(echo "$results_response" | jq -r '.critical_count // 0')
- **High**: $(echo "$results_response" | jq -r '.high_count // 0')
- **Medium**: $(echo "$results_response" | jq -r '.medium_count // 0')
- **Low**: $(echo "$results_response" | jq -r '.low_count // 0')

### AI Risk Assessment
- **High Risk**: $(echo "$results_response" | jq -r '.high_risk_count // 0')
- **Medium Risk**: $(echo "$results_response" | jq -r '.medium_risk_count // 0')
- **Low Risk**: $(echo "$results_response" | jq -r '.low_risk_count // 0')

### Scan Details
- **Files Scanned**: $(echo "$results_response" | jq -r '.files_scanned // 0')
- **Scan Duration**: $(echo "$results_response" | jq -r '.scan_duration_seconds // 0') seconds

---
*Powered by Ghost Scanner AI*"

    # Post comment to PR
    curl -s -X POST "https://api.github.com/repos/$REPO_NAME/issues/$PR_NUMBER/comments" \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        -d "{\"body\": $(echo "$comment_body" | jq -R -s .)}"
    
    log_info "PR comment posted successfully"
}

# Check required inputs
if [ -z "$API_KEY" ]; then
    log_error "API key is required. Please set GHOST_SCANNER_API_KEY secret."
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    log_warn "GitHub token not provided. PR comments will be disabled."
    COMMENT_ON_PR="false"
fi

# Get repository information
REPO_NAME="${GITHUB_REPOSITORY}"
COMMIT_SHA="${GITHUB_SHA}"
BRANCH="${GITHUB_REF#refs/heads/}"
PR_NUMBER="${GITHUB_EVENT_NUMBER:-}"

log_info "Starting Ghost Scanner analysis"
log_info "Repository: $REPO_NAME"
log_info "Commit: $COMMIT_SHA"
log_info "Branch: $BRANCH"
log_info "Scan types: $SCAN_TYPES"

# Create scan session
log_info "Creating scan session..."

# Build JSON payload dynamically
JSON_PAYLOAD="{
    \"repository_id\": 1,
    \"scan_type\": \"secrets\",
    \"commit_sha\": \"$COMMIT_SHA\",
    \"branch\": \"$BRANCH\""

# Add pull_request_number only if it's not empty
if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
    JSON_PAYLOAD="$JSON_PAYLOAD,
    \"pull_request_number\": $PR_NUMBER"
fi

JSON_PAYLOAD="$JSON_PAYLOAD
}"

log_info "Sending JSON payload: $JSON_PAYLOAD"

SCAN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/api/v1/scans/" \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD")

SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.id')

if [ "$SCAN_ID" = "null" ] || [ -z "$SCAN_ID" ]; then
    log_error "Failed to create scan session"
    log_error "Response: $SCAN_RESPONSE"
    exit 1
fi

log_info "Scan session created: $SCAN_ID"

# Run scans based on scan types
FINDINGS="[]"

if [[ "$SCAN_TYPES" == *"secrets"* ]]; then
    log_info "Running secrets scan..."
    SECRETS_FINDINGS=$(run_secrets_scan)
    log_info "Secrets scan output: $SECRETS_FINDINGS"
    FINDINGS=$(echo "$FINDINGS $SECRETS_FINDINGS" | jq -s 'add')
fi

if [[ "$SCAN_TYPES" == *"dependencies"* ]]; then
    log_info "Running dependency scan..."
    DEPENDENCY_FINDINGS=$(run_dependency_scan)
    log_info "Dependency scan output: $DEPENDENCY_FINDINGS"
    FINDINGS=$(echo "$FINDINGS $DEPENDENCY_FINDINGS" | jq -s 'add')
fi

# Send findings to API
log_info "Sending findings to Ghost Scanner API..."
FINDINGS_COUNT=$(echo "$FINDINGS" | jq 'length')

if [ "$FINDINGS_COUNT" -gt 0 ]; then
    log_warn "Found $FINDINGS_COUNT security findings"
    
    # Complete the scan with findings
    curl -s -X POST "$API_BASE_URL/api/v1/scans/$SCAN_ID/complete" \
        -H "Content-Type: application/json" \
        -d "{
            \"findings\": $FINDINGS
        }"
    
    # Get scan results
    log_info "Getting scan results..."
    RESULTS_RESPONSE=$(curl -s -X GET "$API_BASE_URL/api/v1/scans/$SCAN_ID/results")
    
    # Post PR comment if enabled
    if [ "$COMMENT_ON_PR" = "true" ] && [ -n "$PR_NUMBER" ]; then
        log_info "Posting PR comment..."
        post_pr_comment "$RESULTS_RESPONSE"
    fi
    
    # Check if we should fail on high risk findings
    if [ "$FAIL_ON_HIGH_RISK" = "true" ]; then
        HIGH_RISK_COUNT=$(echo "$RESULTS_RESPONSE" | jq -r '.high_risk_count // 0')
        if [ "$HIGH_RISK_COUNT" -gt 0 ]; then
            log_error "Found $HIGH_RISK_COUNT high-risk findings. Failing build."
            exit 1
        fi
    fi
    
else
    log_info "No security findings detected"
fi

log_info "Ghost Scanner analysis completed successfully"
