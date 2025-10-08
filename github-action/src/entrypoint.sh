#!/bin/bash

# Ghost Scanner GitHub Action
# This script runs security scans and sends results to the Ghost Scanner API

set -e

# Configuration
API_BASE_URL="${GHOST_SCANNER_API_URL:-https://api.ghostscanner.com}"
API_KEY="${INPUT_API_KEY}"
REPOSITORY_ID="${INPUT_REPOSITORY_ID}"
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

# Resolve script directory (where this action's scripts live)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Ensure gitleaks is available; attempt install if missing
ensure_gitleaks() {
    if command -v gitleaks &> /dev/null; then
        return 0
    fi

    log_warn "Gitleaks not found. Attempting installation..."

    # Try direct binary download (more reliable than install script)
    if command -v curl &> /dev/null; then
        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="x64" ;;
            arm64|aarch64) ARCH="arm64" ;;
            *) log_warn "Unsupported architecture: $ARCH"; return 1 ;;
        esac
        
        # Detect OS
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        case $OS in
            linux) OS="linux" ;;
            darwin) OS="darwin" ;;
            *) log_warn "Unsupported OS: $OS"; return 1 ;;
        esac
        
        # Get latest version
        VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name' 2>/dev/null || echo "v8.18.0")
        VERSION=${VERSION#v}  # Remove 'v' prefix
        
        # Download and install
        DOWNLOAD_URL="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_${OS}_${ARCH}.tar.gz"
        log_info "Attempting to download Gitleaks from $DOWNLOAD_URL"
        
        if curl -sSfL "$DOWNLOAD_URL" | tar -xz -C /tmp; then
            # Find the extracted binary even if nested in a folder
            BIN_PATH=$(find /tmp -maxdepth 3 -type f -name gitleaks | head -n1)
            if [ -n "$BIN_PATH" ]; then
                if sudo mv "$BIN_PATH" /usr/local/bin/ && sudo chmod +x /usr/local/bin/gitleaks; then
                    :
                fi
            else
                log_warn "Gitleaks binary not found after extraction"
            fi
        else
            log_warn "Failed to download/extract Gitleaks archive"
        fi

        if command -v gitleaks &> /dev/null; then
            if command -v gitleaks &> /dev/null; then
                log_info "Gitleaks installed successfully (v${VERSION})"
                return 0
            fi
        fi
        
        # Fallback: try installing to ~/bin if sudo is unavailable
        if curl -sSfL "$DOWNLOAD_URL" | tar -xz -C /tmp && \
           mkdir -p "$HOME/bin"; then
            BIN_PATH=$(find /tmp -maxdepth 3 -type f -name gitleaks | head -n1)
            if [ -n "$BIN_PATH" ]; then
                mv "$BIN_PATH" "$HOME/bin/" && chmod +x "$HOME/bin/gitleaks"
            else
                log_warn "Gitleaks binary not found after extraction (fallback)"
            fi
            export PATH="$HOME/bin:$PATH"
            if command -v gitleaks &> /dev/null; then
                log_info "Gitleaks installed to $HOME/bin (v${VERSION})"
                return 0
            fi
        fi
    fi

    log_warn "Unable to install Gitleaks automatically"
    return 1
}

# Function to run secrets scan
# Function to run secrets scan (union: Gitleaks + pattern-based)
run_secrets_scan() {
    # Run Gitleaks if available
    local gitleaks_output gitleaks_wt gitleaks_range base_ref
    if command -v gitleaks >/dev/null 2>&1; then
        # Working tree scan (no git history)
        gitleaks_wt=$(gitleaks detect --source "$SCAN_SOURCE_PATH" --format json --no-git 2>/dev/null || echo "[]")
        if ! echo "$gitleaks_wt" | jq . >/dev/null 2>&1; then gitleaks_wt="[]"; fi

        # Commit-range scan for PRs (base..HEAD)
        base_ref=${GITHUB_BASE_REF:-}
        if [ -n "$base_ref" ]; then
            git -C "$SCAN_SOURCE_PATH" fetch origin "$base_ref" --depth=1 >/dev/null 2>&1 || true
            gitleaks_range=$(gitleaks detect --source "$SCAN_SOURCE_PATH" --format json --log-opts "origin/$base_ref..HEAD" 2>/dev/null || echo "[]")
            if ! echo "$gitleaks_range" | jq . >/dev/null 2>&1; then gitleaks_range="[]"; fi
        else
            gitleaks_range="[]"
        fi

        # Merge both gitleaks outputs
        gitleaks_output=$(echo "$gitleaks_wt" "$gitleaks_range" | jq -s 'add' 2>/dev/null || echo "[]")

        # Debug logs (stderr)
        {
            echo "[INFO] Gitleaks executed"
            echo "[INFO] Gitleaks working-tree count: $(echo "$gitleaks_wt" | jq 'length' 2>/dev/null || echo 0)"
            echo "[INFO] Gitleaks commit-range base=$base_ref count: $(echo "$gitleaks_range" | jq 'length' 2>/dev/null || echo 0)"
            echo "[INFO] Gitleaks merged count: $(echo "$gitleaks_output" | jq 'length' 2>/dev/null || echo 0)"
            echo "[INFO] Gitleaks sample (up to 3):"
            echo "$gitleaks_output" | jq '.[0:3]' 2>/dev/null || echo "[]"
        } 1>&2
    else
        gitleaks_output="[]"
        { echo "[INFO] Gitleaks not available; skipping"; } 1>&2
    fi

    # Pattern-based secrets detection via external script to avoid shell escaping issues
    local pattern_output
    pattern_output=$(python3 "$SCRIPT_DIR/pattern_scan.py" "$SCAN_SOURCE_PATH" || echo "[]")

    # Debug: log pattern-based run and finding count to stderr (do not contaminate JSON)
    {
        echo "[INFO] Pattern-based scan executed"
        echo "[INFO] Pattern findings count: $(echo "$pattern_output" | jq 'length' 2>/dev/null || echo 0)"
        echo "[INFO] Pattern sample (up to 3):"
        echo "$pattern_output" | jq '.[0:3]' 2>/dev/null || echo "[]"
    } 1>&2

    # Merge outputs
    local merged
    merged=$(echo "$gitleaks_output" "$pattern_output" | jq -s 'add' 2>/dev/null || echo "[]")
    echo "$merged"
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
    local ai_findings_response="$1"
    local results_response="$2"

    # Choose findings JSON: prefer AI array if valid, else results.findings, else []
    local findings_json
    if echo "$ai_findings_response" | jq -e 'type=="array"' >/dev/null 2>&1; then
        findings_json="$ai_findings_response"
    else
        findings_json=$(echo "$results_response" | jq -c '.findings // []' 2>/dev/null || echo "[]")
    fi

    # Precompute counts with fallbacks
    local total critical high medium low
    total=$(echo "$findings_json"   | jq 'length'                                       2>/dev/null || echo 0)
    critical=$(echo "$findings_json"| jq '[.[] | select(.severity=="critical")] | length' 2>/dev/null || echo 0)
    high=$(echo "$findings_json"    | jq '[.[] | select(.severity=="high")] | length'     2>/dev/null || echo 0)
    medium=$(echo "$findings_json"  | jq '[.[] | select(.severity=="medium")] | length'   2>/dev/null || echo 0)
    low=$(echo "$findings_json"     | jq '[.[] | select(.severity=="low")] | length'      2>/dev/null || echo 0)

    # Optional AI risk counts (ignore if absent)
    local ai_high ai_medium ai_low
    ai_high=$(echo "$findings_json"  | jq '[.[] | select(.ai_risk_score=="high")] | length'   2>/dev/null || echo 0)
    ai_medium=$(echo "$findings_json"| jq '[.[] | select(.ai_risk_score=="medium")] | length' 2>/dev/null || echo 0)
    ai_low=$(echo "$findings_json"   | jq '[.[] | select(.ai_risk_score=="low")] | length'     2>/dev/null || echo 0)

    # Build list markdown from findings
    local findings_list remediation_list
    findings_list=$(echo "$findings_json" | jq -r '.[] | "- **\(.rule_name // "Unknown Rule")** (\(.severity // "unknown" | ascii_upcase))\n  - File: `\(.file_path // "unknown")` (line \(.line_number // 0))\n  - Description: \(.description // "")"' 2>/dev/null || echo "No detailed findings available")
    remediation_list=$(echo "$findings_json" | jq -r '.[] | select(.ai_remediation) | "- **\(.rule_name // "Unknown")**: \(.ai_remediation)"' 2>/dev/null)
    if [ -z "$remediation_list" ]; then
        remediation_list="- Review and secure any exposed credentials
- Use environment variables or secure vaults for sensitive data
- Remove hardcoded passwords and API keys"
    fi

    # Files scanned count (from repo workspace)
    local files_scanned
    files_scanned=$(find "$SCAN_SOURCE_PATH" -type f | wc -l | tr -d ' ')

    # Create comment body (no inline jq calls)
    local comment_body
    comment_body="## 🔍 Ghost Scanner Security Analysis

### Summary
- **Total Findings**: $total
- **Critical**: $critical
- **High**: $high
- **Medium**: $medium
- **Low**: $low

### 🤖 AI Risk Assessment
- **High Risk**: $ai_high
- **Medium Risk**: $ai_medium
- **Low Risk**: $ai_low

### 🔍 Security Findings
$findings_list

### 🛠️ AI-Powered Remediation Recommendations
$remediation_list

### 📊 Scan Details
- **Scan Root**: $SCAN_SOURCE_PATH
- **Files Scanned**: $files_scanned

---
*Powered by Ghost Scanner AI*"

    # Post comment to PR
    local response=$(curl -s -X POST "https://api.github.com/repos/$REPO_NAME/issues/$PR_NUMBER/comments" \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        -d "{\"body\": $(echo "$comment_body" | jq -R -s .)}")
    
    if echo "$response" | jq -e '.id' >/dev/null 2>&1; then
        log_info "PR comment posted successfully"
    else
        log_error "Failed to post PR comment: $response"
    fi
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
# Ensure scans run against the checked out repository, not the action folder
SCAN_SOURCE_PATH="${GITHUB_WORKSPACE:-$(pwd)}"

# Get PR number from different sources
if [ -n "$GITHUB_EVENT_NUMBER" ]; then
    PR_NUMBER="$GITHUB_EVENT_NUMBER"
elif [ -n "$GITHUB_EVENT_PATH" ] && [ -f "$GITHUB_EVENT_PATH" ]; then
    PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
elif [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    PR_NUMBER=$(echo "$GITHUB_REF" | sed 's/refs\/pull\/\([0-9]*\)\/merge/\1/')
else
    PR_NUMBER=""
fi

log_info "Starting Ghost Scanner analysis"
log_info "Repository: $REPO_NAME"
log_info "Commit: $COMMIT_SHA"
log_info "Branch: $BRANCH"
log_info "PR Number: $PR_NUMBER"
log_info "Scan types: $SCAN_TYPES"

# Debug Git context to confirm what's being scanned
log_info "Git context summary:"
echo "  Scan root: $SCAN_SOURCE_PATH"
echo "  HEAD ref: $(git -C \"$SCAN_SOURCE_PATH\" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
echo "  Last commit: $(git -C \"$SCAN_SOURCE_PATH\" log -1 --oneline 2>/dev/null || echo unknown)"
echo "  GITHUB_REF: $GITHUB_REF"
echo "  GITHUB_HEAD_REF: $GITHUB_HEAD_REF"

# Create scan session
log_info "Creating scan session..."

# Prepare common auth header if API key provided
AUTH_HEADER=""
if [ -n "$API_KEY" ]; then
    AUTH_HEADER="Authorization: Bearer $API_KEY"
fi

# Build JSON payload dynamically including repo_full_name (simplified backend contract)
JSON_PAYLOAD="{
    \"scan_type\": \"secrets\",
    \"commit_sha\": \"$COMMIT_SHA\",
    \"branch\": \"$BRANCH\",
    \"repo_full_name\": \"$REPO_NAME\""

# Add pull_request_number only if it's not empty
if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
    JSON_PAYLOAD="$JSON_PAYLOAD,
    \"pull_request_number\": $PR_NUMBER"
fi

JSON_PAYLOAD="$JSON_PAYLOAD
}"

log_info "Sending JSON payload: $JSON_PAYLOAD"

# Create scan session with robust error handling
SCAN_RAW_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE_URL/api/v1/scans/" \
    -H "Content-Type: application/json" ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
    -d "$JSON_PAYLOAD")

SCAN_HTTP_CODE=${SCAN_RAW_RESPONSE##*$'\n'}
SCAN_RESPONSE_BODY=${SCAN_RAW_RESPONSE%$'\n'$SCAN_HTTP_CODE}

if ! echo "$SCAN_RESPONSE_BODY" | jq . >/dev/null 2>&1; then
    log_error "Scan API returned non-JSON response (HTTP $SCAN_HTTP_CODE)"
    echo "$SCAN_RESPONSE_BODY"
    exit 1
fi

SCAN_ID=$(echo "$SCAN_RESPONSE_BODY" | jq -r '.id')

if [ "$SCAN_ID" = "null" ] || [ -z "$SCAN_ID" ]; then
    log_error "Failed to create scan session (HTTP $SCAN_HTTP_CODE)"
    log_error "Response: $SCAN_RESPONSE_BODY"
    exit 1
fi

log_info "Scan session created: $SCAN_ID"

# Run scans based on scan types
FINDINGS="[]"

if [[ "$SCAN_TYPES" == *"secrets"* ]]; then
    log_info "Running secrets scan..."
    # Try to install gitleaks before deciding engine
    ensure_gitleaks >/dev/null 2>&1 || true
    # Announce which engine will run (after attempting install)
    if command -v gitleaks >/dev/null 2>&1; then
        GL_VER=$(gitleaks version 2>/dev/null | head -n1 || echo "unknown")
        log_info "Secrets engine: Gitleaks (${GL_VER})"
    else
        log_info "Secrets engine: Pattern-based"
    fi
    SECRETS_FINDINGS=$(run_secrets_scan)
    log_info "Secrets scan completed"
    
    # Safely merge findings with error handling
    if echo "$FINDINGS $SECRETS_FINDINGS" | jq -s 'add' 2>/dev/null; then
        FINDINGS=$(echo "$FINDINGS $SECRETS_FINDINGS" | jq -s 'add')
    else
        log_warn "Failed to parse secrets findings, using empty array"
        FINDINGS="$FINDINGS"
    fi
fi

if [[ "$SCAN_TYPES" == *"dependencies"* ]]; then
    log_info "Running dependency scan..."
    DEPENDENCY_FINDINGS=$(run_dependency_scan)
    log_info "Dependency scan completed"
    
    # Safely merge findings with error handling
    if echo "$FINDINGS $DEPENDENCY_FINDINGS" | jq -s 'add' 2>/dev/null; then
        FINDINGS=$(echo "$FINDINGS $DEPENDENCY_FINDINGS" | jq -s 'add')
    else
        log_warn "Failed to parse dependency findings, using empty array"
        FINDINGS="$FINDINGS"
    fi
fi

# Send findings to API
log_info "Sending findings to Ghost Scanner API..."
FINDINGS_COUNT=$(echo "$FINDINGS" | jq 'length')

if [ "$FINDINGS_COUNT" -gt 0 ]; then
    log_warn "Found $FINDINGS_COUNT security findings"
    
    # Complete the scan with findings
    curl -s -X POST "$API_BASE_URL/api/v1/scans/$SCAN_ID/complete" \
        -H "Content-Type: application/json" ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
        -d "{
            \"findings\": $FINDINGS
        }"
    
    # Get AI-enhanced findings
    log_info "Getting AI-enhanced findings..."
    AI_FINDINGS_RESPONSE=$(curl -s -X GET "$API_BASE_URL/api/v1/findings/?scan_id=$SCAN_ID" ${AUTH_HEADER:+-H "$AUTH_HEADER"})
    
    # Get scan results
    log_info "Getting scan results..."
    RESULTS_RESPONSE=$(curl -s -X GET "$API_BASE_URL/api/v1/scans/$SCAN_ID/results" ${AUTH_HEADER:+-H "$AUTH_HEADER"})
    
    # Post PR comment if enabled
    log_info "Checking PR comment conditions:"
    log_info "COMMENT_ON_PR: $COMMENT_ON_PR"
    log_info "PR_NUMBER: $PR_NUMBER"
    log_info "GITHUB_TOKEN available: $([ -n "$GITHUB_TOKEN" ] && echo "yes" || echo "no")"
    
    if [ "$COMMENT_ON_PR" = "true" ] && [ -n "$PR_NUMBER" ] && [ -n "$GITHUB_TOKEN" ]; then
        log_info "Posting PR comment..."
        post_pr_comment "$AI_FINDINGS_RESPONSE" "$RESULTS_RESPONSE"
    else
        log_warn "Skipping PR comment - conditions not met"
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
