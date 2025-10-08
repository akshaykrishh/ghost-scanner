"""
Ghost Scanner - Scanning Service

Service for executing security scans using various scanning engines.
"""

import subprocess
import json
import tempfile
import os
import structlog
from typing import Dict, List, Optional
from pathlib import Path
import shutil

from app.core.config import settings
from app.core.exceptions import ScanError

logger = structlog.get_logger()

class ScanService:
    """Service for executing security scans."""
    
    def __init__(self):
        self.gitleaks_path = settings.GITLEAKS_BINARY_PATH
        self.dependency_check_path = settings.DEPENDENCY_CHECK_PATH
    
    def run_secrets_scan(self, repo_path: str, scan_config: Optional[Dict] = None) -> List[Dict]:
        """
        Run secrets scanning using Gitleaks.
        
        Args:
            repo_path: Path to the repository to scan
            scan_config: Optional configuration for the scan
            
        Returns:
            List of secret findings
        """
        try:
            logger.info("Starting secrets scan", repo_path=repo_path)
            
            # Check if gitleaks is available
            if not self._check_gitleaks_available():
                logger.warning("Gitleaks not available, using fallback")
                return self._fallback_secrets_scan(repo_path)
            
            # Run gitleaks scan
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source", repo_path,
                "--format", "json",
                "--no-git"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error("Gitleaks scan failed", 
                           stderr=result.stderr, 
                           returncode=result.returncode)
                raise ScanError(f"Gitleaks scan failed: {result.stderr}")
            
            # Parse results
            findings = self._parse_gitleaks_output(result.stdout)
            
            logger.info("Secrets scan completed", 
                       findings_count=len(findings),
                       repo_path=repo_path)
            
            return findings
            
        except subprocess.TimeoutExpired:
            logger.error("Secrets scan timed out", repo_path=repo_path)
            raise ScanError("Secrets scan timed out")
        except Exception as e:
            logger.error("Secrets scan failed", error=str(e), repo_path=repo_path)
            raise ScanError(f"Secrets scan failed: {str(e)}")
    
    def run_dependency_scan(self, repo_path: str, scan_config: Optional[Dict] = None) -> List[Dict]:
        """
        Run dependency scanning using OWASP Dependency-Check.
        
        Args:
            repo_path: Path to the repository to scan
            scan_config: Optional configuration for the scan
            
        Returns:
            List of dependency findings
        """
        try:
            logger.info("Starting dependency scan", repo_path=repo_path)
            
            # Check if dependency-check is available
            if not self._check_dependency_check_available():
                logger.warning("Dependency-Check not available, using fallback")
                return self._fallback_dependency_scan(repo_path)
            
            # Create temporary output directory
            with tempfile.TemporaryDirectory() as temp_dir:
                output_file = os.path.join(temp_dir, "dependency-check-report.json")
                
                # Run dependency-check
                cmd = [
                    self.dependency_check_path,
                    "--project", "Ghost Scanner Scan",
                    "--scan", repo_path,
                    "--format", "JSON",
                    "--out", temp_dir
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                
                if result.returncode != 0:
                    logger.error("Dependency-Check scan failed", 
                               stderr=result.stderr, 
                               returncode=result.returncode)
                    raise ScanError(f"Dependency-Check scan failed: {result.stderr}")
                
                # Parse results
                findings = self._parse_dependency_check_output(output_file)
                
                logger.info("Dependency scan completed", 
                           findings_count=len(findings),
                           repo_path=repo_path)
                
                return findings
                
        except subprocess.TimeoutExpired:
            logger.error("Dependency scan timed out", repo_path=repo_path)
            raise ScanError("Dependency scan timed out")
        except Exception as e:
            logger.error("Dependency scan failed", error=str(e), repo_path=repo_path)
            raise ScanError(f"Dependency scan failed: {str(e)}")
    
    def _check_gitleaks_available(self) -> bool:
        """Check if Gitleaks is available."""
        try:
            result = subprocess.run(
                [self.gitleaks_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _check_dependency_check_available(self) -> bool:
        """Check if OWASP Dependency-Check is available."""
        try:
            result = subprocess.run(
                [self.dependency_check_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _parse_gitleaks_output(self, output: str) -> List[Dict]:
        """Parse Gitleaks JSON output."""
        findings = []
        
        try:
            if not output.strip():
                return findings
            
            # Gitleaks outputs one JSON object per line
            for line in output.strip().split('\n'):
                if line.strip():
                    finding = json.loads(line)
                    findings.append({
                        "rule_id": finding.get("RuleID", "unknown"),
                        "rule_name": finding.get("RuleID", "Unknown Secret"),
                        "severity": "high",  # Secrets are typically high severity
                        "confidence": 0.9,  # High confidence for detected secrets
                        "file_path": finding.get("File", ""),
                        "line_number": finding.get("StartLine", 0),
                        "column_number": finding.get("StartColumn", 0),
                        "secret_value": finding.get("Secret", ""),
                        "description": f"Secret detected: {finding.get('RuleID', 'Unknown')}",
                        "raw_data": finding
                    })
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Gitleaks output", error=str(e))
            raise ScanError(f"Failed to parse Gitleaks output: {str(e)}")
        
        return findings
    
    def _parse_dependency_check_output(self, output_file: str) -> List[Dict]:
        """Parse OWASP Dependency-Check JSON output."""
        findings = []
        
        try:
            if not os.path.exists(output_file):
                logger.warning("Dependency-Check output file not found", file=output_file)
                return findings
            
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            dependencies = data.get("dependencies", [])
            
            for dep in dependencies:
                vulnerabilities = dep.get("vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    findings.append({
                        "rule_id": vuln.get("name", "unknown"),
                        "rule_name": vuln.get("name", "Unknown Vulnerability"),
                        "severity": self._map_cvss_severity(vuln.get("cvssv3", {}).get("baseScore", 0)),
                        "confidence": 0.95,  # High confidence for CVE data
                        "file_path": dep.get("filePath", ""),
                        "line_number": None,
                        "column_number": None,
                        "secret_value": None,
                        "description": vuln.get("description", ""),
                        "raw_data": {
                            "dependency": dep,
                            "vulnerability": vuln
                        }
                    })
                    
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse Dependency-Check output", error=str(e))
            raise ScanError(f"Failed to parse Dependency-Check output: {str(e)}")
        
        return findings
    
    def _map_cvss_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        else:
            return "info"
    
    def _fallback_secrets_scan(self, repo_path: str) -> List[Dict]:
        """Fallback secrets scanning using simple pattern matching."""
        findings = []
        
        # Simple patterns for common secrets
        secret_patterns = {
            "api_key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
            "aws_access_key": r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
            "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"]{8,})['\"]?",
            "token": r"(?i)(token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?"
        }
        
        # Scan files for patterns
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.json', '.env', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern in secret_patterns.items():
                            import re
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                findings.append({
                                    "rule_id": f"fallback_{pattern_name}",
                                    "rule_name": f"Potential {pattern_name.replace('_', ' ').title()}",
                                    "severity": "medium",
                                    "confidence": 0.6,
                                    "file_path": os.path.relpath(file_path, repo_path),
                                    "line_number": content[:match.start()].count('\n') + 1,
                                    "column_number": match.start() - content.rfind('\n', 0, match.start()),
                                    "secret_value": match.group(2) if len(match.groups()) > 1 else "***",
                                    "description": f"Potential {pattern_name} detected using pattern matching",
                                    "raw_data": {"pattern": pattern_name, "match": match.group()}
                                })
                    except Exception as e:
                        logger.warning("Failed to scan file", file=file_path, error=str(e))
        
        logger.info("Fallback secrets scan completed", findings_count=len(findings))
        return findings
    
    def _fallback_dependency_scan(self, repo_path: str) -> List[Dict]:
        """Fallback dependency scanning by checking common manifest files."""
        findings = []
        
        # Check for package.json (Node.js)
        package_json_path = os.path.join(repo_path, "package.json")
        if os.path.exists(package_json_path):
            findings.extend(self._scan_package_json(package_json_path))
        
        # Check for requirements.txt (Python)
        requirements_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(requirements_path):
            findings.extend(self._scan_requirements_txt(requirements_path))
        
        logger.info("Fallback dependency scan completed", findings_count=len(findings))
        return findings
    
    def _scan_package_json(self, file_path: str) -> List[Dict]:
        """Scan package.json for known vulnerable packages."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            # Known vulnerable packages (simplified for MVP)
            vulnerable_packages = {
                "lodash": "4.17.20",  # Example vulnerable version
                "moment": "2.29.1",   # Example vulnerable version
            }
            
            for package, version in dependencies.items():
                if package in vulnerable_packages:
                    findings.append({
                        "rule_id": f"vulnerable_package_{package}",
                        "rule_name": f"Vulnerable Package: {package}",
                        "severity": "medium",
                        "confidence": 0.8,
                        "file_path": os.path.basename(file_path),
                        "line_number": None,
                        "column_number": None,
                        "secret_value": None,
                        "description": f"Package {package} version {version} may have known vulnerabilities",
                        "raw_data": {"package": package, "version": version}
                    })
                    
        except Exception as e:
            logger.warning("Failed to scan package.json", file=file_path, error=str(e))
        
        return findings
    
    def _scan_requirements_txt(self, file_path: str) -> List[Dict]:
        """Scan requirements.txt for known vulnerable packages."""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            # Known vulnerable packages (simplified for MVP)
            vulnerable_packages = {
                "django": "3.2.0",  # Example vulnerable version
                "flask": "1.1.0",  # Example vulnerable version
            }
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    package = line.split('==')[0].split('>=')[0].split('<=')[0]
                    if package in vulnerable_packages:
                        findings.append({
                            "rule_id": f"vulnerable_package_{package}",
                            "rule_name": f"Vulnerable Package: {package}",
                            "severity": "medium",
                            "confidence": 0.8,
                            "file_path": os.path.basename(file_path),
                            "line_number": line_num,
                            "column_number": None,
                            "secret_value": None,
                            "description": f"Package {package} may have known vulnerabilities",
                            "raw_data": {"package": package, "line": line}
                        })
                        
        except Exception as e:
            logger.warning("Failed to scan requirements.txt", file=file_path, error=str(e))
        
        return findings

# Global scan service instance
scan_service = ScanService()
