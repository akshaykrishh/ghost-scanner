import json
import os
import re
import sys


def run_pattern_scan(root_dir: str) -> None:
    findings = []

    patterns = {
        # Generic API key-ish
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
        # AWS
        'aws_access_key_id': r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?',
        'aws_secret_access_key': r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        # Password-like
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\']{8,})["\']?',
        # Common providers
        'stripe_key': r'(?i)sk_(live|test)_[A-Za-z0-9]{20,}',
        'github_token': r'ghp_[A-Za-z0-9]{36,}',
        'slack_webhook': r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
        'discord_webhook': r'https://discord\.com/api/webhooks/[A-Za-z0-9_/.-]+',
        # Keys
        'rsa_private_key': r'-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA )?PRIVATE KEY-----',
    }

    include_exts = (
        '.py', '.js', '.ts', '.json', '.env', '.yml', '.yaml',
        '.txt', '.md', '.cfg', '.ini', '.pem', '.key'
    )

    for base, _dirs, files in os.walk(root_dir):
        for name in files:
            if not name.endswith(include_exts):
                continue
            file_path = os.path.join(base, name)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                for pattern_name, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        findings.append({
                            'rule_id': f'pattern_{pattern_name}',
                            'rule_name': f'Potential {pattern_name.replace("_", " ").title()}',
                            'severity': 'medium',
                            'file_path': os.path.relpath(file_path, root_dir),
                            'line_number': content[:match.start()].count('\n') + 1,
                            'description': f'Potential {pattern_name} detected',
                        })
            except Exception:
                # Skip unreadable files
                continue

    print(json.dumps(findings))


if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    run_pattern_scan(root)


