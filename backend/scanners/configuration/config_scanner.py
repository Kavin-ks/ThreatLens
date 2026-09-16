"""
Configuration security scanner — detects common security misconfigurations in
source code and config files.

Checks performed:
  - DEBUG mode enabled (Django / Flask / generic)
  - Permissive CORS (allow all origins)
  - Insecure session / cookie flags
  - CSRF protection disabled
  - Weak or placeholder secret keys
  - SSL/TLS certificate verification disabled
  - Broad ALLOWED_HOSTS wildcard (Django)
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from scanners.base import BaseScanner
from scanners.registry import scanner_registry
from scanners.models import (
    ScanTarget,
    RawFinding,
    SecurityCategory,
    Severity,
    Confidence,
)

# ---------------------------------------------------------------------------
# Check rule definition
# ---------------------------------------------------------------------------

@dataclass
class _CheckRule:
    rule_id: str
    pattern: re.Pattern
    severity: Severity
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: str
    owasp_category: str = "A05:2021 – Security Misconfiguration"
    # Optional: restrict to filenames matching this pattern
    filename_pattern: Optional[re.Pattern] = None


_RULES: List[_CheckRule] = [
    _CheckRule(
        rule_id="debug_mode_enabled",
        pattern=re.compile(r'(?i)\bDEBUG\s*[=:]\s*(?:True|true|1|yes)\b'),
        severity=Severity.HIGH,
        title="Debug Mode Enabled",
        description="Application debug mode is enabled, exposing stack traces and internal details.",
        impact=(
            "Debug pages can reveal source code paths, environment variables, installed packages, "
            "database credentials, and internal error details to any user who triggers an exception."
        ),
        remediation=(
            "Set DEBUG = False in production. Use environment-specific settings files or "
            "an environment variable override (e.g. DEBUG=False in production .env)."
        ),
        cwe_id="CWE-489",
    ),
    _CheckRule(
        rule_id="permissive_cors_wildcard",
        pattern=re.compile(
            r'(?i)'
            r'(?:'
            r'allow[_\-]?origins?\s*[=:,]\s*(?:\[[\s"\']*\*[\s"\']*\]|["\']?\*["\']?)'
            r'|cors[_\-]?origins?\s*=\s*\[[\s"\']*\*[\s"\']*\]'
            r'|cors[_\-]?allow[_\-]?all[_\-]?origins?\s*=\s*(?:True|true|1)'
            r'|Access-Control-Allow-Origin\s*[=:,]\s*\*'
            r')'
        ),
        severity=Severity.HIGH,
        title="Permissive CORS Configuration (Wildcard Origin)",
        description="CORS is configured to accept requests from any origin ('*').",
        impact=(
            "Any website can make credentialed cross-origin requests to this API, enabling "
            "cross-site request forgery and sensitive data exposure via malicious pages."
        ),
        remediation=(
            "Restrict CORS to explicit, trusted origin domains. "
            "Never use '*' for APIs that handle authentication or sensitive data."
        ),
        cwe_id="CWE-942",
        owasp_category="A05:2021 – Security Misconfiguration",
    ),
    _CheckRule(
        rule_id="insecure_session_cookie",
        pattern=re.compile(
            r'(?i)SESSION_COOKIE_SECURE\s*[=:]\s*(?:False|false|0|no)\b'
        ),
        severity=Severity.HIGH,
        title="Session Cookie Secure Flag Disabled",
        description="Session cookies are not restricted to HTTPS-only transmission.",
        impact=(
            "Session cookies can be transmitted over plain HTTP connections, "
            "allowing interception by a network attacker (e.g. on public Wi-Fi)."
        ),
        remediation="Set SESSION_COOKIE_SECURE = True and ensure the application runs over HTTPS.",
        cwe_id="CWE-614",
        owasp_category="A02:2021 – Cryptographic Failures",
    ),
    _CheckRule(
        rule_id="insecure_cookie_httponly_disabled",
        pattern=re.compile(
            r'(?i)(?:SESSION_COOKIE_HTTPONLY|httpOnly|http_only)\s*[=:]\s*(?:False|false|0|no)\b'
        ),
        severity=Severity.MEDIUM,
        title="Cookie HttpOnly Flag Disabled",
        description="Cookies are accessible to JavaScript, increasing XSS impact.",
        impact=(
            "If an XSS vulnerability exists, scripts can read session cookies and "
            "impersonate authenticated users."
        ),
        remediation="Enable the HttpOnly flag on all session and authentication cookies.",
        cwe_id="CWE-1004",
    ),
    _CheckRule(
        rule_id="csrf_protection_disabled",
        pattern=re.compile(
            r'(?i)(?:CSRF_ENABLED|WTF_CSRF_ENABLED|csrfProtection|csrf_enabled)'
            r'\s*[=:]\s*(?:False|false|0|no)\b'
        ),
        severity=Severity.HIGH,
        title="CSRF Protection Disabled",
        description="Cross-Site Request Forgery protection has been explicitly disabled.",
        impact=(
            "State-changing actions (account updates, transfers, admin operations) can be "
            "triggered by a malicious page the victim visits while authenticated."
        ),
        remediation=(
            "Enable CSRF protection (set CSRF_ENABLED = True / WTF_CSRF_ENABLED = True). "
            "Never disable it except in APIs that use token-based authentication exclusively."
        ),
        cwe_id="CWE-352",
        owasp_category="A01:2021 – Broken Access Control",
    ),
    _CheckRule(
        rule_id="weak_default_secret_key",
        pattern=re.compile(
            r'(?i)(?:SECRET_KEY|APP_SECRET|FLASK_SECRET)\s*[=:]\s*["\']'
            r'(?:changeme|secret|password|dev|development|test|your[_\-]?secret|insecure|'
            r'django-insecure[^"\']{0,40}|CHANGE[_\-]?THIS[^"\']{0,40})["\']'
        ),
        severity=Severity.HIGH,
        title="Weak or Placeholder Secret Key",
        description="The application secret key is set to a known-weak or placeholder value.",
        impact=(
            "A predictable secret key allows attackers to forge signed cookies, JWT tokens, "
            "or CSRF tokens, bypassing authentication and session protections."
        ),
        remediation=(
            "Generate a strong random secret key (e.g. `python -c \"import secrets; print(secrets.token_hex(32))\"`) "
            "and store it in an environment variable, never in source code."
        ),
        cwe_id="CWE-798",
        owasp_category="A02:2021 – Cryptographic Failures",
    ),
    _CheckRule(
        rule_id="ssl_verification_disabled",
        pattern=re.compile(
            r'(?i)(?:verify\s*[=:]\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["\']?0["\']?'
            r'|ssl[_\-]?verify\s*[=:]\s*(?:False|false|0))',
        ),
        severity=Severity.HIGH,
        title="SSL/TLS Certificate Verification Disabled",
        description="SSL/TLS certificate verification has been disabled, allowing MITM attacks.",
        impact=(
            "Disabling certificate verification lets an attacker intercept and modify encrypted "
            "traffic by presenting an untrusted certificate."
        ),
        remediation=(
            "Always enable SSL/TLS certificate verification in production. "
            "If a self-signed certificate is required, install it in the trusted CA store instead of disabling verification."
        ),
        cwe_id="CWE-295",
        owasp_category="A02:2021 – Cryptographic Failures",
    ),
    _CheckRule(
        rule_id="allowed_hosts_wildcard",
        pattern=re.compile(r'(?i)ALLOWED_HOSTS\s*[=:]\s*\[[\s"\']*\*[\s"\']*\]'),
        severity=Severity.MEDIUM,
        title="ALLOWED_HOSTS Set to Wildcard",
        description="Django ALLOWED_HOSTS is set to ['*'], accepting requests for any hostname.",
        impact=(
            "Wildcard ALLOWED_HOSTS bypasses Django's Host header validation, "
            "enabling host header injection attacks."
        ),
        remediation=(
            "Set ALLOWED_HOSTS to the explicit list of domain names the application serves. "
            "Example: ALLOWED_HOSTS = ['api.example.com', 'localhost']"
        ),
        cwe_id="CWE-116",
    ),
]

_SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.cfg', '.ini', '.conf',
    '.yaml', '.yml', '.toml', '.json', '.env', '.sh',
}

_SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'env', 'dist', 'build', '.pytest_cache', 'vendor',
}

# Test/dev config files — downgrade to POSSIBLE
_TEST_CONFIG_FRAGMENTS = {
    'test', 'tests', 'dev', 'development', 'local', 'example', 'sample',
}


def _is_test_config(rel_str: str) -> bool:
    parts = {p.lower() for p in Path(rel_str).parts}
    return bool(parts & _TEST_CONFIG_FRAGMENTS)


@scanner_registry.register
class ConfigurationScanner(BaseScanner):
    scanner_id = "configuration.security_misconfig"
    name = "Security Misconfiguration Scanner"
    description = (
        "Detects common security misconfigurations in source code and config files: "
        "debug mode, permissive CORS, insecure cookies, disabled CSRF, weak secret keys, "
        "and disabled SSL verification."
    )
    category = SecurityCategory.CONFIGURATION
    supported_stacks = []
    cwe_ids = ["CWE-489", "CWE-942", "CWE-614", "CWE-352", "CWE-798", "CWE-295"]

    def can_scan(self, target: ScanTarget) -> bool:
        return target.target_path is not None and target.target_path.is_dir()

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        seen: set = set()
        for file_path in self._iter_files(target.target_path):
            try:
                for f in self._scan_file(file_path, target.target_path):
                    key = (f.affected_file, f.affected_line, f.title)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
            except Exception:
                continue
        return findings

    def _scan_file(self, file_path: Path, root: Path) -> List[RawFinding]:
        rel_str = str(file_path.relative_to(root))
        is_test_cfg = _is_test_config(rel_str)

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        findings: List[RawFinding] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(('#', '//', '*', '--', ';')):
                continue

            for rule in _RULES:
                if rule.filename_pattern and not rule.filename_pattern.search(file_path.name):
                    continue
                if not rule.pattern.search(line):
                    continue

                confidence = Confidence.POSSIBLE if is_test_cfg else Confidence.LIKELY

                ctx_start = max(0, line_no - 3)
                ctx_end = min(len(lines), line_no + 2)
                snippet = "\n".join(
                    f"{i + 1:4d} | {lines[i]}" for i in range(ctx_start, ctx_end)
                )

                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title=rule.title,
                    description=f"{rule.description} Found in `{rel_str}` at line {line_no}.",
                    category=SecurityCategory.CONFIGURATION,
                    severity=rule.severity,
                    confidence=confidence,
                    affected_file=rel_str,
                    affected_line=line_no,
                    affected_component=f"File: {rel_str}",
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    impact=rule.impact,
                    remediation=rule.remediation,
                    evidence_data={
                        "type": "config_value",
                        "title": f"Config snippet — {rel_str}:{line_no}",
                        "content": snippet,
                        "metadata": {
                            "file": rel_str,
                            "line": line_no,
                            "rule_id": rule.rule_id,
                        },
                    },
                ))
        return findings

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path
