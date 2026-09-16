"""
Hardcoded secrets scanner — detects API keys, passwords, tokens, and private keys
embedded in source code using pattern matching.

Confidence levels:
  LIKELY   — strong pattern match in a non-test, non-example file with a real-looking value
  POSSIBLE — placeholder value, example file, or test context
"""
import re
from pathlib import Path
from typing import List

from scanners.base import BaseScanner
from scanners.registry import scanner_registry
from scanners.models import (
    ScanTarget,
    RawFinding,
    ValidationResult,
    SecurityCategory,
    Severity,
    Confidence,
)

# ---------------------------------------------------------------------------
# Pattern table
# (pattern_name, compiled_regex, value_capture_group, severity, description, cwe_id)
# value_capture_group: 1 if group(1) holds the secret; 0 = use the full match
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list = [
    (
        "hardcoded_password",
        re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'${\s][^"\']{4,})["\']'),
        1, Severity.HIGH,
        "Hardcoded password found in source code",
        "CWE-798",
    ),
    (
        "hardcoded_secret_key",
        re.compile(
            r'(?i)(?:secret[_\-]?key|auth[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\']([^"\'${\s][^"\']{6,})["\']'
        ),
        1, Severity.HIGH,
        "Hardcoded secret key found in source code",
        "CWE-798",
    ),
    (
        "aws_access_key_id",
        re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        1, Severity.CRITICAL,
        "AWS Access Key ID found in source code",
        "CWE-312",
    ),
    (
        "github_token",
        re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b'),
        1, Severity.CRITICAL,
        "GitHub personal access token found in source code",
        "CWE-312",
    ),
    (
        "generic_api_key",
        re.compile(
            r'(?i)(?:api[_\-]?key|access[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'
        ),
        1, Severity.HIGH,
        "Hardcoded API key or access token found",
        "CWE-798",
    ),
    (
        "private_key_block",
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        0, Severity.CRITICAL,
        "Private key material found in source code",
        "CWE-321",
    ),
    (
        "slack_token",
        re.compile(r'\b(xox[baprs]-(?:[0-9a-zA-Z]{10,48}-?){2,})\b'),
        1, Severity.HIGH,
        "Slack API token found in source code",
        "CWE-312",
    ),
    (
        "stripe_key",
        re.compile(r'\b((?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,})\b'),
        1, Severity.CRITICAL,
        "Stripe API key found in source code",
        "CWE-312",
    ),
    (
        "jwt_secret",
        re.compile(r'(?i)jwt[_\-]?secret\s*[=:]\s*["\']([^"\'${\s][^"\']{6,})["\']'),
        1, Severity.HIGH,
        "Hardcoded JWT secret found in source code",
        "CWE-798",
    ),
    (
        "db_credentials_in_uri",
        re.compile(
            r'(?i)(?:mongodb|mysql|postgresql|postgres|redis|mssql)://[^:\s"\']+:([^@\s"\']{6,})@'
        ),
        1, Severity.HIGH,
        "Database connection string with embedded credentials found",
        "CWE-312",
    ),
]

# Lines that look like runtime env-var lookups are not hardcoded values
_ENV_LOOKUP_RE = re.compile(
    r'(?:os\.environ|os\.getenv|process\.env|getenv|config\.get|environ\.get'
    r'|settings\.\w|env\[|dotenv|System\.getenv)',
    re.IGNORECASE,
)

# Values that are clearly placeholders — downgrade to POSSIBLE
_PLACEHOLDER_RE = re.compile(
    r'^(?:changeme|your[_\-]?(?:key|token|secret|password|api[_\-]?key)|example'
    r'|placeholder|test(?:ing)?|dummy|xxx+|secret|password|passwd|change_me'
    r'|insert[_\-]?here|todo|fixme|null|none|empty|\$\{[^}]+\}|<[^>]+>)$',
    re.IGNORECASE,
)

_SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
    '.cs', '.cfg', '.conf', '.ini', '.yaml', '.yml', '.toml',
    '.json', '.xml', '.properties', '.sh', '.bash', '.zsh', '.ksh', '.env',
}

_SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
    'dist', 'build', '.pytest_cache', '.mypy_cache', 'vendor', '.tox',
}

_EXAMPLE_FILENAMES = {
    '.env.example', '.env.sample', '.env.test', '.env.template',
    'README.md', 'README.rst', 'CHANGELOG.md', 'CONTRIBUTING.md', 'INSTALL.md',
}

_TEST_PARTS = {'test', 'tests', 'spec', 'specs', 'fixture', 'fixtures', 'mock', 'mocks'}


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def _in_test_context(rel_str: str) -> bool:
    return any(p.lower() in _TEST_PARTS for p in Path(rel_str).parts)


@scanner_registry.register
class SecretsScanner(BaseScanner):
    scanner_id = "secrets.hardcoded_credentials"
    name = "Hardcoded Secrets & Credentials"
    description = (
        "Detects hardcoded API keys, passwords, tokens, and private keys in source code "
        "using pattern matching. Does not confirm that discovered credentials are active."
    )
    category = SecurityCategory.SECRETS
    supported_stacks = []
    cwe_ids = ["CWE-798", "CWE-312", "CWE-321"]

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
        is_example = file_path.name in _EXAMPLE_FILENAMES
        is_test = _in_test_context(rel_str)

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        findings: List[RawFinding] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(('#', '//', '*', '--', ';')):
                continue
            if _ENV_LOOKUP_RE.search(line):
                continue

            for pat_name, pattern, val_grp, severity, description, cwe in _SECRET_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue

                value = (
                    m.group(val_grp)
                    if val_grp and m.lastindex and m.lastindex >= val_grp
                    else m.group(0)
                )

                if is_example or is_test or _is_placeholder(value):
                    confidence = Confidence.POSSIBLE
                    effective_sev = Severity.LOW
                else:
                    confidence = Confidence.LIKELY
                    effective_sev = severity

                # Code snippet: ±2 lines of context, secret value redacted
                ctx_start = max(0, line_no - 3)
                ctx_end = min(len(lines), line_no + 2)
                snippet = "\n".join(
                    f"{i + 1:4d} | {lines[i]}" for i in range(ctx_start, ctx_end)
                )
                if len(value) > 4:
                    snippet = snippet.replace(value, "[REDACTED]")

                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title=f"Hardcoded Secret: {pat_name.replace('_', ' ').title()}",
                    description=f"{description} in `{rel_str}` at line {line_no}.",
                    category=SecurityCategory.SECRETS,
                    severity=effective_sev,
                    confidence=confidence,
                    affected_file=rel_str,
                    affected_line=line_no,
                    affected_component=f"File: {rel_str}",
                    cwe_id=cwe,
                    owasp_category="A02:2021 – Cryptographic Failures",
                    impact=(
                        "An attacker who discovers this credential could authenticate as the application "
                        "to external services, access sensitive data, or escalate privileges."
                    ),
                    remediation=(
                        "Remove the hardcoded credential from source code. Use environment variables "
                        "or a dedicated secrets manager. Rotate any exposed credentials immediately."
                    ),
                    evidence_data={
                        "type": "code_snippet",
                        "title": f"Code snippet — {rel_str}:{line_no}",
                        "content": snippet,
                        "metadata": {"file": rel_str, "line": line_no, "pattern": pat_name},
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

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        if finding.affected_file and _in_test_context(finding.affected_file):
            return ValidationResult(
                is_valid=True,
                confidence=Confidence.POSSIBLE,
                notes="Finding in test/fixture file — confidence lowered.",
            )
        return ValidationResult(
            is_valid=finding.confidence != Confidence.FALSE_POSITIVE,
            confidence=finding.confidence,
        )
