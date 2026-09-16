"""
Injection probe scanners — error-based detection of SQL injection and
command injection vulnerabilities in a running local application.

Design:
  All probes are NON-DESTRUCTIVE:
    - SQL probes use read-only syntax (no INSERT/UPDATE/DELETE/DROP).
    - Command probes inject characters that trigger shell parse errors;
      they do not execute any commands with side effects.
  Detection relies on characteristic error strings in the HTTP response,
  not on timing or out-of-band channels.

Authorization constraint: only scans targets whose host resolves to
localhost or a private/RFC-1918 network address.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from scanners._dynamic_base import DynamicScanError, fetch, is_local_target
from scanners.base import BaseScanner
from scanners.models import (
    Confidence,
    RawFinding,
    ScanTarget,
    SecurityCategory,
    Severity,
    ValidationResult,
)
from scanners.registry import scanner_registry

logger = logging.getLogger(__name__)


def _fetch(url: str, **kwargs):
    """Module-level wrapper — patched in unit tests."""
    return fetch(url, **kwargs)


# ---------------------------------------------------------------------------
# Common parameter names to probe when the URL has no existing query string
# ---------------------------------------------------------------------------
_COMMON_PARAMS = [
    "id", "user_id", "item_id", "product_id",
    "q", "search", "query",
    "name", "username", "email",
    "page", "limit", "offset", "sort",
    "category", "type", "filter",
]

# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

# Read-only probes — use syntax errors to trigger database error messages
_SQL_PROBES = [
    "'",           # basic string termination
    "\"",          # double-quote string termination
    "' OR '1'='1", # classic tautology (read-only, no mutation)
    "1 AND 1=2",   # false condition that may produce different output
    "' --",        # comment truncation
]

# Database error patterns (case-insensitive)
_SQL_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"you have an error in your sql syntax",        "mysql_syntax"),
    (r"warning.*mysql_",                             "mysql_warning"),
    (r"unclosed quotation mark after the character", "mssql_quote"),
    (r"quoted string not properly terminated",       "oracle_quote"),
    (r"pg_query\(\):",                               "pg_error"),
    (r'ERROR:\s+syntax error at or near',            "pg_syntax"),
    (r"sqlite3\.operationalerror",                   "sqlite_error"),
    (r"ORA-\d{5}",                                   "oracle_ora"),
    (r"microsoft ole db provider",                   "mssql_ole"),
    (r"jet database engine",                         "access_jet"),
    (r"odbc.*error",                                 "odbc_error"),
    (r"db2 sql error",                               "db2_error"),
]
_SQL_ERROR_RE = re.compile(
    "|".join(f"({pat})" for pat, _ in _SQL_ERROR_PATTERNS),
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Command injection (error-based — no command execution)
# ---------------------------------------------------------------------------

# Probes that cause shell parsing errors without executing a real command.
# The injected string is never a valid command; the shell's error output
# (not any command output) is what we detect.
_CMD_PROBES = [
    "; invalid_cmd_notexist_threatlens",
    "| invalid_cmd_notexist_threatlens",
    "` invalid_cmd_notexist_threatlens`",
    "&& invalid_cmd_notexist_threatlens",
]

# Shell error strings that indicate the injection reached a shell interpreter
_CMD_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"command not found",                 "cmd_not_found"),
    (r"not recognized as an internal or external command", "win_cmd_error"),
    (r"/bin/sh.*not found",                "sh_not_found"),
    (r"syntax error near unexpected token", "bash_syntax"),
    (r"is not recognized as the name",     "ps_error"),
    (r"sh:.*not found",                    "sh_error"),
    (r"bash:.*not found",                  "bash_not_found"),
]
_CMD_ERROR_RE = re.compile(
    "|".join(f"({pat})" for pat, _ in _CMD_ERROR_PATTERNS),
    re.IGNORECASE,
)


def _build_url_with_param(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(existing, doseq=True)))


# ===========================================================================
# SQL Injection Scanner
# ===========================================================================

@scanner_registry.register
class SqlInjectionScanner(BaseScanner):
    scanner_id = "injection.sql_error_based"
    name = "SQL Injection Scanner (Error-Based)"
    description = (
        "Probes URL parameters with non-destructive SQL syntax payloads and looks for "
        "database error messages in responses. Detects error-based SQL injection only; "
        "does not perform blind, time-based, or out-of-band injection."
    )
    category = SecurityCategory.INJECTION
    requires_running_app = True
    cwe_ids = ["CWE-89"]

    def can_scan(self, target: ScanTarget) -> bool:
        return (
            target.target_url is not None
            and is_local_target(target.target_url)
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        url = target.target_url
        parsed = urlparse(url)
        existing_params = list(parse_qs(parsed.query).keys())
        params_to_probe = list(dict.fromkeys(existing_params + _COMMON_PARAMS))

        seen: set = set()

        for param in params_to_probe:
            for probe in _SQL_PROBES:
                probe_url = _build_url_with_param(url, param, probe)
                try:
                    resp = _fetch(probe_url, timeout=8.0)
                except DynamicScanError as exc:
                    logger.debug("SQL probe failed for %s: %s", probe_url, exc)
                    continue

                body = resp.text or ""
                match = _SQL_ERROR_RE.search(body)
                if match:
                    key = (param, match.group(0)[:40])
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title="SQL Injection — Database Error Disclosed",
                        description=(
                            f"Parameter `{param}` triggers a database error message when injected "
                            f"with `{probe}`. Matched pattern: `{match.group(0)[:80]}`. "
                            f"Endpoint: {url}"
                        ),
                        category=SecurityCategory.INJECTION,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LIKELY,
                        affected_endpoint=url,
                        affected_component=f"Parameter: {param}",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 – Injection",
                        impact=(
                            "SQL injection allows an attacker to read, modify, or delete "
                            "database content, bypass authentication, and potentially execute "
                            "OS commands via database-level functions."
                        ),
                        remediation=(
                            "Use parameterised queries or prepared statements for all database access. "
                            "Never concatenate user input into SQL strings. "
                            "Suppress database error messages in production responses."
                        ),
                        evidence_data={
                            "type": "request_response",
                            "title": f"SQL error response — {param} @ {url}",
                            "content": (
                                f"Probe URL: {probe_url}\n"
                                f"Probe value: {probe}\n"
                                f"HTTP Status: {resp.status_code}\n"
                                f"Error matched: {match.group(0)[:120]}\n"
                                f"Response snippet:\n{body[:500]}"
                            ),
                            "metadata": {
                                "url": probe_url,
                                "parameter": param,
                                "probe": probe,
                                "error_match": match.group(0)[:120],
                            },
                        },
                    ))
                    break  # one finding per parameter is enough

        return findings

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        return ValidationResult(
            is_valid=True,
            confidence=Confidence.LIKELY,
            notes=(
                "Database error string observed in response. Manual confirmation of "
                "full exploitability is recommended."
            ),
        )


# ===========================================================================
# Command Injection Scanner (error-based only)
# ===========================================================================

@scanner_registry.register
class CommandInjectionScanner(BaseScanner):
    scanner_id = "injection.command_error_based"
    name = "Command Injection Scanner (Error-Based)"
    description = (
        "Probes URL parameters with shell meta-characters and looks for shell interpreter "
        "error strings in responses. Detection is error-based only — no commands with "
        "side effects are executed."
    )
    category = SecurityCategory.INJECTION
    requires_running_app = True
    cwe_ids = ["CWE-78"]

    def can_scan(self, target: ScanTarget) -> bool:
        return (
            target.target_url is not None
            and is_local_target(target.target_url)
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        url = target.target_url
        parsed = urlparse(url)
        existing_params = list(parse_qs(parsed.query).keys())
        params_to_probe = list(dict.fromkeys(existing_params + _COMMON_PARAMS))

        seen: set = set()

        for param in params_to_probe:
            for probe in _CMD_PROBES:
                probe_url = _build_url_with_param(url, param, probe)
                try:
                    resp = _fetch(probe_url, timeout=8.0)
                except DynamicScanError as exc:
                    logger.debug("CMD probe failed for %s: %s", probe_url, exc)
                    continue

                body = resp.text or ""
                match = _CMD_ERROR_RE.search(body)
                if match:
                    key = (param, match.group(0)[:40])
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title="Command Injection — Shell Error Disclosed",
                        description=(
                            f"Parameter `{param}` triggers a shell interpreter error when injected "
                            f"with `{probe}`. Matched error: `{match.group(0)[:80]}`. "
                            f"Endpoint: {url}"
                        ),
                        category=SecurityCategory.INJECTION,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LIKELY,
                        affected_endpoint=url,
                        affected_component=f"Parameter: {param}",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 – Injection",
                        impact=(
                            "Command injection allows an attacker to execute arbitrary OS commands "
                            "on the server with the application's privileges, leading to full "
                            "system compromise, data exfiltration, and lateral movement."
                        ),
                        remediation=(
                            "Never pass user-controlled input to shell commands. "
                            "Use library functions that accept argument arrays (e.g. Python's subprocess "
                            "with a list, not a shell=True string). "
                            "Validate and allowlist input rigorously."
                        ),
                        evidence_data={
                            "type": "request_response",
                            "title": f"Shell error response — {param} @ {url}",
                            "content": (
                                f"Probe URL: {probe_url}\n"
                                f"Probe value: {probe}\n"
                                f"HTTP Status: {resp.status_code}\n"
                                f"Error matched: {match.group(0)[:120]}\n"
                                f"Response snippet:\n{body[:500]}"
                            ),
                            "metadata": {
                                "url": probe_url,
                                "parameter": param,
                                "probe": probe,
                                "error_match": match.group(0)[:120],
                            },
                        },
                    ))
                    break  # one finding per parameter is enough

        return findings

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        return ValidationResult(
            is_valid=True,
            confidence=Confidence.LIKELY,
            notes=(
                "Shell error string observed in response. Manual confirmation of "
                "full exploitability is recommended before marking CONFIRMED."
            ),
        )
