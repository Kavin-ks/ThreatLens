"""
API Security Scanner — probes a running local application for common API-level
security weaknesses.

Checks performed:
  - Exposed API documentation (OpenAPI/Swagger, ReDoc)
  - Exposed debug/console endpoints
  - Exposed admin interfaces
  - Unauthenticated access to sensitive-looking endpoints
  - Verbose error / stack trace disclosure
  - Rate-limiting header presence

Authorization constraint: only scans targets whose host resolves to
localhost or a private/RFC-1918 network address.
"""
from __future__ import annotations

import json
import logging
from typing import List, Tuple
from urllib.parse import urljoin

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
# Probe path definitions
# ---------------------------------------------------------------------------

# (path, rule_id, title, description, severity, confirm_fn)
# confirm_fn(response) -> bool — decides whether the response is a real hit
_DOC_PATHS: List[Tuple[str, str, str, str, Severity]] = [
    ("/openapi.json",    "exposed_openapi_json",    "OpenAPI Specification Exposed",        "The OpenAPI JSON schema is publicly accessible without authentication.",      Severity.MEDIUM),
    ("/swagger.json",    "exposed_swagger_json",    "Swagger JSON Specification Exposed",   "The Swagger JSON spec is publicly accessible without authentication.",        Severity.MEDIUM),
    ("/swagger-ui.html","exposed_swagger_ui",       "Swagger UI Exposed",                   "The Swagger UI is accessible without authentication.",                        Severity.MEDIUM),
    ("/docs",            "exposed_fastapi_docs",     "Interactive API Documentation Exposed","The /docs endpoint (FastAPI/Swagger UI) is accessible without authentication.", Severity.MEDIUM),
    ("/redoc",           "exposed_redoc",            "ReDoc API Documentation Exposed",      "The /redoc endpoint is accessible without authentication.",                    Severity.MEDIUM),
    ("/api-docs",        "exposed_api_docs",         "API Documentation Exposed",            "The /api-docs endpoint is accessible without authentication.",                 Severity.MEDIUM),
    ("/graphql",         "exposed_graphql_playground","GraphQL Endpoint Exposed",            "A GraphQL endpoint is accessible. Verify it requires authentication and introspection is disabled in production.", Severity.MEDIUM),
]

_DEBUG_PATHS: List[Tuple[str, str, str, str, Severity]] = [
    ("/__debug__/",      "debug_toolbar",    "Django Debug Toolbar Exposed",   "Django Debug Toolbar is accessible, revealing SQL queries, config, and request data.", Severity.HIGH),
    ("/console",         "console_exposed",  "Interactive Console Exposed",    "An interactive debug console is accessible, which can allow remote code execution.", Severity.CRITICAL),
    ("/debug",           "debug_endpoint",   "Debug Endpoint Exposed",         "A /debug endpoint is accessible without authentication.",                              Severity.HIGH),
    ("/_debug",          "debug_endpoint2",  "Debug Endpoint Exposed",         "A /_debug endpoint is accessible without authentication.",                             Severity.HIGH),
    ("/metrics",         "metrics_exposed",  "Metrics Endpoint Exposed Without Auth", "Prometheus/application metrics are accessible without authentication.",          Severity.MEDIUM),
    ("/health/detailed", "health_detailed",  "Detailed Health Endpoint Exposed","A detailed health endpoint exposes internal configuration or dependency status.",     Severity.LOW),
    ("/env",             "env_endpoint",     "Environment Variables Endpoint Exposed", "An /env endpoint may expose environment variables and secrets.",                Severity.HIGH),
    ("/.env",            "dotenv_exposed",   ".env File Accessible",           "The .env file is directly accessible from the web server.",                            Severity.CRITICAL),
    ("/config.json",     "config_json",      "Config File Accessible",         "A config.json file is directly accessible from the web server.",                       Severity.HIGH),
]

_ADMIN_PATHS: List[Tuple[str, str, str, str, Severity]] = [
    ("/admin",           "admin_exposed",    "Admin Interface Exposed",        "An admin interface is accessible without authentication check.",                        Severity.HIGH),
    ("/admin/",          "admin_exposed2",   "Admin Interface Exposed",        "An admin interface is accessible without authentication check.",                        Severity.HIGH),
    ("/wp-admin",        "wp_admin",         "WordPress Admin Exposed",        "A WordPress admin interface (/wp-admin) is accessible.",                                Severity.MEDIUM),
    ("/phpmyadmin",      "phpmyadmin",       "phpMyAdmin Exposed",             "phpMyAdmin is accessible without prior authentication gate.",                           Severity.HIGH),
]

# Patterns that signal verbose error disclosure in an error response body
_ERROR_PATTERNS = [
    ("Traceback (most recent call last)", "python_traceback"),
    ("at org.springframework",            "java_spring_trace"),
    ("java.lang.Exception",               "java_exception"),
    ("System.Exception",                  "dotnet_exception"),
    ("Warning: include(",                 "php_error"),
    ("mysql_fetch_array",                 "mysql_php_error"),
    ("ORA-",                              "oracle_error"),
]


def _is_success_or_partial(status: int) -> bool:
    return status in (200, 206)


def _looks_like_doc_response(response) -> bool:
    ct = response.headers.get("content-type", "")
    text = response.text or ""
    return (
        _is_success_or_partial(response.status_code)
        and (
            "application/json" in ct
            or "text/html" in ct
            or "swagger" in text.lower()
            or "openapi" in text.lower()
            or "redoc" in text.lower()
            or '"paths"' in text
            or '"openapi"' in text
        )
    )


@scanner_registry.register
class ApiSecurityScanner(BaseScanner):
    scanner_id = "api_security.endpoint_probe"
    name = "API Security Scanner"
    description = (
        "Probes a running local application for exposed API documentation, debug endpoints, "
        "admin interfaces, verbose error responses, and missing rate-limiting controls."
    )
    category = SecurityCategory.API_SECURITY
    requires_running_app = True
    cwe_ids = ["CWE-200", "CWE-284", "CWE-778", "CWE-209"]

    def can_scan(self, target: ScanTarget) -> bool:
        return (
            target.target_url is not None
            and is_local_target(target.target_url)
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        base = target.target_url.rstrip("/")

        # ----------------------------------------------------------------
        # 1. Exposed documentation
        # ----------------------------------------------------------------
        for path, rule_id, title, desc, severity in _DOC_PATHS:
            url = base + path
            try:
                resp = _fetch(url, timeout=6.0)
                if _looks_like_doc_response(resp):
                    findings.append(self._doc_finding(url, rule_id, title, desc, severity, resp))
            except DynamicScanError:
                pass

        # ----------------------------------------------------------------
        # 2. Debug and sensitive endpoints
        # ----------------------------------------------------------------
        for path, rule_id, title, desc, severity in _DEBUG_PATHS:
            url = base + path
            try:
                resp = _fetch(url, timeout=6.0)
                if _is_success_or_partial(resp.status_code):
                    findings.append(self._path_finding(url, rule_id, title, desc, severity, resp))
            except DynamicScanError:
                pass

        # ----------------------------------------------------------------
        # 3. Admin interfaces
        # ----------------------------------------------------------------
        for path, rule_id, title, desc, severity in _ADMIN_PATHS:
            url = base + path
            try:
                resp = _fetch(url, timeout=6.0)
                # 200 without redirect to login suggests unauthenticated access
                if _is_success_or_partial(resp.status_code):
                    findings.append(self._path_finding(url, rule_id, title, desc, severity, resp))
            except DynamicScanError:
                pass

        # ----------------------------------------------------------------
        # 4. Verbose error / stack trace disclosure
        # ----------------------------------------------------------------
        try:
            error_url = base + "/api/v1/nonexistent-endpoint-1234"
            resp = _fetch(error_url, timeout=6.0)
            for pattern, pattern_id in _ERROR_PATTERNS:
                if pattern in (resp.text or ""):
                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title="Verbose Error / Stack Trace Disclosure",
                        description=(
                            f"The application returns detailed error information in HTTP responses "
                            f"(detected: `{pattern}`). Observed on: {error_url}"
                        ),
                        category=SecurityCategory.DATA_EXPOSURE,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_endpoint=error_url,
                        cwe_id="CWE-209",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        impact=(
                            "Stack traces reveal internal paths, library versions, and application logic, "
                            "helping an attacker target specific known vulnerabilities."
                        ),
                        remediation=(
                            "Configure the application to return generic error pages in production. "
                            "Log detailed errors server-side only."
                        ),
                        evidence_data={
                            "type": "request_response",
                            "title": f"Error response — {error_url}",
                            "content": (resp.text or "")[:500],
                            "metadata": {
                                "url": error_url,
                                "rule_id": pattern_id,
                                "pattern": pattern,
                                "status": resp.status_code,
                            },
                        },
                    ))
                    break  # one finding per error probe
        except DynamicScanError:
            pass

        # ----------------------------------------------------------------
        # 5. Rate-limiting header absence (informational)
        # ----------------------------------------------------------------
        try:
            resp = _fetch(base + "/", timeout=6.0)
            rate_headers = {"x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit", "retry-after"}
            present = any(
                resp.headers.get(h) is not None for h in rate_headers
            )
            if not present:
                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title="No Rate-Limiting Headers Observed",
                    description=(
                        "The application root response does not include rate-limiting headers "
                        f"(X-RateLimit-Limit, etc.). Observed on: {base}/"
                    ),
                    category=SecurityCategory.API_SECURITY,
                    severity=Severity.LOW,
                    confidence=Confidence.POSSIBLE,
                    affected_endpoint=base + "/",
                    cwe_id="CWE-770",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    impact=(
                        "Without rate limiting, the API is susceptible to brute-force, "
                        "credential stuffing, and enumeration attacks."
                    ),
                    remediation=(
                        "Implement rate limiting (e.g. via a reverse proxy, API gateway, or middleware) "
                        "and surface limit information in response headers."
                    ),
                    evidence_data={
                        "type": "request_response",
                        "title": f"Root response headers — {base}/",
                        "content": f"No rate-limiting headers found in response from {base}/",
                        "metadata": {"url": base + "/", "rule_id": "no_rate_limit_headers"},
                    },
                ))
        except DynamicScanError:
            pass

        return findings

    def _doc_finding(self, url, rule_id, title, desc, severity, resp) -> RawFinding:
        preview = (resp.text or "")[:300]
        return RawFinding(
            scanner_id=self.scanner_id,
            title=title,
            description=f"{desc} Accessible at: {url}",
            category=SecurityCategory.API_SECURITY,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            affected_endpoint=url,
            cwe_id="CWE-200",
            owasp_category="A05:2021 – Security Misconfiguration",
            impact=(
                "Exposed API documentation reveals all endpoints, parameters, and data models, "
                "significantly lowering the bar for targeted attacks."
            ),
            remediation=(
                "Restrict API documentation endpoints to authenticated users or disable them entirely "
                "in production. Use network-level controls (VPN, IP allowlist) as an additional layer."
            ),
            evidence_data={
                "type": "request_response",
                "title": f"API doc response — {url}",
                "content": f"GET {url}\nHTTP {resp.status_code}\n\n{preview}",
                "metadata": {
                    "url": url,
                    "rule_id": rule_id,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                },
            },
        )

    def _path_finding(self, url, rule_id, title, desc, severity, resp) -> RawFinding:
        preview = (resp.text or "")[:300]
        return RawFinding(
            scanner_id=self.scanner_id,
            title=title,
            description=f"{desc} Accessible at: {url}",
            category=SecurityCategory.API_SECURITY,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            affected_endpoint=url,
            cwe_id="CWE-284",
            owasp_category="A05:2021 – Security Misconfiguration",
            impact=(
                "Unauthenticated access to privileged endpoints can lead to "
                "information disclosure, unauthorized configuration changes, or remote code execution."
            ),
            remediation=(
                "Require authentication before serving this endpoint. "
                "Consider removing it entirely in production deployments."
            ),
            evidence_data={
                "type": "request_response",
                "title": f"Sensitive endpoint response — {url}",
                "content": f"GET {url}\nHTTP {resp.status_code}\n\n{preview}",
                "metadata": {
                    "url": url,
                    "rule_id": rule_id,
                    "status": resp.status_code,
                },
            },
        )

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        return ValidationResult(
            is_valid=True,
            confidence=Confidence.CONFIRMED,
            notes="HTTP response directly observed.",
        )
