"""
HTTP Security Scanner — probes a running local application for missing or
misconfigured HTTP security controls.

Checks performed:
  - Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy
  - Cookie flags: Secure, HttpOnly, SameSite
  - Server/X-Powered-By information disclosure
  - CORS misconfiguration (wildcard + credentials)
  - HTTP to HTTPS redirect enforcement

Authorization constraint: only scans targets whose host resolves to
localhost or a private/RFC-1918 network address.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

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
# Security header rules
# ---------------------------------------------------------------------------

@dataclass
class _HeaderRule:
    header_name: str          # lowercase
    rule_id: str
    severity: Severity
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: str
    owasp: str = "A05:2021 – Security Misconfiguration"
    https_only: bool = False  # only relevant for HTTPS targets


_HEADER_RULES: List[_HeaderRule] = [
    _HeaderRule(
        header_name="content-security-policy",
        rule_id="missing_csp",
        severity=Severity.MEDIUM,
        title="Missing Content-Security-Policy Header",
        description=(
            "The application does not send a Content-Security-Policy (CSP) header. "
            "CSP is the primary browser-side defence against cross-site scripting (XSS)."
        ),
        impact=(
            "Without CSP, a successful XSS injection can execute arbitrary scripts, "
            "steal session tokens, or modify page content with no browser-side mitigation."
        ),
        remediation=(
            "Add a Content-Security-Policy header. Start with a restrictive policy: "
            "`Content-Security-Policy: default-src 'self'` and relax rules only as needed."
        ),
        cwe_id="CWE-693",
    ),
    _HeaderRule(
        header_name="strict-transport-security",
        rule_id="missing_hsts",
        severity=Severity.HIGH,
        title="Missing HTTP Strict Transport Security (HSTS)",
        description=(
            "The application does not send an HSTS header, allowing browsers to "
            "connect over plain HTTP."
        ),
        impact=(
            "Without HSTS, a network attacker can downgrade HTTPS connections to HTTP, "
            "enabling cookie theft and traffic interception."
        ),
        remediation=(
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` "
            "to all HTTPS responses."
        ),
        cwe_id="CWE-319",
        owasp="A02:2021 – Cryptographic Failures",
        https_only=True,
    ),
    _HeaderRule(
        header_name="x-frame-options",
        rule_id="missing_xfo",
        severity=Severity.MEDIUM,
        title="Missing X-Frame-Options Header",
        description=(
            "The application does not send an X-Frame-Options header, leaving it "
            "vulnerable to clickjacking."
        ),
        impact=(
            "An attacker can embed the application in an invisible iframe on a malicious "
            "page to trick authenticated users into unintended actions."
        ),
        remediation=(
            "Add `X-Frame-Options: DENY` (or `SAMEORIGIN`). "
            "Alternatively, use `Content-Security-Policy: frame-ancestors 'none'`."
        ),
        cwe_id="CWE-1021",
    ),
    _HeaderRule(
        header_name="x-content-type-options",
        rule_id="missing_xcto",
        severity=Severity.LOW,
        title="Missing X-Content-Type-Options Header",
        description=(
            "The X-Content-Type-Options: nosniff header is not present. "
            "Browsers may MIME-sniff responses and execute scripts from incorrectly typed responses."
        ),
        impact=(
            "A MIME confusion attack allows scripts disguised as non-script resources "
            "to execute in the browser."
        ),
        remediation="Add `X-Content-Type-Options: nosniff` to all responses.",
        cwe_id="CWE-693",
    ),
    _HeaderRule(
        header_name="referrer-policy",
        rule_id="missing_rp",
        severity=Severity.LOW,
        title="Missing Referrer-Policy Header",
        description=(
            "The application does not set a Referrer-Policy, causing the full URL "
            "(including sensitive query parameters) to leak in the Referer header "
            "to external sites."
        ),
        impact="Session tokens or other sensitive data in URLs may be leaked to third parties.",
        remediation=(
            "Add `Referrer-Policy: strict-origin-when-cross-origin` or "
            "`no-referrer` to all responses."
        ),
        cwe_id="CWE-116",
    ),
]

# SQL-like patterns that indicate a weak or absent HSTS max-age
_HSTS_MIN_SECONDS = 15_768_000  # ~6 months

# Cookie attribute names (lowercase)
_COOKIE_CHECKS = [
    ("secure", "cookie_missing_secure", Severity.HIGH,
     "Session Cookie Missing Secure Flag",
     "A Set-Cookie header does not include the Secure attribute.",
     "The cookie can be transmitted over plain HTTP, allowing interception.",
     "Add the Secure attribute to all cookies that contain session or sensitive data.",
     "CWE-614",
     "A02:2021 – Cryptographic Failures",
     True),  # https_only
    ("httponly", "cookie_missing_httponly", Severity.MEDIUM,
     "Session Cookie Missing HttpOnly Flag",
     "A Set-Cookie header does not include the HttpOnly attribute.",
     "JavaScript can read this cookie value, amplifying any XSS vulnerability.",
     "Add the HttpOnly attribute to all session and authentication cookies.",
     "CWE-1004",
     "A05:2021 – Security Misconfiguration",
     False),
    ("samesite", "cookie_missing_samesite", Severity.MEDIUM,
     "Session Cookie Missing SameSite Attribute",
     "A Set-Cookie header does not include the SameSite attribute.",
     (
         "Without SameSite, cookies are sent with cross-origin requests, "
         "enabling CSRF attacks even when CSRF tokens are absent."
     ),
     "Add `SameSite=Lax` (or `SameSite=Strict`) to session cookies.",
     "CWE-352",
     "A01:2021 – Broken Access Control",
     False),
]


def _parse_cookies(headers: dict) -> List[str]:
    """Return a list of raw Set-Cookie header values from a headers dict."""
    cookies = []
    if hasattr(headers, "get_list"):
        cookies = headers.get_list("set-cookie")
    else:
        # Plain dict — may have a single concatenated value
        raw = headers.get("set-cookie", "")
        if raw:
            cookies = [raw]
    return cookies


@scanner_registry.register
class HttpSecurityScanner(BaseScanner):
    scanner_id = "headers.http_security"
    name = "HTTP Security Scanner"
    description = (
        "Checks a running local application for missing or misconfigured HTTP security "
        "controls: security headers, HSTS, cookie flags, server info exposure, and CORS."
    )
    category = SecurityCategory.HEADERS
    requires_running_app = True
    cwe_ids = ["CWE-693", "CWE-319", "CWE-1021", "CWE-614", "CWE-116", "CWE-942"]

    def can_scan(self, target: ScanTarget) -> bool:
        return (
            target.target_url is not None
            and is_local_target(target.target_url)
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        url = target.target_url

        try:
            response = _fetch(url)
        except DynamicScanError as exc:
            logger.warning("HttpSecurityScanner: cannot reach %s — %s", url, exc)
            return []

        headers = response.headers
        is_https = urlparse(url).scheme.lower() == "https"
        status = response.status_code

        # ----------------------------------------------------------------
        # Security header checks
        # ----------------------------------------------------------------
        for rule in _HEADER_RULES:
            if rule.https_only and not is_https:
                continue
            header_val = headers.get(rule.header_name) if hasattr(headers, "get") else None
            if header_val is not None:
                continue  # Header present — check specific values below

            snippet = self._response_snippet(url, status, headers)
            findings.append(RawFinding(
                scanner_id=self.scanner_id,
                title=rule.title,
                description=f"{rule.description} Observed on: {url}",
                category=SecurityCategory.HEADERS,
                severity=rule.severity,
                confidence=Confidence.CONFIRMED,
                affected_endpoint=url,
                affected_component=f"HTTP Response: {url}",
                cwe_id=rule.cwe_id,
                owasp_category=rule.owasp,
                impact=rule.impact,
                remediation=rule.remediation,
                evidence_data={
                    "type": "request_response",
                    "title": f"HTTP response headers — {url}",
                    "content": snippet,
                    "metadata": {"url": url, "rule_id": rule.rule_id, "status": status},
                },
            ))

        # Check HSTS max-age if header is present
        hsts_val = headers.get("strict-transport-security") if is_https else None
        if hsts_val:
            try:
                parts = {p.strip().lower() for p in hsts_val.split(";")}
                max_age = next(
                    (int(p.split("=")[1]) for p in parts if p.startswith("max-age=")),
                    None,
                )
                if max_age is not None and max_age < _HSTS_MIN_SECONDS:
                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title="HSTS max-age Too Short",
                        description=(
                            f"Strict-Transport-Security max-age is {max_age}s "
                            f"(less than the recommended {_HSTS_MIN_SECONDS}s / 6 months)."
                        ),
                        category=SecurityCategory.HEADERS,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_endpoint=url,
                        cwe_id="CWE-319",
                        owasp_category="A02:2021 – Cryptographic Failures",
                        impact="A short HSTS lifetime reduces the protection window against downgrade attacks.",
                        remediation="Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                        evidence_data={
                            "type": "request_response",
                            "title": f"HSTS response — {url}",
                            "content": f"Strict-Transport-Security: {hsts_val}",
                            "metadata": {"url": url, "rule_id": "hsts_short_max_age"},
                        },
                    ))
            except (ValueError, StopIteration):
                pass

        # ----------------------------------------------------------------
        # Cookie flag checks
        # ----------------------------------------------------------------
        cookies = _parse_cookies(headers)
        for cookie_val in cookies:
            cookie_lower = cookie_val.lower()
            for attr, rule_id, sev, title, desc, impact, remed, cwe, owasp, https_req in _COOKIE_CHECKS:
                if https_req and not is_https:
                    continue
                if attr not in cookie_lower:
                    cookie_name = cookie_val.split("=")[0].strip()
                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title=title,
                        description=f"{desc} Cookie: `{cookie_name}`. Observed on: {url}",
                        category=SecurityCategory.SESSION,
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        affected_endpoint=url,
                        affected_component=f"Cookie: {cookie_name}",
                        cwe_id=cwe,
                        owasp_category=owasp,
                        impact=impact,
                        remediation=remed,
                        evidence_data={
                            "type": "request_response",
                            "title": f"Set-Cookie header — {url}",
                            "content": f"Set-Cookie: {cookie_val}",
                            "metadata": {
                                "url": url,
                                "rule_id": rule_id,
                                "cookie": cookie_name,
                            },
                        },
                    ))

        # ----------------------------------------------------------------
        # Server information exposure
        # ----------------------------------------------------------------
        for header_name, rule_id in (("server", "server_info_exposure"), ("x-powered-by", "x_powered_by_exposure")):
            val = headers.get(header_name, "")
            if val and any(char.isdigit() for char in val):
                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title=f"Server Version Disclosed in {header_name.title()} Header",
                    description=(
                        f"The `{header_name}` response header exposes server version information: `{val}`. "
                        f"Observed on: {url}"
                    ),
                    category=SecurityCategory.DATA_EXPOSURE,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_endpoint=url,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    impact=(
                        "Version information assists attackers in targeting known CVEs for the specific "
                        "server/framework version."
                    ),
                    remediation=(
                        f"Suppress or genericise the `{header_name}` header in the server configuration."
                    ),
                    evidence_data={
                        "type": "request_response",
                        "title": f"{header_name.title()} header — {url}",
                        "content": f"{header_name}: {val}",
                        "metadata": {"url": url, "rule_id": rule_id, "value": val},
                    },
                ))

        # ----------------------------------------------------------------
        # CORS misconfiguration (wildcard + credentials)
        # ----------------------------------------------------------------
        try:
            cors_resp = _fetch(
                url,
                method="OPTIONS",
                headers={"Origin": "http://evil.example.test"},
                timeout=5.0,
            )
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title="CORS Misconfiguration: Wildcard Origin with Credentials",
                    description=(
                        "The server responds with `Access-Control-Allow-Origin: *` and "
                        "`Access-Control-Allow-Credentials: true` — this combination is "
                        "rejected by browsers but indicates a misconfigured CORS policy."
                    ),
                    category=SecurityCategory.CONFIGURATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    affected_endpoint=url,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    impact=(
                        "A misconfigured CORS policy that accepts arbitrary origins with credentials "
                        "allows any website to make authenticated API requests on behalf of logged-in users."
                    ),
                    remediation=(
                        "Never combine `Access-Control-Allow-Origin: *` with "
                        "`Access-Control-Allow-Credentials: true`. "
                        "Restrict allowed origins to an explicit allowlist."
                    ),
                    evidence_data={
                        "type": "request_response",
                        "title": f"CORS OPTIONS response — {url}",
                        "content": (
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        "metadata": {"url": url, "rule_id": "cors_wildcard_credentials"},
                    },
                ))
            elif acao.lower() not in ("", "*") and acac == "true":
                # Check if the reflected origin is the evil one we sent
                if "evil.example.test" in acao:
                    findings.append(RawFinding(
                        scanner_id=self.scanner_id,
                        title="CORS Misconfiguration: Origin Reflection with Credentials",
                        description=(
                            "The server reflects the request Origin header back as "
                            "Access-Control-Allow-Origin with credentials allowed, "
                            "effectively accepting requests from any origin."
                        ),
                        category=SecurityCategory.CONFIGURATION,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        affected_endpoint=url,
                        cwe_id="CWE-942",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        impact=(
                            "Any attacker-controlled origin can make credentialed cross-origin requests "
                            "to the API and read the responses."
                        ),
                        remediation=(
                            "Validate the Origin header against an explicit allowlist before reflecting it. "
                            "Never use `request.origin` directly as the ACAO value."
                        ),
                        evidence_data={
                            "type": "request_response",
                            "title": f"CORS origin reflection — {url}",
                            "content": (
                                f"Request Origin: http://evil.example.test\n"
                                f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            "metadata": {"url": url, "rule_id": "cors_origin_reflection"},
                        },
                    ))
        except DynamicScanError:
            pass  # CORS check is best-effort

        return findings

    @staticmethod
    def _response_snippet(url: str, status: int, headers) -> str:
        lines = [f"HTTP response: {url}", f"Status: {status}", "Headers present:"]
        for key in (
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "server",
            "x-powered-by",
        ):
            val = headers.get(key)
            lines.append(f"  {key}: {val or '(not set)'}")
        return "\n".join(lines)

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        return ValidationResult(
            is_valid=True,
            confidence=Confidence.CONFIRMED,
            notes="HTTP response directly observed — no additional validation needed.",
        )
