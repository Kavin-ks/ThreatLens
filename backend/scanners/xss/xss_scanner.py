"""
Reflected XSS Scanner — probes URL parameters of a running local application
for reflected cross-site scripting vulnerabilities.

Approach:
  1. Extract query parameters from the target URL (if any).
  2. Augment with a list of commonly-used parameter names.
  3. Inject a benign HTML probe that should be entity-encoded by a safe app.
  4. Confirm: probe appears verbatim (unencoded) in the response body.

Scope: reflected XSS only — no DOM-based or stored XSS detection.
Payload policy: probe strings do not contain `<script>` or event handlers;
  they are designed to reveal missing output encoding, not to execute.

Authorization constraint: only scans targets whose host resolves to
localhost or a private/RFC-1918 network address.
"""
from __future__ import annotations

import logging
import secrets
from typing import List
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


# Common parameter names to probe when the URL has no query string
_COMMON_PARAMS = [
    "q", "search", "s", "query", "term",
    "id", "name", "input", "data", "text",
    "value", "page", "ref", "url", "redirect",
]

# Probe characters that MUST be HTML-entity-encoded in safe applications.
# Using a distinctive marker avoids collision with legitimate page content.
_PROBE_MARKER = "thrtelens"  # not a typo — intentionally distinct


def _make_probe(suffix: str) -> str:
    """
    Return a probe string that is distinctive and will reveal missing
    HTML encoding if reflected back unaltered.
    The angle brackets MUST be encoded as &lt; / &gt; in a safe application.
    """
    return f"<{_PROBE_MARKER}-xss-{suffix}>"


def _probe_is_reflected(probe: str, response_text: str) -> bool:
    """
    Return True if the probe appears verbatim (unencoded) in the response.
    We look for the literal angle-bracket form — not the entity-encoded form.
    """
    return probe in response_text


@scanner_registry.register
class ReflectedXssScanner(BaseScanner):
    scanner_id = "xss.reflected"
    name = "Reflected XSS Scanner"
    description = (
        "Probes URL parameters for reflected XSS by injecting a benign HTML marker "
        "and checking whether the response contains it unencoded. "
        "Scope: reflected XSS only. No script execution probes are used."
    )
    category = SecurityCategory.XSS
    requires_running_app = True
    cwe_ids = ["CWE-79"]

    def can_scan(self, target: ScanTarget) -> bool:
        return (
            target.target_url is not None
            and is_local_target(target.target_url)
        )

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        url = target.target_url
        parsed = urlparse(url)

        # Collect parameter names to probe
        existing_params = list(parse_qs(parsed.query).keys())
        params_to_probe = list(dict.fromkeys(existing_params + _COMMON_PARAMS))

        nonce = secrets.token_hex(4)

        for param in params_to_probe:
            probe = _make_probe(f"{nonce}-{param}")
            probe_url = _build_url_with_param(url, param, probe)

            try:
                resp = _fetch(probe_url, timeout=8.0)
            except DynamicScanError as exc:
                logger.debug("XSS probe failed for %s: %s", probe_url, exc)
                continue

            if resp.status_code >= 500:
                continue

            body = resp.text or ""
            if _probe_is_reflected(probe, body):
                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title="Reflected XSS — Unencoded Output",
                    description=(
                        f"Parameter `{param}` reflects user input without HTML encoding. "
                        f"The probe `{probe}` appeared verbatim in the HTTP response body. "
                        f"Endpoint: {probe_url}"
                    ),
                    category=SecurityCategory.XSS,
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    affected_endpoint=probe_url,
                    affected_component=f"Parameter: {param}",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 – Injection",
                    impact=(
                        "Reflected XSS allows an attacker to craft a malicious URL that, when "
                        "visited by an authenticated user, executes arbitrary JavaScript in their "
                        "browser — enabling session hijacking, credential theft, or UI redressing."
                    ),
                    remediation=(
                        "HTML-encode all user-controlled values before rendering them in HTML responses. "
                        "Use a templating engine that auto-escapes output (e.g. Jinja2 with `autoescape=True`, "
                        "React JSX). Apply a strict Content-Security-Policy as a defence-in-depth layer."
                    ),
                    evidence_data={
                        "type": "request_response",
                        "title": f"Reflected probe — {param} @ {url}",
                        "content": (
                            f"Probe URL: {probe_url}\n"
                            f"Probe value: {probe}\n"
                            f"HTTP Status: {resp.status_code}\n"
                            f"Reflected verbatim in response: YES\n"
                            f"Response snippet (first 500 chars):\n{body[:500]}"
                        ),
                        "metadata": {
                            "url": probe_url,
                            "parameter": param,
                            "probe": probe,
                            "reflected": True,
                        },
                    },
                ))
                # Move on to the next parameter once we confirm one reflection
                continue

        return findings

    def validate(self, finding: RawFinding, target: ScanTarget) -> ValidationResult:
        # Probe reflection was directly observed — no further steps needed
        return ValidationResult(
            is_valid=True,
            confidence=Confidence.LIKELY,
            notes=(
                "Probe string reflected verbatim. Manual verification recommended "
                "to confirm full XSS exploitability."
            ),
        )


def _build_url_with_param(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [value]
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
