"""Unit tests for HttpSecurityScanner — all HTTP calls are mocked."""
import pytest
from unittest.mock import MagicMock, patch

from scanners.headers.http_security_scanner import HttpSecurityScanner
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


LOCAL_URL = "http://localhost:8000"
EXTERNAL_URL = "http://evil.example.com"


def _mock_resp(status=200, headers=None, text="<html>ok</html>"):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    return resp


@pytest.fixture()
def scanner():
    return HttpSecurityScanner()


@pytest.fixture()
def target():
    return ScanTarget(project_id="test-project", target_url=LOCAL_URL)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("headers.http_security")
    assert s is not None
    assert s.scanner_id == "headers.http_security"


# ---------------------------------------------------------------------------
# can_scan
# ---------------------------------------------------------------------------

def test_can_scan_local(scanner, target):
    assert scanner.can_scan(target) is True


def test_cannot_scan_external(scanner):
    t = ScanTarget(project_id="p", target_url=EXTERNAL_URL)
    assert scanner.can_scan(t) is False


def test_cannot_scan_no_url(scanner):
    t = ScanTarget(project_id="p")
    assert scanner.can_scan(t) is False


# ---------------------------------------------------------------------------
# Missing CSP header
# ---------------------------------------------------------------------------

def test_missing_csp_produces_finding(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        })
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)


# ---------------------------------------------------------------------------
# Missing HSTS header
# ---------------------------------------------------------------------------

def test_missing_hsts_on_https_produces_finding(scanner):
    t = ScanTarget(project_id="p", target_url="https://localhost:8443")
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "content-security-policy": "default-src 'self'",
        })
        findings = scanner.scan(t)

    titles = [f.title for f in findings]
    assert any("HSTS" in t or "Strict-Transport" in t for t in titles)


def test_hsts_not_flagged_on_http(scanner, target):
    """HSTS is only meaningful on HTTPS — should not fire on plain HTTP."""
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        })
        findings = scanner.scan(target)

    hsts_findings = [f for f in findings if "HSTS" in f.title or "Strict-Transport" in f.title]
    assert len(hsts_findings) == 0


# ---------------------------------------------------------------------------
# Missing X-Frame-Options
# ---------------------------------------------------------------------------

def test_missing_x_frame_options_produces_finding(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        })
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("X-Frame-Options" in t or "Clickjacking" in t for t in titles)


# ---------------------------------------------------------------------------
# Server version exposure
# ---------------------------------------------------------------------------

def test_server_version_disclosure(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "server": "nginx/1.18.0",
        })
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Server" in t or "Version" in t or "Disclosure" in t for t in titles)


def test_server_without_version_not_flagged(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(headers={
            "server": "nginx",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        })
        findings = scanner.scan(target)

    server_version_findings = [
        f for f in findings
        if "Server" in f.title and ("Version" in f.title or "Disclosure" in f.title)
    ]
    assert len(server_version_findings) == 0


# ---------------------------------------------------------------------------
# Cookie flags
# ---------------------------------------------------------------------------

def test_cookie_missing_httponly(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        resp = _mock_resp(headers={"set-cookie": "session=abc123; Path=/"})
        mock_fetch.return_value = resp
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("HttpOnly" in t or "Cookie" in t for t in titles)


def test_cookie_missing_samesite(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        resp = _mock_resp(headers={"set-cookie": "session=abc123; Path=/; HttpOnly"})
        mock_fetch.return_value = resp
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("SameSite" in t or "Cookie" in t for t in titles)


# ---------------------------------------------------------------------------
# CORS wildcard
# ---------------------------------------------------------------------------

def test_cors_wildcard_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if kwargs.get("method") == "OPTIONS":
            return _mock_resp(headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            })
        return _mock_resp(headers={})

    with patch("scanners.headers.http_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("CORS" in t for t in titles)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_validate_returns_confirmed(scanner, target):
    with patch("scanners.headers.http_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp()
        findings = scanner.scan(target)

    if findings:
        result = scanner.validate(findings[0], target)
        assert result.is_valid is True
        assert result.confidence == Confidence.CONFIRMED
