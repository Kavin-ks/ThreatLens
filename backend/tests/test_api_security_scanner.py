"""Unit tests for ApiSecurityScanner — all HTTP calls are mocked."""
import pytest
from unittest.mock import MagicMock, patch

from scanners.api_security.api_security_scanner import ApiSecurityScanner
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


LOCAL_URL = "http://localhost:8000"
EXTERNAL_URL = "http://evil.example.com"


def _mock_resp(status=200, headers=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    return resp


@pytest.fixture()
def scanner():
    return ApiSecurityScanner()


@pytest.fixture()
def target():
    return ScanTarget(project_id="test-project", target_url=LOCAL_URL)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("api_security.endpoint_probe")
    assert s is not None
    assert s.scanner_id == "api_security.endpoint_probe"


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
# Exposed API documentation
# ---------------------------------------------------------------------------

def test_exposed_openapi_json_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if "/openapi.json" in url:
            return _mock_resp(
                status=200,
                headers={"content-type": "application/json"},
                text='{"openapi": "3.0.0", "paths": {}}',
            )
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("OpenAPI" in t or "Documentation" in t or "Specification" in t for t in titles)


def test_exposed_swagger_ui_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if "/swagger-ui.html" in url:
            return _mock_resp(
                status=200,
                headers={"content-type": "text/html"},
                text="<html>swagger</html>",
            )
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Swagger" in t or "Documentation" in t for t in titles)


def test_no_docs_no_doc_finding(scanner, target):
    with patch("scanners.api_security.api_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=404)
        findings = scanner.scan(target)

    doc_findings = [
        f for f in findings
        if "OpenAPI" in f.title or "Swagger" in f.title or "Documentation" in f.title
    ]
    assert len(doc_findings) == 0


# ---------------------------------------------------------------------------
# Debug endpoints
# ---------------------------------------------------------------------------

def test_exposed_dotenv_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if "/.env" in url:
            return _mock_resp(
                status=200,
                headers={"content-type": "text/plain"},
                text="SECRET_KEY=abc123\nDATABASE_URL=postgres://...",
            )
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any(".env" in t or "Accessible" in t or "Exposed" in t for t in titles)


def test_exposed_debug_toolbar_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if "/__debug__/" in url:
            return _mock_resp(status=200, text="<html>Django Debug Toolbar</html>")
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Debug" in t or "Toolbar" in t for t in titles)


# ---------------------------------------------------------------------------
# Admin interfaces
# ---------------------------------------------------------------------------

def test_exposed_admin_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        if url.rstrip("/").endswith("/admin"):
            return _mock_resp(status=200, text="<html>Admin Panel</html>")
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Admin" in t for t in titles)


# ---------------------------------------------------------------------------
# Verbose error disclosure
# ---------------------------------------------------------------------------

def test_python_traceback_disclosure(scanner, target):
    def side_effect(url, **kwargs):
        if "nonexistent-endpoint" in url:
            return _mock_resp(
                status=500,
                text="Traceback (most recent call last):\n  File 'app.py', line 42",
            )
        return _mock_resp(status=404)

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Error" in t or "Traceback" in t or "Stack" in t for t in titles)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_no_rate_limit_headers_produces_finding(scanner, target):
    with patch("scanners.api_security.api_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=200, headers={})
        findings = scanner.scan(target)

    titles = [f.title for f in findings]
    assert any("Rate" in t for t in titles)


def test_rate_limit_header_present_no_finding(scanner, target):
    def side_effect(url, **kwargs):
        return _mock_resp(status=200, headers={"x-ratelimit-limit": "100"})

    with patch("scanners.api_security.api_security_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    rate_findings = [f for f in findings if "Rate" in f.title]
    assert len(rate_findings) == 0


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_validate_returns_confirmed(scanner, target):
    with patch("scanners.api_security.api_security_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=404)
        findings = scanner.scan(target)

    if findings:
        result = scanner.validate(findings[0], target)
        assert result.is_valid is True
        assert result.confidence == Confidence.CONFIRMED
