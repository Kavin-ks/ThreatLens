"""Unit tests for ReflectedXssScanner — all HTTP calls are mocked."""
import pytest
from unittest.mock import MagicMock, patch

from scanners.xss.xss_scanner import ReflectedXssScanner, _make_probe, _probe_is_reflected
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


LOCAL_URL = "http://localhost:8000"
EXTERNAL_URL = "http://evil.example.com"


def _mock_resp(status=200, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {}
    resp.text = text
    return resp


@pytest.fixture()
def scanner():
    return ReflectedXssScanner()


@pytest.fixture()
def target():
    return ScanTarget(project_id="test-project", target_url=LOCAL_URL)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("xss.reflected")
    assert s is not None
    assert s.scanner_id == "xss.reflected"


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

def test_make_probe_contains_marker():
    probe = _make_probe("test-suffix")
    assert "thrtelens" in probe
    assert "<" in probe and ">" in probe


def test_probe_is_reflected_true():
    probe = _make_probe("abc")
    assert _probe_is_reflected(probe, f"<html>{probe}</html>") is True


def test_probe_is_reflected_false_when_encoded():
    probe = _make_probe("abc")
    encoded = probe.replace("<", "&lt;").replace(">", "&gt;")
    assert _probe_is_reflected(probe, f"<html>{encoded}</html>") is False


def test_probe_is_reflected_false_on_unrelated_content():
    probe = _make_probe("abc")
    assert _probe_is_reflected(probe, "<html>clean page</html>") is False


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
# Reflected probe detection
# ---------------------------------------------------------------------------

def test_reflected_probe_produces_finding(scanner, target):
    def side_effect(url, **kwargs):
        # Return the probe value verbatim in the response body
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Find the probe value from any parameter
        for vals in params.values():
            for v in vals:
                if "thrtelens" in v:
                    return _mock_resp(status=200, text=f"<html>You searched for: {v}</html>")
        return _mock_resp(status=200, text="<html>no reflection</html>")

    with patch("scanners.xss.xss_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    assert len(findings) >= 1
    assert any("XSS" in f.title or "Reflected" in f.title for f in findings)


def test_no_finding_when_probe_encoded(scanner, target):
    def side_effect(url, **kwargs):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for vals in params.values():
            for v in vals:
                if "thrtelens" in v:
                    encoded = v.replace("<", "&lt;").replace(">", "&gt;")
                    return _mock_resp(status=200, text=f"<html>You searched for: {encoded}</html>")
        return _mock_resp(status=200, text="<html>no reflection</html>")

    with patch("scanners.xss.xss_scanner._fetch", side_effect=side_effect):
        findings = scanner.scan(target)

    assert len(findings) == 0


def test_no_finding_on_500_response(scanner, target):
    """Scanner must skip 500 responses to avoid false positives from crash dumps."""
    with patch("scanners.xss.xss_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=500, text="Internal server error")
        findings = scanner.scan(target)

    assert len(findings) == 0


def test_no_finding_on_clean_page(scanner, target):
    with patch("scanners.xss.xss_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=200, text="<html>clean</html>")
        findings = scanner.scan(target)

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Existing URL params are also probed
# ---------------------------------------------------------------------------

def test_existing_url_param_probed(scanner):
    t = ScanTarget(project_id="p", target_url="http://localhost:8000/search?query=hello")
    probed_params = []

    def side_effect(url, **kwargs):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        probed_params.extend(params.keys())
        return _mock_resp(status=200, text="<html>clean</html>")

    with patch("scanners.xss.xss_scanner._fetch", side_effect=side_effect):
        scanner.scan(t)

    assert "query" in probed_params


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_validate_returns_likely(scanner, target):
    with patch("scanners.xss.xss_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(status=200, text="<html>clean</html>")
        findings = scanner.scan(target)

    if not findings:
        # Manually confirm the validate signature by creating a dummy finding
        from scanners.models import RawFinding, SecurityCategory, Severity, Confidence
        finding = RawFinding(
            scanner_id="xss.reflected",
            title="Reflected XSS — Unencoded Output",
            description="test",
            category=SecurityCategory.XSS,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            affected_endpoint="http://localhost:8000",
        )
        result = scanner.validate(finding, target)
    else:
        result = scanner.validate(findings[0], target)

    assert result.is_valid is True
    assert result.confidence == Confidence.LIKELY
