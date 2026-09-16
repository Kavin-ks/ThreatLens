"""Unit tests for SqlInjectionScanner and CommandInjectionScanner."""
import pytest
from unittest.mock import MagicMock, patch

from scanners.injection.injection_scanner import (
    SqlInjectionScanner,
    CommandInjectionScanner,
    _build_url_with_param,
)
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
def sql_scanner():
    return SqlInjectionScanner()


@pytest.fixture()
def cmd_scanner():
    return CommandInjectionScanner()


@pytest.fixture()
def target():
    return ScanTarget(project_id="test-project", target_url=LOCAL_URL)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_sql_scanner_registered():
    s = scanner_registry.get("injection.sql_error_based")
    assert s is not None
    assert s.scanner_id == "injection.sql_error_based"


def test_cmd_scanner_registered():
    s = scanner_registry.get("injection.command_error_based")
    assert s is not None
    assert s.scanner_id == "injection.command_error_based"


# ---------------------------------------------------------------------------
# Helper: _build_url_with_param
# ---------------------------------------------------------------------------

def test_build_url_adds_new_param():
    url = _build_url_with_param("http://localhost:8000/search", "q", "test")
    assert "q=test" in url


def test_build_url_preserves_existing_params():
    url = _build_url_with_param("http://localhost:8000/search?page=2", "q", "test")
    assert "page=2" in url
    assert "q=test" in url


def test_build_url_replaces_existing_param():
    url = _build_url_with_param("http://localhost:8000/search?q=original", "q", "injected")
    assert "injected" in url


# ---------------------------------------------------------------------------
# can_scan
# ---------------------------------------------------------------------------

def test_sql_can_scan_local(sql_scanner, target):
    assert sql_scanner.can_scan(target) is True


def test_sql_cannot_scan_external(sql_scanner):
    t = ScanTarget(project_id="p", target_url=EXTERNAL_URL)
    assert sql_scanner.can_scan(t) is False


def test_sql_cannot_scan_no_url(sql_scanner):
    t = ScanTarget(project_id="p")
    assert sql_scanner.can_scan(t) is False


def test_cmd_can_scan_local(cmd_scanner, target):
    assert cmd_scanner.can_scan(target) is True


def test_cmd_cannot_scan_external(cmd_scanner):
    t = ScanTarget(project_id="p", target_url=EXTERNAL_URL)
    assert cmd_scanner.can_scan(t) is False


def test_cmd_cannot_scan_no_url(cmd_scanner):
    t = ScanTarget(project_id="p")
    assert cmd_scanner.can_scan(t) is False


# ---------------------------------------------------------------------------
# SQL injection — error detection
# ---------------------------------------------------------------------------

def test_mysql_error_produces_finding(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="You have an error in your SQL syntax near '' at line 1"
        )
        findings = sql_scanner.scan(target)

    assert len(findings) >= 1
    assert any("SQL" in f.title or "Injection" in f.title for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_postgresql_error_produces_finding(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="ERROR:  syntax error at or near \"'\""
        )
        findings = sql_scanner.scan(target)

    assert len(findings) >= 1


def test_sqlite_error_produces_finding(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="sqlite3.OperationalError: unrecognized token"
        )
        findings = sql_scanner.scan(target)

    assert len(findings) >= 1


def test_oracle_error_produces_finding(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(text="ORA-00907: missing right parenthesis")
        findings = sql_scanner.scan(target)

    assert len(findings) >= 1


def test_clean_response_no_sql_finding(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="<html><body>Search results: 0 items</body></html>"
        )
        findings = sql_scanner.scan(target)

    assert len(findings) == 0


def test_sql_finding_confidence_is_likely(sql_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="You have an error in your SQL syntax"
        )
        findings = sql_scanner.scan(target)

    assert all(f.confidence == Confidence.LIKELY for f in findings)


def test_sql_existing_url_params_probed(sql_scanner):
    t = ScanTarget(project_id="p", target_url="http://localhost:8000/items?id=5")
    probed_params = []

    def side_effect(url, **kwargs):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        probed_params.extend(params.keys())
        return _mock_resp(text="clean")

    with patch("scanners.injection.injection_scanner._fetch", side_effect=side_effect):
        sql_scanner.scan(t)

    assert "id" in probed_params


# ---------------------------------------------------------------------------
# Command injection — error detection
# ---------------------------------------------------------------------------

def test_command_not_found_produces_finding(cmd_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="/bin/sh: 1: invalid_cmd_notexist_threatlens: not found"
        )
        findings = cmd_scanner.scan(target)

    assert len(findings) >= 1
    assert any("Command" in f.title or "Injection" in f.title or "Shell" in f.title for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_windows_command_error_produces_finding(cmd_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="'invalid_cmd_notexist_threatlens' is not recognized as an internal or external command"
        )
        findings = cmd_scanner.scan(target)

    assert len(findings) >= 1


def test_bash_not_found_produces_finding(cmd_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="bash: invalid_cmd_notexist_threatlens: not found"
        )
        findings = cmd_scanner.scan(target)

    assert len(findings) >= 1


def test_clean_response_no_cmd_finding(cmd_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="<html><body>OK</body></html>"
        )
        findings = cmd_scanner.scan(target)

    assert len(findings) == 0


def test_cmd_finding_confidence_is_likely(cmd_scanner, target):
    with patch("scanners.injection.injection_scanner._fetch") as mock_fetch:
        mock_fetch.return_value = _mock_resp(
            text="command not found: invalid_cmd_notexist_threatlens"
        )
        findings = cmd_scanner.scan(target)

    assert all(f.confidence == Confidence.LIKELY for f in findings)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_sql_validate_returns_likely(sql_scanner, target):
    from scanners.models import RawFinding, SecurityCategory, Severity, Confidence
    finding = RawFinding(
        scanner_id="injection.sql_error_based",
        title="SQL Injection — Database Error Disclosed",
        description="test",
        category=SecurityCategory.INJECTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.LIKELY,
        affected_endpoint="http://localhost:8000",
    )
    result = sql_scanner.validate(finding, target)
    assert result.is_valid is True
    assert result.confidence == Confidence.LIKELY


def test_cmd_validate_returns_likely(cmd_scanner, target):
    from scanners.models import RawFinding, SecurityCategory, Severity, Confidence
    finding = RawFinding(
        scanner_id="injection.command_error_based",
        title="Command Injection — Shell Error Disclosed",
        description="test",
        category=SecurityCategory.INJECTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.LIKELY,
        affected_endpoint="http://localhost:8000",
    )
    result = cmd_scanner.validate(finding, target)
    assert result.is_valid is True
    assert result.confidence == Confidence.LIKELY
