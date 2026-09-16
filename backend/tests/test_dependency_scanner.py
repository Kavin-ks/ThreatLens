"""Unit tests for PythonDependencyScanner and NodeDependencyScanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

from scanners.dependencies.dependency_scanner import (
    PythonDependencyScanner,
    NodeDependencyScanner,
)
from scanners.models import ScanTarget, Severity, Confidence
from scanners.registry import scanner_registry


@pytest.fixture()
def py_scanner():
    return PythonDependencyScanner()


@pytest.fixture()
def node_scanner():
    return NodeDependencyScanner()


@pytest.fixture()
def target_with_requirements(tmp_path) -> ScanTarget:
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask==1.0.2\n")
    return ScanTarget(project_id="test-project", target_path=tmp_path)


@pytest.fixture()
def target_with_package_json(tmp_path) -> ScanTarget:
    pkg = {"name": "test-app", "dependencies": {"lodash": "4.17.15"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "package-lock.json").write_text("{}")
    return ScanTarget(project_id="test-project", target_path=tmp_path)


@pytest.fixture()
def empty_target(tmp_path) -> ScanTarget:
    return ScanTarget(project_id="test-project", target_path=tmp_path)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_python_scanner_registered():
    assert scanner_registry.get("dependencies.python_packages") is not None


def test_node_scanner_registered():
    assert scanner_registry.get("dependencies.node_packages") is not None


# ---------------------------------------------------------------------------
# can_scan — Python
# ---------------------------------------------------------------------------

def test_python_can_scan_with_requirements(py_scanner, target_with_requirements):
    assert py_scanner.can_scan(target_with_requirements) is True


def test_python_cannot_scan_empty_directory(py_scanner, empty_target):
    assert py_scanner.can_scan(empty_target) is False


def test_python_cannot_scan_without_path(py_scanner):
    assert py_scanner.can_scan(ScanTarget("p", target_path=None)) is False


def test_python_can_scan_with_pyproject(py_scanner, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.poetry]\nname='test'\n")
    assert py_scanner.can_scan(ScanTarget("p", target_path=tmp_path)) is True


# ---------------------------------------------------------------------------
# can_scan — Node.js
# ---------------------------------------------------------------------------

def test_node_can_scan_with_package_json(node_scanner, target_with_package_json):
    assert node_scanner.can_scan(target_with_package_json) is True


def test_node_cannot_scan_empty_directory(node_scanner, empty_target):
    assert node_scanner.can_scan(empty_target) is False


# ---------------------------------------------------------------------------
# pip-audit not available → INFO finding
# ---------------------------------------------------------------------------

def test_python_pip_audit_not_available(py_scanner, target_with_requirements):
    with patch("shutil.which", return_value=None):
        findings = py_scanner.scan(target_with_requirements)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "pip-audit" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# npm not available → INFO finding
# ---------------------------------------------------------------------------

def test_node_npm_not_available(node_scanner, target_with_package_json):
    with patch("shutil.which", return_value=None):
        findings = node_scanner.scan(target_with_package_json)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "npm" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# pip-audit output parsing
# ---------------------------------------------------------------------------

_PIP_AUDIT_VULN_OUTPUT = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.25.0",
            "vulns": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "description": "Certificate verification bypass via SSRF",
                    "fix_versions": ["2.31.0"],
                    "aliases": ["CVE-2023-32681"],
                }
            ],
        },
        {
            "name": "flask",
            "version": "1.0.2",
            "vulns": [],  # no vulns
        },
    ]
})


def test_python_parses_pip_audit_output(py_scanner, target_with_requirements):
    mock_result = MagicMock()
    mock_result.stdout = _PIP_AUDIT_VULN_OUTPUT
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/pip-audit"), \
         patch("subprocess.run", return_value=mock_result):
        findings = py_scanner.scan(target_with_requirements)

    assert len(findings) == 1
    f = findings[0]
    assert "requests" in f.title
    assert "2.25.0" in f.title
    assert "GHSA-j8r2-6x86-q33q" in f.title
    assert f.confidence == Confidence.CONFIRMED
    assert f.evidence_data is not None
    assert f.evidence_data.get("type") == "dependency_record"


def test_python_no_findings_when_no_vulns(py_scanner, target_with_requirements):
    clean_output = json.dumps({
        "dependencies": [{"name": "requests", "version": "2.31.0", "vulns": []}]
    })
    mock_result = MagicMock()
    mock_result.stdout = clean_output
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/pip-audit"), \
         patch("subprocess.run", return_value=mock_result):
        findings = py_scanner.scan(target_with_requirements)

    assert findings == []


def test_python_handles_invalid_json_gracefully(py_scanner, target_with_requirements):
    mock_result = MagicMock()
    mock_result.stdout = "not valid json at all"
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/pip-audit"), \
         patch("subprocess.run", return_value=mock_result):
        findings = py_scanner.scan(target_with_requirements)

    assert findings == []


# ---------------------------------------------------------------------------
# npm audit output parsing
# ---------------------------------------------------------------------------

_NPM_AUDIT_OUTPUT = json.dumps({
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "isDirect": True,
            "via": [
                {
                    "source": 1096820,
                    "name": "lodash",
                    "dependency": "lodash",
                    "title": "Prototype Pollution in lodash",
                    "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                    "severity": "high",
                    "cwe": ["CWE-1321"],
                    "range": "<4.17.21",
                }
            ],
            "effects": [],
            "range": "<4.17.21",
            "nodes": ["node_modules/lodash"],
            "fixAvailable": True,
        }
    },
    "metadata": {"vulnerabilities": {"total": 1}},
})


def test_node_parses_npm_audit_output(node_scanner, target_with_package_json):
    mock_result = MagicMock()
    mock_result.stdout = _NPM_AUDIT_OUTPUT
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/npm"), \
         patch("subprocess.run", return_value=mock_result):
        findings = node_scanner.scan(target_with_package_json)

    assert len(findings) == 1
    f = findings[0]
    assert "lodash" in f.title
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "npm audit fix" in (f.remediation or "")


def test_node_empty_vulnerabilities(node_scanner, target_with_package_json):
    clean_output = json.dumps({"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}})
    mock_result = MagicMock()
    mock_result.stdout = clean_output
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/npm"), \
         patch("subprocess.run", return_value=mock_result):
        findings = node_scanner.scan(target_with_package_json)

    assert findings == []


def test_node_handles_invalid_json_gracefully(node_scanner, target_with_package_json):
    mock_result = MagicMock()
    mock_result.stdout = "not valid json"
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/npm"), \
         patch("subprocess.run", return_value=mock_result):
        findings = node_scanner.scan(target_with_package_json)

    assert findings == []
