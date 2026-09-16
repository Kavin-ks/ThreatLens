"""Unit tests for the SecretsScanner."""
import pytest
from pathlib import Path

from scanners.secrets.secrets_scanner import SecretsScanner
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


@pytest.fixture()
def scanner():
    return SecretsScanner()


@pytest.fixture()
def target(tmp_path) -> ScanTarget:
    return ScanTarget(project_id="test-project", target_path=tmp_path)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("secrets.hardcoded_credentials")
    assert s is not None
    assert s.scanner_id == "secrets.hardcoded_credentials"


# ---------------------------------------------------------------------------
# can_scan
# ---------------------------------------------------------------------------

def test_can_scan_with_valid_directory(scanner, tmp_path):
    assert scanner.can_scan(ScanTarget("p", target_path=tmp_path)) is True


def test_can_scan_with_none_path(scanner):
    assert scanner.can_scan(ScanTarget("p", target_path=None)) is False


def test_can_scan_with_nonexistent_path(scanner, tmp_path):
    bad = tmp_path / "does_not_exist"
    assert scanner.can_scan(ScanTarget("p", target_path=bad)) is False


# ---------------------------------------------------------------------------
# Clean file — no findings
# ---------------------------------------------------------------------------

def test_no_findings_in_clean_file(scanner, tmp_path, target):
    (tmp_path / "app.py").write_text("import os\nDEBUG = os.getenv('DEBUG', 'false')\n")
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# AWS Access Key ID
# ---------------------------------------------------------------------------

def test_detects_aws_access_key(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scanner.scan(target)
    assert any("aws_access_key_id" in f.title.lower() or "aws" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# GitHub token
# ---------------------------------------------------------------------------

def test_detects_github_token(scanner, tmp_path, target):
    # Token needs 36+ alphanumeric chars after the prefix
    (tmp_path / "ci.py").write_text('TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"\n')
    findings = scanner.scan(target)
    assert any("github" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Hardcoded password
# ---------------------------------------------------------------------------

def test_detects_hardcoded_password(scanner, tmp_path, target):
    (tmp_path / "db.py").write_text('db_password = "s3cur3Passw0rd!"\n')
    findings = scanner.scan(target)
    assert len(findings) >= 1
    assert any("password" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Database URI with credentials
# ---------------------------------------------------------------------------

def test_detects_db_uri_credentials(scanner, tmp_path, target):
    (tmp_path / "config.yaml").write_text(
        'database_url: "postgresql://admin:MySuperSecret@db.local:5432/prod"\n'
    )
    findings = scanner.scan(target)
    assert any("credential" in f.title.lower() or "uri" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Placeholder values → POSSIBLE confidence
# ---------------------------------------------------------------------------

def test_placeholder_password_downgraded_to_possible(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text('password = "changeme"\n')
    findings = scanner.scan(target)
    assert len(findings) >= 1
    for f in findings:
        if "password" in f.title.lower():
            assert f.confidence == Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# Example file → POSSIBLE confidence
# ---------------------------------------------------------------------------

def test_example_file_downgraded_to_possible(scanner, tmp_path, target):
    (tmp_path / ".env.example").write_text('AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scanner.scan(target)
    for f in findings:
        assert f.confidence == Confidence.POSSIBLE, f"Expected POSSIBLE for .env.example finding, got {f.confidence}"


# ---------------------------------------------------------------------------
# Test context → POSSIBLE confidence
# ---------------------------------------------------------------------------

def test_test_file_confidence_downgraded(scanner, tmp_path, target):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    # Use a generic 30-char API key string that triggers the generic_api_key pattern
    # without matching any known credential format that would trip push protection
    (tests_dir / "fixtures.py").write_text('api_key = "FAKEKEYFORTESTINGABCDEFGHIJKLMNOP"\n')
    findings = scanner.scan(target)
    for f in findings:
        assert f.confidence == Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# Env-var lookups are NOT flagged
# ---------------------------------------------------------------------------

def test_env_var_lookup_not_flagged(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text(
        "import os\n"
        "password = os.environ.get('DB_PASSWORD')\n"
        "api_key = os.getenv('API_KEY')\n"
    )
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# Comment lines are NOT flagged
# ---------------------------------------------------------------------------

def test_comment_line_not_flagged(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text(
        "# password = 'hardcodedvalue'\n"
        "# api_key = 'AKIAIOSFODNN7EXAMPLE'\n"
    )
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# node_modules are skipped
# ---------------------------------------------------------------------------

def test_skips_node_modules(scanner, tmp_path, target):
    nm = tmp_path / "node_modules" / "somelib"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text('const password = "SuperSecret123"\n')
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# Evidence structure
# ---------------------------------------------------------------------------

def test_finding_has_evidence_data(scanner, tmp_path, target):
    (tmp_path / "app.py").write_text('password = "RealHardcoded!99"\n')
    findings = scanner.scan(target)
    assert len(findings) >= 1
    f = findings[0]
    assert f.evidence_data is not None
    assert f.evidence_data.get("type") == "code_snippet"
    assert "[REDACTED]" in f.evidence_data.get("content", "")


def test_finding_metadata(scanner, tmp_path, target):
    (tmp_path / "app.py").write_text('password = "RealHardcoded!99"\n')
    findings = scanner.scan(target)
    assert len(findings) >= 1
    f = findings[0]
    assert f.affected_file is not None
    assert f.affected_line is not None
    assert f.cwe_id is not None
