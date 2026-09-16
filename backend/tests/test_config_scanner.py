"""Unit tests for the ConfigurationScanner."""
import pytest

from scanners.configuration.config_scanner import ConfigurationScanner
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


@pytest.fixture()
def scanner():
    return ConfigurationScanner()


@pytest.fixture()
def target(tmp_path) -> ScanTarget:
    return ScanTarget(project_id="test-project", target_path=tmp_path)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("configuration.security_misconfig")
    assert s is not None


# ---------------------------------------------------------------------------
# can_scan
# ---------------------------------------------------------------------------

def test_can_scan_with_directory(scanner, tmp_path):
    assert scanner.can_scan(ScanTarget("p", target_path=tmp_path)) is True


def test_cannot_scan_without_path(scanner):
    assert scanner.can_scan(ScanTarget("p", target_path=None)) is False


# ---------------------------------------------------------------------------
# Clean file — no findings
# ---------------------------------------------------------------------------

def test_no_findings_in_clean_file(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text(
        "import os\n"
        "DEBUG = os.getenv('DEBUG', 'False') == 'True'\n"
        "SESSION_COOKIE_SECURE = True\n"
        "CSRF_ENABLED = True\n"
    )
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# DEBUG mode
# ---------------------------------------------------------------------------

def test_detects_debug_true_python(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("DEBUG = True\n")
    findings = scanner.scan(target)
    assert any("debug" in f.title.lower() for f in findings)


def test_detects_debug_inline(scanner, tmp_path, target):
    (tmp_path / "app.py").write_text("app = Flask(__name__)\nDEBUG = True\n")
    findings = scanner.scan(target)
    assert any("debug" in f.title.lower() for f in findings)


def test_comment_debug_not_flagged(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("# DEBUG = True\n")
    findings = scanner.scan(target)
    assert not any("debug" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Permissive CORS
# ---------------------------------------------------------------------------

def test_detects_cors_wildcard_list(scanner, tmp_path, target):
    (tmp_path / "main.py").write_text('allow_origins=["*"],\n')
    findings = scanner.scan(target)
    assert any("cors" in f.title.lower() for f in findings)


def test_detects_cors_allow_all_origins_true(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("CORS_ALLOW_ALL_ORIGINS = True\n")
    findings = scanner.scan(target)
    assert any("cors" in f.title.lower() for f in findings)


def test_detects_cors_origins_wildcard_list(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text('CORS_ORIGINS = ["*"]\n')
    findings = scanner.scan(target)
    assert any("cors" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Insecure session cookie
# ---------------------------------------------------------------------------

def test_detects_session_cookie_secure_false(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("SESSION_COOKIE_SECURE = False\n")
    findings = scanner.scan(target)
    assert any("cookie" in f.title.lower() or "secure" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# CSRF disabled
# ---------------------------------------------------------------------------

def test_detects_csrf_enabled_false(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("CSRF_ENABLED = False\n")
    findings = scanner.scan(target)
    assert any("csrf" in f.title.lower() for f in findings)


def test_detects_wtf_csrf_disabled(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text("WTF_CSRF_ENABLED = False\n")
    findings = scanner.scan(target)
    assert any("csrf" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Weak secret key
# ---------------------------------------------------------------------------

def test_detects_weak_secret_key_changeme(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text('SECRET_KEY = "changeme"\n')
    findings = scanner.scan(target)
    assert any("secret" in f.title.lower() for f in findings)


def test_detects_django_insecure_default_key(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text(
        'SECRET_KEY = "django-insecure-abc123def456ghi789"\n'
    )
    findings = scanner.scan(target)
    assert any("secret" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# SSL verification disabled
# ---------------------------------------------------------------------------

def test_detects_ssl_verify_false(scanner, tmp_path, target):
    (tmp_path / "client.py").write_text("response = requests.get(url, verify=False)\n")
    findings = scanner.scan(target)
    assert any("ssl" in f.title.lower() or "tls" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# ALLOWED_HOSTS wildcard
# ---------------------------------------------------------------------------

def test_detects_allowed_hosts_wildcard(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("ALLOWED_HOSTS = ['*']\n")
    findings = scanner.scan(target)
    assert any("allowed_hosts" in f.title.lower() or "allowed hosts" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Dev/test config files — downgrade to POSSIBLE
# ---------------------------------------------------------------------------

def test_dev_config_confidence_possible(scanner, tmp_path, target):
    dev_dir = tmp_path / "dev"
    dev_dir.mkdir()
    (dev_dir / "settings.py").write_text("DEBUG = True\n")
    findings = scanner.scan(target)
    debug_findings = [f for f in findings if "debug" in f.title.lower()]
    assert len(debug_findings) >= 1
    for f in debug_findings:
        assert f.confidence == Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# node_modules are skipped
# ---------------------------------------------------------------------------

def test_skips_node_modules(scanner, tmp_path, target):
    nm = tmp_path / "node_modules" / "config"
    nm.mkdir(parents=True)
    (nm / "defaults.js").write_text("DEBUG = True\n")
    findings = scanner.scan(target)
    assert not any(
        "node_modules" in (f.affected_file or "") for f in findings
    )


# ---------------------------------------------------------------------------
# Evidence structure
# ---------------------------------------------------------------------------

def test_finding_has_evidence_data(scanner, tmp_path, target):
    (tmp_path / "settings.py").write_text("DEBUG = True\n")
    findings = scanner.scan(target)
    assert len(findings) >= 1
    f = findings[0]
    assert f.evidence_data is not None
    assert f.evidence_data.get("type") == "config_value"
    assert f.affected_file is not None
    assert f.affected_line is not None
