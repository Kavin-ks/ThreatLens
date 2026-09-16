"""Unit tests for the CryptographyScanner."""
import pytest

from scanners.crypto.crypto_scanner import CryptographyScanner
from scanners.models import ScanTarget, Confidence, Severity
from scanners.registry import scanner_registry


@pytest.fixture()
def scanner():
    return CryptographyScanner()


@pytest.fixture()
def target(tmp_path) -> ScanTarget:
    return ScanTarget(project_id="test-project", target_path=tmp_path)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_scanner_registered():
    s = scanner_registry.get("crypto.weak_algorithms")
    assert s is not None
    assert s.scanner_id == "crypto.weak_algorithms"


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
    (tmp_path / "crypto.py").write_text(
        "import hashlib\n"
        "digest = hashlib.sha256(data).hexdigest()\n"
    )
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# MD5 — Python
# ---------------------------------------------------------------------------

def test_detects_md5_python(scanner, tmp_path, target):
    (tmp_path / "auth.py").write_text(
        "import hashlib\n"
        "hashed = hashlib.md5(password.encode()).hexdigest()\n"
    )
    findings = scanner.scan(target)
    assert any("md5" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings if "md5" in f.title.lower())


# ---------------------------------------------------------------------------
# MD5 — Node.js
# ---------------------------------------------------------------------------

def test_detects_md5_nodejs(scanner, tmp_path, target):
    (tmp_path / "utils.js").write_text(
        "const crypto = require('crypto');\n"
        "const hash = crypto.createHash('md5').update(data).digest('hex');\n"
    )
    findings = scanner.scan(target)
    assert any("md5" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# MD5 — Java
# ---------------------------------------------------------------------------

def test_detects_md5_java(scanner, tmp_path, target):
    (tmp_path / "Hasher.java").write_text(
        'MessageDigest md = MessageDigest.getInstance("MD5");\n'
    )
    findings = scanner.scan(target)
    assert any("md5" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# SHA-1 — Python
# ---------------------------------------------------------------------------

def test_detects_sha1_python(scanner, tmp_path, target):
    (tmp_path / "utils.py").write_text(
        "import hashlib\n"
        "token_hash = hashlib.sha1(token.encode()).hexdigest()\n"
    )
    findings = scanner.scan(target)
    assert any("sha-1" in f.title.lower() or "sha1" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings if "sha" in f.title.lower())


# ---------------------------------------------------------------------------
# SHA-1 — Node.js
# ---------------------------------------------------------------------------

def test_detects_sha1_nodejs(scanner, tmp_path, target):
    (tmp_path / "auth.js").write_text(
        "const sig = crypto.createHash('sha1').update(token).digest('hex');\n"
    )
    findings = scanner.scan(target)
    assert any("sha-1" in f.title.lower() or "sha1" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# ECB mode
# ---------------------------------------------------------------------------

def test_detects_ecb_mode_java(scanner, tmp_path, target):
    (tmp_path / "Cipher.java").write_text(
        'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
    )
    findings = scanner.scan(target)
    assert any("ecb" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings if "ecb" in f.title.lower())


def test_detects_ecb_mode_nodejs(scanner, tmp_path, target):
    (tmp_path / "encrypt.js").write_text(
        "const cipher = crypto.createCipheriv('aes-128-ecb', key, null);\n"
    )
    findings = scanner.scan(target)
    assert any("ecb" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# DES / 3DES
# ---------------------------------------------------------------------------

def test_detects_des_java(scanner, tmp_path, target):
    (tmp_path / "Legacy.java").write_text(
        'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n'
    )
    findings = scanner.scan(target)
    assert any("des" in f.title.lower() for f in findings)


def test_detects_3des(scanner, tmp_path, target):
    (tmp_path / "LegacyCipher.java").write_text(
        'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
    )
    findings = scanner.scan(target)
    assert any("des" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------

def test_detects_rc4(scanner, tmp_path, target):
    (tmp_path / "stream.java").write_text(
        'Cipher rc = Cipher.getInstance("RC4");\n'
    )
    findings = scanner.scan(target)
    assert any("rc4" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Hardcoded crypto key
# ---------------------------------------------------------------------------

def test_detects_hardcoded_key_hex(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text(
        'encryption_key = b"0102030405060708090a0b0c0d0e0f10"\n'
    )
    findings = scanner.scan(target)
    assert any("hardcoded" in f.title.lower() and "key" in f.title.lower() for f in findings)


def test_detects_hardcoded_key_base64(scanner, tmp_path, target):
    (tmp_path / "config.py").write_text(
        'AES_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde="\n'
    )
    findings = scanner.scan(target)
    assert any("key" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Comment lines not flagged
# ---------------------------------------------------------------------------

def test_comment_not_flagged(scanner, tmp_path, target):
    (tmp_path / "notes.py").write_text(
        "# hashlib.md5(password) -- do not use!\n"
        "# crypto.createHash('md5') is deprecated\n"
    )
    findings = scanner.scan(target)
    assert findings == []


# ---------------------------------------------------------------------------
# Test context → POSSIBLE confidence
# ---------------------------------------------------------------------------

def test_test_file_confidence_possible(scanner, tmp_path, target):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_hash.py").write_text(
        "import hashlib\n"
        "val = hashlib.md5(b'test').hexdigest()\n"
    )
    findings = scanner.scan(target)
    md5_findings = [f for f in findings if "md5" in f.title.lower()]
    assert len(md5_findings) >= 1
    for f in md5_findings:
        assert f.confidence == Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# node_modules skipped
# ---------------------------------------------------------------------------

def test_skips_node_modules(scanner, tmp_path, target):
    nm = tmp_path / "node_modules" / "lib"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("const h = crypto.createHash('md5').update(x).digest();\n")
    findings = scanner.scan(target)
    assert not any("node_modules" in (f.affected_file or "") for f in findings)


# ---------------------------------------------------------------------------
# Evidence structure
# ---------------------------------------------------------------------------

def test_finding_has_evidence_data(scanner, tmp_path, target):
    (tmp_path / "auth.py").write_text(
        "import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n"
    )
    findings = scanner.scan(target)
    assert len(findings) >= 1
    f = findings[0]
    assert f.evidence_data is not None
    assert f.evidence_data.get("type") == "code_snippet"
    assert f.affected_line is not None
    assert f.cwe_id == "CWE-328"
