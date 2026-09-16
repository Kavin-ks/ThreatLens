"""
Cryptography weakness scanner — detects use of weak/deprecated cryptographic
algorithms and hardcoded cryptographic key material in source code.

Checks performed:
  - Weak hash: MD5 in security-sensitive contexts (passwords, tokens, auth)
  - Weak hash: SHA1 in security-sensitive contexts
  - ECB block cipher mode
  - DES / 3DES (Triple DES) usage
  - RC4 stream cipher usage
  - Hardcoded symmetric key literals
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from scanners.base import BaseScanner
from scanners.registry import scanner_registry
from scanners.models import (
    ScanTarget,
    RawFinding,
    SecurityCategory,
    Severity,
    Confidence,
)

# ---------------------------------------------------------------------------
# Crypto check rule definition
# ---------------------------------------------------------------------------

@dataclass
class _CryptoRule:
    rule_id: str
    pattern: re.Pattern
    severity: Severity
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: str
    # If set, only flag if this word also appears within ±5 lines of the match
    security_context_words: Optional[List[str]] = None
    owasp_category: str = "A02:2021 – Cryptographic Failures"


# Words that indicate a hash is being used in a security-sensitive context
_SECURITY_CONTEXT = [
    'password', 'passwd', 'secret', 'token', 'auth', 'credential',
    'key', 'sign', 'verify', 'hash', 'digest', 'hmac', 'user', 'login',
]

_RULES: List[_CryptoRule] = [
    # MD5
    _CryptoRule(
        rule_id="weak_hash_md5_python",
        pattern=re.compile(r'\bhashlib\.md5\s*\('),
        severity=Severity.HIGH,
        title="Weak Hash Algorithm: MD5 (Python)",
        description="MD5 is cryptographically broken and must not be used for security-sensitive hashing.",
        impact=(
            "MD5 hash collisions can be computed in seconds. Using MD5 for passwords or integrity "
            "checks allows attackers to forge or crack values trivially."
        ),
        remediation=(
            "Replace with a secure algorithm. For passwords: use bcrypt, argon2, or scrypt. "
            "For integrity checking: use SHA-256 or SHA-3."
        ),
        cwe_id="CWE-328",
    ),
    _CryptoRule(
        rule_id="weak_hash_md5_node",
        pattern=re.compile(r'''(?:crypto\.createHash|createHash)\s*\(\s*['"]md5['"]\s*\)'''),
        severity=Severity.HIGH,
        title="Weak Hash Algorithm: MD5 (Node.js)",
        description="MD5 is cryptographically broken and must not be used for security-sensitive hashing.",
        impact=(
            "MD5 collisions are trivial to compute. Using MD5 for password storage or "
            "integrity verification provides no meaningful security guarantee."
        ),
        remediation=(
            "Use SHA-256 or SHA-3 for integrity checks. "
            "For passwords, use bcrypt, argon2, or scrypt via a dedicated library."
        ),
        cwe_id="CWE-328",
    ),
    _CryptoRule(
        rule_id="weak_hash_md5_java",
        pattern=re.compile(r'''MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)'''),
        severity=Severity.HIGH,
        title="Weak Hash Algorithm: MD5 (Java)",
        description="MD5 MessageDigest is cryptographically broken.",
        impact="MD5 collisions compromise any integrity or authentication scheme built on it.",
        remediation="Replace with `MessageDigest.getInstance(\"SHA-256\")` or a stronger algorithm.",
        cwe_id="CWE-328",
    ),
    # SHA-1
    _CryptoRule(
        rule_id="weak_hash_sha1_python",
        pattern=re.compile(r'\bhashlib\.sha1\s*\('),
        severity=Severity.MEDIUM,
        title="Weak Hash Algorithm: SHA-1 (Python)",
        description=(
            "SHA-1 is deprecated for security-sensitive uses. "
            "Practical collision attacks have been demonstrated."
        ),
        impact=(
            "SHA-1 collisions have been demonstrated in practice (SHAttered). "
            "Avoid SHA-1 for digital signatures, certificate fingerprints, and password hashing."
        ),
        remediation=(
            "Use SHA-256 or SHA-3 for new code. "
            "For passwords, use bcrypt, argon2, or scrypt."
        ),
        cwe_id="CWE-328",
    ),
    _CryptoRule(
        rule_id="weak_hash_sha1_node",
        pattern=re.compile(r'''(?:crypto\.createHash|createHash)\s*\(\s*['"]sha1['"]\s*\)'''),
        severity=Severity.MEDIUM,
        title="Weak Hash Algorithm: SHA-1 (Node.js)",
        description="SHA-1 is deprecated for security-sensitive operations.",
        impact="SHA-1 collisions have been demonstrated. Avoid for digital signatures and credential hashing.",
        remediation="Replace with `crypto.createHash('sha256')` or stronger.",
        cwe_id="CWE-328",
    ),
    _CryptoRule(
        rule_id="weak_hash_sha1_java",
        pattern=re.compile(r'''MessageDigest\.getInstance\s*\(\s*["']SHA-1["']\s*\)'''),
        severity=Severity.MEDIUM,
        title="Weak Hash Algorithm: SHA-1 (Java)",
        description="SHA-1 MessageDigest is deprecated for security-sensitive uses.",
        impact="SHA-1 collisions exist; avoid for signatures, certificate fingerprints, and credential storage.",
        remediation="Replace with `MessageDigest.getInstance(\"SHA-256\")` or stronger.",
        cwe_id="CWE-328",
    ),
    # ECB mode
    _CryptoRule(
        rule_id="ecb_mode_cipher",
        pattern=re.compile(
            r'(?i)(?:AES|DES|Blowfish)/ECB'
            r'|Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']'
            r'|createCipheriv\s*\(\s*["\'][^"\']*-ecb[^"\']*["\']',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="Insecure Block Cipher Mode: ECB",
        description=(
            "ECB (Electronic Codebook) mode encrypts identical plaintext blocks to identical "
            "ciphertext blocks, leaking structural information about the plaintext."
        ),
        impact=(
            "Encrypted data using ECB mode can expose patterns in the plaintext. "
            "This allows partial decryption and distinguishability attacks."
        ),
        remediation=(
            "Use AES-GCM (authenticated encryption) or at minimum AES-CBC with a random IV. "
            "Example: `AES/GCM/NoPadding` in Java, `aes-256-gcm` in Node.js."
        ),
        cwe_id="CWE-327",
    ),
    # DES / 3DES
    _CryptoRule(
        rule_id="des_3des_usage",
        pattern=re.compile(
            r'(?i)(?:Cipher\.getInstance\s*\(\s*["\'][^"\']*(?:DES|3DES|TripleDES)[^"\']*["\']'
            r'|createCipheriv\s*\(\s*["\']des[^"\']*["\']'
            r'|\bDESede\b|\bTripleDES\b|\bBlowfish\b)',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        title="Deprecated Cipher: DES / 3DES",
        description=(
            "DES has a 56-bit key (broken). 3DES (Triple DES) has an effective 112-bit security "
            "level and is vulnerable to the Sweet32 birthday attack."
        ),
        impact=(
            "DES keys can be brute-forced in hours. 3DES is vulnerable to Sweet32 in long sessions "
            "and is deprecated by NIST as of 2023."
        ),
        remediation="Replace with AES-256 (AES-GCM preferred). Remove all DES and 3DES usage.",
        cwe_id="CWE-327",
    ),
    # RC4
    _CryptoRule(
        rule_id="rc4_usage",
        pattern=re.compile(
            r'(?i)(?:RC4|ARCFOUR|ARC4)'
            r'|createCipheriv\s*\(\s*["\']rc4["\']',
        ),
        severity=Severity.HIGH,
        title="Deprecated Stream Cipher: RC4",
        description="RC4 is a broken stream cipher prohibited by RFC 7465 for TLS use.",
        impact=(
            "RC4 has multiple known biases. Session data encrypted with RC4 can be "
            "partially or fully recovered by statistical attacks."
        ),
        remediation=(
            "Replace all RC4 usage with AES-GCM or ChaCha20-Poly1305."
        ),
        cwe_id="CWE-327",
    ),
    # Hardcoded symmetric key literal
    _CryptoRule(
        rule_id="hardcoded_crypto_key",
        pattern=re.compile(
            r'(?i)(?:key|secret|aes_key|encryption_key|cipher_key)\s*[=:]\s*'
            r'b?["\'](?:[0-9a-fA-F]{16,}|[A-Za-z0-9+/]{16,}={0,2})["\']'
        ),
        severity=Severity.HIGH,
        title="Hardcoded Cryptographic Key",
        description=(
            "A symmetric encryption key is hardcoded in source code as a string literal."
        ),
        impact=(
            "Anyone with access to the source code can decrypt data protected by this key. "
            "Key rotation is impossible without a code change and redeployment."
        ),
        remediation=(
            "Store encryption keys in environment variables or a dedicated key management service "
            "(e.g. AWS KMS, HashiCorp Vault). Generate keys securely and rotate them regularly."
        ),
        cwe_id="CWE-321",
        owasp_category="A02:2021 – Cryptographic Failures",
    ),
]

_SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
    '.cs', '.kt', '.scala', '.swift',
}

_SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'env', 'dist', 'build', '.pytest_cache', 'vendor',
}

_TEST_PARTS = {'test', 'tests', 'spec', 'specs', 'fixture', 'fixtures', 'mock', 'mocks'}


def _in_test_context(rel_str: str) -> bool:
    return any(p.lower() in _TEST_PARTS for p in Path(rel_str).parts)


@scanner_registry.register
class CryptographyScanner(BaseScanner):
    scanner_id = "crypto.weak_algorithms"
    name = "Weak Cryptography Detector"
    description = (
        "Detects use of weak or deprecated cryptographic algorithms (MD5, SHA-1, DES, 3DES, RC4, "
        "ECB mode) and hardcoded symmetric key literals in source code."
    )
    category = SecurityCategory.CRYPTOGRAPHY
    supported_stacks = []
    cwe_ids = ["CWE-328", "CWE-327", "CWE-321"]

    def can_scan(self, target: ScanTarget) -> bool:
        return target.target_path is not None and target.target_path.is_dir()

    def scan(self, target: ScanTarget) -> List[RawFinding]:
        findings: List[RawFinding] = []
        seen: set = set()
        for file_path in self._iter_files(target.target_path):
            try:
                for f in self._scan_file(file_path, target.target_path):
                    key = (f.affected_file, f.affected_line, f.title)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
            except Exception:
                continue
        return findings

    def _scan_file(self, file_path: Path, root: Path) -> List[RawFinding]:
        rel_str = str(file_path.relative_to(root))
        is_test = _in_test_context(rel_str)

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

        findings: List[RawFinding] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(('#', '//', '*', '--', ';')):
                continue

            for rule in _RULES:
                if not rule.pattern.search(line):
                    continue

                # Determine confidence based on context
                confidence = Confidence.POSSIBLE if is_test else Confidence.LIKELY

                # Build code snippet (±2 lines context)
                ctx_start = max(0, line_no - 3)
                ctx_end = min(len(lines), line_no + 2)
                snippet = "\n".join(
                    f"{i + 1:4d} | {lines[i]}" for i in range(ctx_start, ctx_end)
                )

                findings.append(RawFinding(
                    scanner_id=self.scanner_id,
                    title=rule.title,
                    description=f"{rule.description} Found in `{rel_str}` at line {line_no}.",
                    category=SecurityCategory.CRYPTOGRAPHY,
                    severity=rule.severity,
                    confidence=confidence,
                    affected_file=rel_str,
                    affected_line=line_no,
                    affected_component=f"File: {rel_str}",
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    impact=rule.impact,
                    remediation=rule.remediation,
                    evidence_data={
                        "type": "code_snippet",
                        "title": f"Code snippet — {rel_str}:{line_no}",
                        "content": snippet,
                        "metadata": {
                            "file": rel_str,
                            "line": line_no,
                            "rule_id": rule.rule_id,
                        },
                    },
                ))
        return findings

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path
