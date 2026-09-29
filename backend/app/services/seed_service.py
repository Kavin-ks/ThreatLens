"""
Seed service — populates default sample projects (ThreatLens and LedgerLens)
with realistic findings, scan runs, and audit evidence.
Runs automatically on application startup so the deployed site on Render
or local environments always has full, rich assessment data.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from app.core.database import SessionLocal
from app.models.project import Project, ProjectStatus
from app.models.scan import ScanRun, ScannerResult, ScanStatus
from app.models.finding import (
    Finding,
    FindingHistory,
    FindingStatus,
    Severity,
    Confidence,
    SecurityCategory,
)
from app.models.evidence import Evidence, EvidenceType

logger = logging.getLogger(__name__)

THREATLENS_PROJECT_ID = "11111111-2222-3333-4444-555555555555"
LEDGERLENS_PROJECT_ID = "22222222-3333-4444-5555-666666666666"


def seed_initial_projects():
    db = SessionLocal()
    try:
        # Check if ThreatLens project exists
        p1 = db.get(Project, THREATLENS_PROJECT_ID)
        if not p1:
            logger.info("Seeding default ThreatLens assessment project...")
            now = datetime.now(timezone.utc)
            scan1_id = "aaaa1111-2222-3333-4444-555555555555"

            p1 = Project(
                id=THREATLENS_PROJECT_ID,
                name="ThreatLens Security Assessment",
                description="Evidence-driven application security assessment for World Monitor application — NTRO Problem Statement.",
                target_path="C:/Users/priya/jeeva_project/sih2/ThreatLens",
                target_url="http://localhost:8000",
                status=ProjectStatus.ACTIVE,
                stack_info=json.dumps({
                    "languages": ["Python", "TypeScript", "JavaScript"],
                    "frameworks": ["FastAPI", "React", "Vite", "Tailwind CSS"],
                    "package_managers": ["pip", "npm"],
                }),
                created_at=now - timedelta(days=2),
                updated_at=now - timedelta(hours=1),
            )
            db.add(p1)

            scan1 = ScanRun(
                id=scan1_id,
                project_id=THREATLENS_PROJECT_ID,
                status=ScanStatus.COMPLETED,
                scanner_config=json.dumps({
                    "scanner_ids": None,
                    "target_path": "C:/Users/priya/jeeva_project/sih2/ThreatLens",
                    "target_url": "http://localhost:8000",
                }),
                summary=json.dumps({
                    "total_raw": 18,
                    "total_confirmed": 14,
                    "by_severity": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 5, "LOW": 2},
                    "scanner_count": 8,
                }),
                created_at=now - timedelta(days=1),
                updated_at=now - timedelta(hours=2),
            )
            db.add(scan1)

            # Findings for ThreatLens
            f1 = Finding(
                id="f1111111-0001-4444-8888-000000000001",
                project_id=THREATLENS_PROJECT_ID,
                scan_run_id=scan1_id,
                scanner_id="injection.sql_error_based",
                title="SQL Injection — Database Error Disclosed",
                description="Unsanitized user input in query parameter triggers SQL syntax error disclosing database internals.",
                category=SecurityCategory.INJECTION,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="api/v1/projects",
                affected_file="backend/app/api/v1/projects.py",
                affected_line=42,
                cwe_id="CWE-89",
                owasp_category="A03:2021 – Injection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
                impact="Full database compromise, unauthorized record extraction, and data tampering.",
                remediation="Use parameterized queries and SQLAlchemy ORM bound expressions instead of raw string formatting.",
                created_at=now - timedelta(days=1),
            )
            f2 = Finding(
                id="f1111111-0002-4444-8888-000000000002",
                project_id=THREATLENS_PROJECT_ID,
                scan_run_id=scan1_id,
                scanner_id="crypto.weak_algorithms",
                title="Weak Cryptographic Hash: MD5 in Authentication Context",
                description="MD5 hashing algorithm detected in password and session validation logic. MD5 is vulnerable to collision attacks.",
                category=SecurityCategory.CRYPTOGRAPHY,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="app/core/security",
                affected_file="backend/app/core/security.py",
                affected_line=78,
                cwe_id="CWE-327",
                owasp_category="A02:2021 – Cryptographic Failures",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                impact="Credentials can be reversed using precomputed rainbow tables or collision attacks.",
                remediation="Upgrade password hashing to Argon2id or bcrypt with appropriate work factors.",
                created_at=now - timedelta(days=1),
            )
            f3 = Finding(
                id="f1111111-0003-4444-8888-000000000003",
                project_id=THREATLENS_PROJECT_ID,
                scan_run_id=scan1_id,
                scanner_id="secrets.hardcoded_keys",
                title="Hardcoded JWT Secret Key in Application Configuration",
                description="A static secret key used for signing JWT access tokens was detected committed directly in configuration files.",
                category=SecurityCategory.SECRETS,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="core/config",
                affected_file="backend/app/core/config.py",
                affected_line=26,
                cwe_id="CWE-798",
                owasp_category="A02:2021 – Cryptographic Failures",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_score=8.1,
                impact="Attackers can forge arbitrary authentication tokens and impersonate administrators.",
                remediation="Store secrets strictly in external environment variables or a secrets manager like Vault.",
                created_at=now - timedelta(days=1),
            )
            f4 = Finding(
                id="f1111111-0004-4444-8888-000000000004",
                project_id=THREATLENS_PROJECT_ID,
                scan_run_id=scan1_id,
                scanner_id="dependencies.python_packages",
                title="Vulnerable Dependency: Outdated Celery with Remote Execution Vector",
                description="Detected legacy package version with known advisory CVE-2023-38606 allowing remote code execution via unsafe deserialization.",
                category=SecurityCategory.DEPENDENCIES,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="requirements.txt",
                affected_file="backend/requirements.txt",
                affected_line=8,
                cwe_id="CWE-1104",
                owasp_category="A06:2021 – Vulnerable and Outdated Components",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.1,
                impact="Potential remote code execution on background worker machines.",
                remediation="Upgrade celery to version 5.4.0 or newer and enforce JSON serialization.",
                created_at=now - timedelta(days=1),
            )
            f5 = Finding(
                id="f1111111-0005-4444-8888-000000000005",
                project_id=THREATLENS_PROJECT_ID,
                scan_run_id=scan1_id,
                scanner_id="headers.http_security",
                title="Missing HTTP Security Headers (Content-Security-Policy & HSTS)",
                description="Web application responses lack strict Content-Security-Policy and Strict-Transport-Security headers.",
                category=SecurityCategory.HEADERS,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.RESOLVED,
                affected_component="middleware/security",
                affected_file="backend/app/main.py",
                affected_line=31,
                cwe_id="CWE-693",
                owasp_category="A05:2021 – Security Misconfiguration",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_score=3.7,
                impact="Increases susceptibility to cross-site scripting and SSL stripping attacks.",
                remediation="Add security headers middleware configuring CSP, HSTS, and X-Content-Type-Options.",
                created_at=now - timedelta(days=1),
            )

            db.add_all([f1, f2, f3, f4, f5])

            # Add sample evidence for findings
            e1 = Evidence(
                finding_id=f1.id,
                evidence_type=EvidenceType.CODE_SNIPPET,
                content='query = f"SELECT * FROM projects WHERE id = \'{project_id}\'"',
                title="Vulnerable Raw SQL Construction",
                description="String concatenation directly interpolates unvalidated user input into database query.",
            )
            e2 = Evidence(
                finding_id=f3.id,
                evidence_type=EvidenceType.CODE_SNIPPET,
                content='SECRET_KEY = "CHANGE-THIS-IN-PRODUCTION-USE-A-STRONG-RANDOM-KEY"',
                title="Hardcoded Default Secret",
                description="Default hardcoded secret token found present in production settings file.",
            )
            db.add_all([e1, e2])

        # Check if LedgerLens project exists
        p2 = db.get(Project, LEDGERLENS_PROJECT_ID)
        if not p2:
            logger.info("Seeding default LedgerLens blockchain assessment project...")
            now = datetime.now(timezone.utc)
            scan2_id = "bbbb2222-3333-4444-5555-666666666666"

            p2 = Project(
                id=LEDGERLENS_PROJECT_ID,
                name="LedgerLens - Blockchain Forensic & AML Analysis",
                description="Multi-chain fraud tracing, AML transaction tracking, and smart contract security audit.",
                target_path="C:/Users/priya/jeeva_project/LedgerLens",
                target_url="http://localhost:3000",
                status=ProjectStatus.ACTIVE,
                stack_info=json.dumps({
                    "languages": ["Solidity", "TypeScript", "Python"],
                    "frameworks": ["Hardhat", "FastAPI", "React", "Next.js"],
                    "package_managers": ["npm", "pip"],
                }),
                created_at=now - timedelta(days=3),
                updated_at=now - timedelta(hours=3),
            )
            db.add(p2)

            scan2 = ScanRun(
                id=scan2_id,
                project_id=LEDGERLENS_PROJECT_ID,
                status=ScanStatus.COMPLETED,
                scanner_config=json.dumps({
                    "scanner_ids": None,
                    "target_path": "C:/Users/priya/jeeva_project/LedgerLens",
                    "target_url": "http://localhost:3000",
                }),
                summary=json.dumps({
                    "total_raw": 12,
                    "total_confirmed": 9,
                    "by_severity": {"CRITICAL": 2, "HIGH": 4, "MEDIUM": 3},
                    "scanner_count": 6,
                }),
                created_at=now - timedelta(days=2),
                updated_at=now - timedelta(hours=4),
            )
            db.add(scan2)

            # Findings for LedgerLens
            lf1 = Finding(
                id="f2222222-0001-4444-8888-000000000001",
                project_id=LEDGERLENS_PROJECT_ID,
                scan_run_id=scan2_id,
                scanner_id="contracts.reentrancy",
                title="Smart Contract Reentrancy Vulnerability (ETH Transfer Before State Update)",
                description="Vault contract sends ETH via external call before deducting user balance, allowing recursive reentrant draining of contract funds.",
                category=SecurityCategory.INJECTION,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="contracts/TreasuryVault.sol",
                affected_file="contracts/TreasuryVault.sol",
                affected_line=64,
                cwe_id="CWE-841",
                owasp_category="A04:2021 – Insecure Design",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",
                cvss_score=10.0,
                impact="Malicious contract can siphon all locked funds in a single transaction sequence.",
                remediation="Follow the Checks-Effects-Interactions pattern or utilize OpenZeppelin ReentrancyGuard mutex locks.",
                created_at=now - timedelta(days=2),
            )
            lf2 = Finding(
                id="f2222222-0002-4444-8888-000000000002",
                project_id=LEDGERLENS_PROJECT_ID,
                scan_run_id=scan2_id,
                scanner_id="contracts.access_control",
                title="Missing Ownership Modifier on Liquidity Withdrawal Function",
                description="Publicly exposed emergencyWithdraw() function lacks onlyOwner or AccessControl authorization restrictions.",
                category=SecurityCategory.AUTHORIZATION,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="contracts/PoolManager.sol",
                affected_file="contracts/PoolManager.sol",
                affected_line=112,
                cwe_id="CWE-285",
                owasp_category="A01:2021 – Broken Access Control",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                cvss_score=9.1,
                impact="Any caller can trigger emergency liquidation and divert liquidity pool assets.",
                remediation="Apply the onlyOwner modifier from OpenZeppelin Ownable contract to restricted routines.",
                created_at=now - timedelta(days=2),
            )
            lf3 = Finding(
                id="f2222222-0003-4444-8888-000000000003",
                project_id=LEDGERLENS_PROJECT_ID,
                scan_run_id=scan2_id,
                scanner_id="contracts.weak_prng",
                title="Predictable On-Chain Randomness Using block.timestamp",
                description="Random number generation relies on block.timestamp and blockhash, which can be manipulated by block validators/miners.",
                category=SecurityCategory.CRYPTOGRAPHY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                affected_component="contracts/LotteryDraw.sol",
                affected_file="contracts/LotteryDraw.sol",
                affected_line=35,
                cwe_id="CWE-338",
                owasp_category="A02:2021 – Cryptographic Failures",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                cvss_score=5.9,
                impact="MEV bots and miners can bias random outcomes in their favor.",
                remediation="Integrate Chainlink VRF (Verifiable Random Function) or off-chain commit-reveal schemes.",
                created_at=now - timedelta(days=2),
            )

            db.add_all([lf1, lf2, lf3])

            le1 = Evidence(
                finding_id=lf1.id,
                evidence_type=EvidenceType.CODE_SNIPPET,
                content='(bool sent, ) = msg.sender.call{value: amount}("");\nbalances[msg.sender] -= amount;',
                title="Checks-Effects-Interactions Violation",
                description="External call occurs on line 64 before storage balance deduction on line 65.",
            )
            db.add(le1)

        db.commit()
        logger.info("Default seed projects successfully verified/created.")
    except Exception as e:
        logger.exception("Error seeding initial projects: %s", e)
        db.rollback()
    finally:
        db.close()
