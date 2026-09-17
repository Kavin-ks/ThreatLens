"""
Phase 8 — End-to-End Workflow Validation

Tests the complete 12-step security assessment workflow against a controlled,
intentionally vulnerable local test fixture. All scanning is restricted to
localhost and the local test fixture directory.

Security constraints enforced throughout:
  - Dynamic scanner targets must be localhost/RFC-1918 only (enforced by is_local_target)
  - No external systems are contacted
  - Credentials in the fixture are entirely fabricated
  - The vulnerable HTTP server runs on 127.0.0.1 on an ephemeral port only during testing
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy.orm import Session

FIXTURE_DIR = Path(__file__).parent.parent / "test_fixtures"
VULN_APP_DIR = FIXTURE_DIR / "vulnerable_app"
FIXED_APP_DIR = FIXTURE_DIR / "vulnerable_app_fixed"


# ─── Intentionally vulnerable local HTTP server ───────────────────────────────

class _VulnerableHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP server simulating common vulnerability patterns.

    Intentional weaknesses (local test only):
      - No security response headers (triggers http_security.headers scanner)
      - Returns a sqlite3.OperationalError message when a query param contains
        a SQL injection probe character (triggers injection.sql_error_based)
    """

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Simulate SQL injection: return a database error for probe characters
        for vals in params.values():
            for v in vals:
                if "'" in v or '"' in v:
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"sqlite3.OperationalError: near \"'\": syntax error"
                    )
                    return

        # Normal response — intentionally missing all security headers
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Vulnerable Test App</h1>"
            b"<p>E2E test fixture - intentionally vulnerable</p></body></html>"
        )

    def log_message(self, fmt, *args):  # suppress server log noise
        pass


@pytest.fixture(scope="module")
def vuln_server():
    """Start a local intentionally-vulnerable HTTP server on a free ephemeral port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(("127.0.0.1", port), _VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ─── Helper: run orchestrator directly in the test session ───────────────────

def _run_scan_directly(
    db: Session,
    scan_run_id: str,
    *,
    target_path: Path | None = None,
    target_url: str | None = None,
) -> dict:
    """
    Execute the scan orchestrator directly using the test's DB session.
    Bypasses execute_scan (which creates its own SessionLocal) to keep
    everything inside the test's rolled-back transaction.
    """
    from app.models.scan import ScanRun, ScanStatus
    from scanners.models import ScanTarget
    from scanners.orchestrator import ScanOrchestrator

    scan_run = db.get(ScanRun, scan_run_id)
    assert scan_run is not None, f"ScanRun {scan_run_id} not found in test DB"

    scan_run.status = ScanStatus.RUNNING
    db.commit()

    target = ScanTarget(
        project_id=scan_run.project_id,
        target_path=target_path,
        target_url=target_url,
    )
    orchestrator = ScanOrchestrator(db=db)
    summary = orchestrator.run(scan_run=scan_run, target=target)

    scan_run.status = ScanStatus.COMPLETED
    scan_run.summary = json.dumps(summary)
    db.commit()
    return summary


# ─── Complete 12-step workflow test ──────────────────────────────────────────

class TestCompleteWorkflow:
    """
    Validates every phase of ThreatLens's assessment lifecycle against the
    intentionally vulnerable local test fixture.
    """

    def test_complete_12_step_workflow(
        self,
        client,
        db,
        monkeypatch,
        vuln_server,
        tmp_path,
    ):
        # Prevent BackgroundTasks from calling execute_scan (which would create
        # its own SessionLocal disconnected from the test transaction).
        monkeypatch.setattr("app.workers.scan_tasks.execute_scan", lambda _: None)

        # ── STEP 1: Target ingestion ──────────────────────────────────────────
        r = client.post("/api/v1/projects", json={
            "name": "E2E Vulnerable Test App",
            "description": "Phase 8 e2e test target — intentionally vulnerable fixture",
            "target_path": str(VULN_APP_DIR),
            "target_url": vuln_server,
        })
        assert r.status_code == 201, r.text
        project = r.json()
        project_id = project["id"]
        assert project["target_path"] == str(VULN_APP_DIR)
        assert project["target_url"] == vuln_server

        # ── STEP 2: Scan creation (static) ───────────────────────────────────
        r = client.post(f"/api/v1/projects/{project_id}/scans", json={})
        assert r.status_code == 202, r.text
        static_scan_id = r.json()["id"]

        # ── STEP 3: Stack detection + Static scanning ─────────────────────────
        static_summary = _run_scan_directly(
            db, static_scan_id, target_path=VULN_APP_DIR
        )
        assert static_summary["total_raw"] >= 1, (
            "Secrets scanner should detect hardcoded credentials in config.py. "
            f"Summary: {static_summary}"
        )

        # Verify stack detection updated the project
        r = client.get(f"/api/v1/projects/{project_id}")
        assert r.status_code == 200
        project_data = r.json()
        # Stack info should be populated (Python files detected)
        assert project_data.get("stack_info") is not None, (
            "Stack detection should have populated stack_info"
        )

        # ── STEP 4: Dynamic scanning ─────────────────────────────────────────
        r = client.post(f"/api/v1/projects/{project_id}/scans", json={})
        assert r.status_code == 202, r.text
        dynamic_scan_id = r.json()["id"]

        dynamic_summary = _run_scan_directly(
            db, dynamic_scan_id, target_url=vuln_server
        )
        # HTTP header scanner should fire — missing CSP, X-Frame-Options, etc.
        assert dynamic_summary["total_raw"] >= 1, (
            "HTTP security scanner should detect missing security headers. "
            f"Summary: {dynamic_summary}"
        )

        # ── STEP 5: Finding creation ──────────────────────────────────────────
        r = client.get(f"/api/v1/projects/{project_id}/findings")
        assert r.status_code == 200
        findings = r.json()
        assert len(findings) >= 2, (
            f"Expected at least 2 findings (static + dynamic), got {len(findings)}"
        )

        # Select a secrets finding for the full lifecycle workflow
        secrets_finding = next(
            (f for f in findings if "secrets" in f.get("scanner_id", "")),
            None,
        )
        assert secrets_finding is not None, (
            "Expected a finding from secrets.hardcoded_credentials scanner. "
            f"Available scanners: {[f.get('scanner_id') for f in findings]}"
        )
        finding_id = secrets_finding["id"]

        # ── STEP 6: Evidence collection ───────────────────────────────────────
        r = client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}")
        assert r.status_code == 200
        detail = r.json()
        assert detail["evidence"], (
            "Secrets finding should include code snippet evidence"
        )
        # Evidence should contain a code snippet with [REDACTED] in place of the secret
        evidence_content = detail["evidence"][0].get("content", "")
        assert "config.py" in evidence_content or "[REDACTED]" in evidence_content, (
            f"Evidence should reference config.py or show redacted value, got: {evidence_content[:200]}"
        )

        # ── STEP 7: Finding validation ────────────────────────────────────────
        r = client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/validate",
            json={
                "confidence": "CONFIRMED",
                "note": "Manually verified: hardcoded credential present in config.py",
            },
        )
        assert r.status_code == 200, r.text
        validated = r.json()
        assert validated["confidence"] == "CONFIRMED"
        assert validated["status"] == "CONFIRMED"

        # ── STEP 8: CVSS scoring ──────────────────────────────────────────────
        # Network-accessible hardcoded credential: AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:L, A:N
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        r = client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/cvss",
            json={"vector": cvss_vector},
        )
        assert r.status_code == 200, r.text
        cvss_result = r.json()
        assert cvss_result["cvss_score"] > 0, "CVSS score must be positive"
        assert cvss_result["severity_label"] in ("HIGH", "CRITICAL"), (
            f"Expected HIGH or CRITICAL severity, got {cvss_result['severity_label']}"
        )

        # Verify CVSS vector persisted on the finding
        r = client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}")
        assert r.json()["cvss_vector"] == cvss_vector

        # ── STEP 9: Remediation recording ────────────────────────────────────
        r = client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/remediation",
            json={
                "description": (
                    "Removed hardcoded credentials from config.py. "
                    "Credentials are now loaded via os.getenv() from environment variables."
                ),
                "applied_by": "developer",
            },
        )
        assert r.status_code == 201, r.text
        remediation = r.json()
        remediation_id = remediation["id"]
        assert remediation["retest_status"] == "pending"

        # Finding should advance to REMEDIATION status
        r = client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}")
        assert r.json()["status"] == "REMEDIATION", (
            f"Expected REMEDIATION status after recording remediation, got {r.json()['status']}"
        )

        # ── STEP 10: Retest — project now points to fixed version ─────────────
        # Update the project's target path to the fixed app (no hardcoded secrets)
        r = client.patch(f"/api/v1/projects/{project_id}", json={
            "target_path": str(FIXED_APP_DIR),
        })
        assert r.status_code == 200, r.text
        assert r.json()["target_path"] == str(FIXED_APP_DIR)

        # Trigger retest — scanner re-runs against the fixed directory
        r = client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}"
            f"/remediation/{remediation_id}/retest",
            json={"notes": "Retesting after credential removal — expect pass"},
        )
        assert r.status_code == 200, r.text
        retest_result = r.json()
        assert retest_result["retest_status"] == "passed", (
            f"Retest should pass since fixed app has no hardcoded credentials. "
            f"Got: {retest_result}"
        )

        # ── STEP 11: Finding resolution ───────────────────────────────────────
        r = client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}")
        assert r.status_code == 200
        resolved_finding = r.json()
        assert resolved_finding["status"] == "RESOLVED", (
            f"Finding should be auto-resolved after retest passed. "
            f"Got: {resolved_finding['status']}"
        )

        # History should record the RESOLVED transition
        history_statuses = [h["to_status"] for h in resolved_finding.get("history", [])]
        assert "RESOLVED" in history_statuses, (
            f"History should contain RESOLVED transition. History: {history_statuses}"
        )

        # ── STEP 12: PDF report generation ───────────────────────────────────
        r = client.post(f"/api/v1/projects/{project_id}/reports", json={
            "title": "E2E Security Assessment Report",
        })
        assert r.status_code == 201, r.text
        report = r.json()
        report_id = report["id"]

        r = client.get(f"/api/v1/projects/{project_id}/reports/{report_id}/download")
        assert r.status_code == 200, r.text
        assert "application/pdf" in r.headers.get("content-type", ""), (
            f"Expected application/pdf content type, got: {r.headers.get('content-type')}"
        )
        pdf_bytes = r.content
        assert len(pdf_bytes) > 500, "PDF should have non-trivial content"
        assert pdf_bytes[:4] == b"%PDF", "Downloaded file should be a valid PDF"


# ─── Scanner autodiscovery tests ──────────────────────────────────────────────

class TestScannerDiscovery:
    """Verifies scanner autodiscovery and enable/disable configuration."""

    def test_all_expected_scanners_registered(self, client):
        r = client.get("/api/v1/scanners/")
        assert r.status_code == 200
        scanner_ids = {s["scanner_id"] for s in r.json()}
        expected = {
            "secrets.hardcoded_credentials",
            "injection.sql_error_based",
            "headers.http_security",
        }
        missing = expected - scanner_ids
        assert not missing, f"Expected scanners not registered: {missing}"

    def test_scanner_info_has_required_fields(self, client):
        r = client.get("/api/v1/scanners/")
        assert r.status_code == 200
        for scanner in r.json():
            assert "scanner_id" in scanner
            assert "name" in scanner
            assert "description" in scanner
            assert "cwe_ids" in scanner

    def test_enable_disable_per_project(self, client):
        r = client.post("/api/v1/projects", json={"name": "Scanner Config Test"})
        project_id = r.json()["id"]

        # Default: no config → all scanners enabled (null)
        r = client.get(f"/api/v1/projects/{project_id}/scanner-config")
        assert r.status_code == 200
        assert r.json()["enabled_scanners"] is None

        # Restrict to secrets scanner only
        r = client.patch(f"/api/v1/projects/{project_id}/scanner-config", json={
            "enabled_scanners": ["secrets.hardcoded_credentials"],
        })
        assert r.status_code == 200
        assert r.json()["enabled_scanners"] == ["secrets.hardcoded_credentials"]

        # Re-enable all (set to null)
        r = client.patch(f"/api/v1/projects/{project_id}/scanner-config", json={
            "enabled_scanners": None,
        })
        assert r.status_code == 200
        assert r.json()["enabled_scanners"] is None

    def test_authorized_targets_saved_and_retrieved(self, client):
        r = client.post("/api/v1/projects", json={"name": "Auth Targets Test"})
        project_id = r.json()["id"]

        targets = ["http://127.0.0.1:8080", "http://localhost:9090"]
        r = client.patch(f"/api/v1/projects/{project_id}/scanner-config", json={
            "authorized_targets": targets,
        })
        assert r.status_code == 200
        returned = r.json()["authorized_targets"]
        for t in targets:
            assert t in returned


# ─── Dynamic scanner local target enforcement tests ──────────────────────────

class TestDynamicScannerLocalEnforcement:
    """
    Verifies that dynamic scanners refuse non-local targets.
    ThreatLens must never scan external systems automatically.
    """

    def test_sql_scanner_refuses_external_target(self):
        from scanners.injection.injection_scanner import SqlInjectionScanner
        from scanners.models import ScanTarget

        scanner = SqlInjectionScanner()
        target = ScanTarget(
            project_id="test",
            target_url="https://example.com",
        )
        assert not scanner.can_scan(target), (
            "SQL injection scanner must refuse external (non-local) targets"
        )

    def test_http_scanner_refuses_external_target(self):
        from scanners.headers.http_security_scanner import HttpSecurityScanner
        from scanners.models import ScanTarget

        scanner = HttpSecurityScanner()
        target = ScanTarget(
            project_id="test",
            target_url="https://example.com",
        )
        assert not scanner.can_scan(target), (
            "HTTP security scanner must refuse external (non-local) targets"
        )

    def test_sql_scanner_accepts_localhost(self):
        from scanners.injection.injection_scanner import SqlInjectionScanner
        from scanners.models import ScanTarget

        scanner = SqlInjectionScanner()
        target = ScanTarget(
            project_id="test",
            target_url="http://127.0.0.1:8080",
        )
        assert scanner.can_scan(target), (
            "SQL injection scanner should accept localhost targets"
        )

    def test_sql_scanner_accepts_private_ip(self):
        from scanners.injection.injection_scanner import SqlInjectionScanner
        from scanners.models import ScanTarget

        scanner = SqlInjectionScanner()
        target = ScanTarget(
            project_id="test",
            target_url="http://192.168.1.10:3000",
        )
        assert scanner.can_scan(target), (
            "SQL injection scanner should accept RFC-1918 private addresses"
        )


# ─── Static scanner finding quality tests ────────────────────────────────────

class TestStaticScannerFindingQuality:
    """Verifies that the secrets scanner produces findings with required fields."""

    def test_secrets_scanner_finds_hardcoded_credentials(self):
        from scanners.secrets.secrets_scanner import SecretsScanner
        from scanners.models import ScanTarget

        scanner = SecretsScanner()
        target = ScanTarget(project_id="test", target_path=VULN_APP_DIR)
        findings = scanner.scan(target)

        assert len(findings) >= 1, (
            f"Expected at least one finding in vulnerable_app, got {len(findings)}"
        )

        # All findings should have required fields
        for f in findings:
            assert f.title
            assert f.description
            assert f.affected_file
            assert f.affected_line and f.affected_line > 0
            assert f.cwe_id
            assert f.evidence_data

    def test_secrets_scanner_does_not_flag_env_lookups(self):
        from scanners.secrets.secrets_scanner import SecretsScanner
        from scanners.models import ScanTarget

        scanner = SecretsScanner()
        target = ScanTarget(project_id="test", target_path=FIXED_APP_DIR)
        findings = scanner.scan(target)

        # Fixed version uses os.getenv() — should not produce high-confidence findings
        high_conf = [f for f in findings if f.confidence == "LIKELY"]
        assert len(high_conf) == 0, (
            f"Fixed app should have no LIKELY-confidence findings, got: {high_conf}"
        )

    def test_secrets_scanner_evidence_redacts_secret_value(self):
        from scanners.secrets.secrets_scanner import SecretsScanner
        from scanners.models import ScanTarget

        scanner = SecretsScanner()
        target = ScanTarget(project_id="test", target_path=VULN_APP_DIR)
        findings = scanner.scan(target)

        for f in findings:
            if f.evidence_data and f.evidence_data.get("content"):
                content = f.evidence_data["content"]
                # The actual secret value must not appear verbatim in the evidence
                assert "Fake_Password_Value_ForTesting_XR9a" not in content, (
                    "Evidence should redact the actual password value"
                )
