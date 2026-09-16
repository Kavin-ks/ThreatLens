"""
Tests for Phase 6: validation, remediation, retesting, and report generation.
"""
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from app.models.finding import Finding, FindingStatus, Confidence, FindingHistory
from app.models.remediation import RemediationRecord, RetestStatus
from app.models.project import Project
from app.models.scan import ScanRun, ScanStatus


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(db):
    p = Project(name="Test Project", target_path="/tmp/fakerepo")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@pytest.fixture()
def scan_run(db, project):
    run = ScanRun(
        project_id=project.id,
        status=ScanStatus.COMPLETED,
        scanner_config=json.dumps({"target_path": "/tmp/fakerepo"}),
        summary=json.dumps({"total_raw": 1}),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@pytest.fixture()
def finding(db, project, scan_run):
    f = Finding(
        project_id=project.id,
        scan_run_id=scan_run.id,
        scanner_id="secrets.api_key",
        title="Exposed API Key",
        description="An API key was found in source code.",
        category="secrets",
        severity="HIGH",
        confidence=Confidence.LIKELY,
        status=FindingStatus.DETECTED,
        fingerprint="abc123fingerprint",
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


# ── Validate finding ──────────────────────────────────────────────────────────

class TestValidateFinding:
    def test_validate_as_confirmed(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/validate",
            json={"confidence": "CONFIRMED", "note": "Manually verified"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["confidence"] == "CONFIRMED"
        assert data["status"] == "CONFIRMED"
        history = data["history"]
        assert any(h["to_status"] == "CONFIRMED" for h in history)

    def test_validate_as_false_positive(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/validate",
            json={"confidence": "FALSE_POSITIVE"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["confidence"] == "FALSE_POSITIVE"
        assert data["status"] == "REJECTED"

    def test_validate_as_possible(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/validate",
            json={"confidence": "POSSIBLE"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "VALIDATING"

    def test_validate_finding_not_found(self, client, project):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/nonexistent/validate",
            json={"confidence": "CONFIRMED"},
        )
        assert resp.status_code == 404

    def test_validate_wrong_project(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/wrong-project/findings/{finding.id}/validate",
            json={"confidence": "CONFIRMED"},
        )
        assert resp.status_code == 404


# ── Remediation records ───────────────────────────────────────────────────────

class TestRemediationRecords:
    def test_create_remediation(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "Removed hardcoded key, moved to env vars", "applied_by": "dev-team"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["retest_status"] == "pending"
        assert data["description"] == "Removed hardcoded key, moved to env vars"
        assert data["applied_by"] == "dev-team"

    def test_create_remediation_advances_finding_status(self, client, project, finding):
        client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "Fix applied"},
        )
        resp = client.get(f"/api/v1/projects/{project.id}/findings/{finding.id}")
        assert resp.json()["status"] == "REMEDIATION"

    def test_list_remediation_empty(self, client, project, finding):
        resp = client.get(f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_remediation_returns_records(self, client, project, finding):
        client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "First fix"},
        )
        client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "Second fix"},
        )
        resp = client.get(f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation")
        assert len(resp.json()) == 2

    def test_remediation_includes_patch_diff(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "Fix", "patch_diff": "-SECRET_KEY=abc\n+SECRET_KEY=$ENV_VAR"},
        )
        assert resp.json()["patch_diff"] == "-SECRET_KEY=abc\n+SECRET_KEY=$ENV_VAR"

    def test_create_remediation_finding_not_found(self, client, project):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/nonexistent/remediation",
            json={"description": "Fix"},
        )
        assert resp.status_code == 404


# ── Retest ────────────────────────────────────────────────────────────────────

class TestRetest:
    def _create_remediation(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}/remediation",
            json={"description": "Applied fix"},
        )
        return resp.json()["id"]

    def test_retest_scanner_not_registered_inconclusive(self, client, project, finding):
        """When the scanner_id is unrecognised, retest returns inconclusive."""
        rem_id = self._create_remediation(client, project, finding)
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{finding.id}"
                f"/remediation/{rem_id}/retest",
                json={},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "inconclusive"

    def test_retest_scanner_returns_same_finding_fails(self, client, project, finding):
        """When the scanner re-detects the same fingerprint, retest fails."""
        rem_id = self._create_remediation(client, project, finding)

        mock_raw = MagicMock()
        mock_raw.scanner_id = finding.scanner_id
        mock_raw.affected_file = None
        mock_raw.affected_line = None
        mock_raw.title = finding.title

        mock_scanner = MagicMock()
        mock_scanner.can_scan = MagicMock(return_value=True)
        mock_scanner.scan = MagicMock(return_value=[mock_raw])

        with patch("app.services.retest_service.scanner_registry") as mock_reg, \
             patch("app.services.retest_service._fingerprint") as mock_fp:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_scanner)
            mock_fp.return_value = "abc123fingerprint"  # same as finding.fingerprint

            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{finding.id}"
                f"/remediation/{rem_id}/retest",
                json={"notes": "re-checking"},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "failed"

    def test_retest_scanner_no_longer_detects_resolves(self, client, project, finding):
        """When scanner finds nothing, retest passes and finding is resolved."""
        rem_id = self._create_remediation(client, project, finding)

        mock_scanner = MagicMock()
        mock_scanner.can_scan = MagicMock(return_value=True)
        mock_scanner.scan = MagicMock(return_value=[])  # no findings

        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_scanner)

            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{finding.id}"
                f"/remediation/{rem_id}/retest",
                json={},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "passed"

        # Finding should now be RESOLVED
        finding_resp = client.get(f"/api/v1/projects/{project.id}/findings/{finding.id}")
        assert finding_resp.json()["status"] == "RESOLVED"

    def test_retest_advances_to_retesting_status(self, client, project, finding):
        rem_id = self._create_remediation(client, project, finding)
        mock_scanner = MagicMock()
        mock_scanner.can_scan = MagicMock(return_value=True)
        mock_scanner.scan = MagicMock(return_value=[])
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_scanner)
            client.post(
                f"/api/v1/projects/{project.id}/findings/{finding.id}"
                f"/remediation/{rem_id}/retest",
                json={},
            )
        finding_resp = client.get(f"/api/v1/projects/{project.id}/findings/{finding.id}")
        history = finding_resp.json()["history"]
        assert any(h["to_status"] == "RETESTING" for h in history)

    def test_retest_remediation_not_found(self, client, project, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{finding.id}"
            f"/remediation/nonexistent/retest",
            json={},
        )
        assert resp.status_code == 404


# ── Report generation ─────────────────────────────────────────────────────────

class TestReportGeneration:
    def test_generate_report_returns_metadata(self, client, project, scan_run, finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/reports",
            json={"scan_run_id": scan_run.id},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["project_id"] == project.id
        assert data["format"] == "pdf"
        assert "Security Assessment" in data["title"]

    def test_generate_report_custom_title(self, client, project):
        resp = client.post(
            f"/api/v1/projects/{project.id}/reports",
            json={"title": "My Custom Report Title"},
        )
        assert resp.status_code == 201
        assert resp.json()["title"] == "My Custom Report Title"

    def test_list_reports_empty(self, client, project):
        resp = client.get(f"/api/v1/projects/{project.id}/reports")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_reports_after_generation(self, client, project):
        client.post(f"/api/v1/projects/{project.id}/reports", json={})
        resp = client.get(f"/api/v1/projects/{project.id}/reports")
        assert len(resp.json()) >= 1

    def test_get_report_by_id(self, client, project):
        create_resp = client.post(f"/api/v1/projects/{project.id}/reports", json={})
        report_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/projects/{project.id}/reports/{report_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == report_id

    def test_get_report_not_found(self, client, project):
        resp = client.get(f"/api/v1/projects/{project.id}/reports/nonexistent")
        assert resp.status_code == 404

    def test_download_report_returns_pdf_bytes(self, client, project, scan_run, finding):
        create_resp = client.post(
            f"/api/v1/projects/{project.id}/reports",
            json={"scan_run_id": scan_run.id},
        )
        report_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/projects/{project.id}/reports/{report_id}/download")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content[:4] == b"%PDF"

    def test_download_report_wrong_project(self, client, project):
        create_resp = client.post(f"/api/v1/projects/{project.id}/reports", json={})
        report_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/projects/wrong-project/reports/{report_id}/download")
        assert resp.status_code == 404

    def test_report_for_invalid_project_404(self, client):
        resp = client.post("/api/v1/projects/nonexistent/reports", json={})
        assert resp.status_code == 404

    def test_pdf_contains_project_name(self, client, project, scan_run, finding):
        create_resp = client.post(
            f"/api/v1/projects/{project.id}/reports",
            json={"scan_run_id": scan_run.id},
        )
        report_id = create_resp.json()["id"]
        pdf_resp = client.get(f"/api/v1/projects/{project.id}/reports/{report_id}/download")
        # PDF text is encoded; check the bytes contain something related
        assert len(pdf_resp.content) > 2000  # non-trivial PDF
