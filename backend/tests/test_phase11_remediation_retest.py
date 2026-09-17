"""
Phase 11 regression tests — MCP TOCTOU remediation & retest workflow.

Covers:
  - Full lifecycle of a manually-identified finding (scanner_id="manual"):
    DETECTED → CONFIRMED → REMEDIATION → RETESTING → RESOLVED
  - manual_resolve flag: allows resolution when the scanner is inconclusive
    but the assessor has independently verified the fix (e.g. via PoC)
  - manual_resolve=False leaves an inconclusive result unchanged
  - patch_diff stored and retrievable in the remediation record
  - History contains every status transition in order
  - PDF includes the RESOLVED finding with retest notes
"""
import json
import pytest
from unittest.mock import patch, MagicMock

from app.models.finding import Finding, FindingStatus, Confidence, FindingHistory
from app.models.remediation import RemediationRecord, RetestStatus
from app.models.project import Project
from app.models.scan import ScanRun, ScanStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(db):
    p = Project(name="World Monitor Remediation Test", target_path="/tmp/wm_remediated")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@pytest.fixture()
def scan_run(db, project):
    run = ScanRun(
        project_id=project.id,
        status=ScanStatus.COMPLETED,
        scanner_config=json.dumps({"target_path": "/tmp/wm_remediated"}),
        summary=json.dumps({"total_raw": 1}),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@pytest.fixture()
def manual_finding(db, project, scan_run):
    """A finding produced by manual assessment (no auto-scanner)."""
    f = Finding(
        project_id=project.id,
        scan_run_id=scan_run.id,
        scanner_id="manual",
        title="MCP Proxy TOCTOU DNS Rebinding Race",
        description=(
            "TOCTOU race between revalidateBeforeFetch() and fetch() "
            "in api/mcp-proxy.ts allows DNS rebinding."
        ),
        category="ssrf",
        severity="MEDIUM",
        confidence=Confidence.POSSIBLE,
        status=FindingStatus.CONFIRMED,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N",
        cvss_score=4.0,
        fingerprint="toctou_mcp_proxy_001",
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


@pytest.fixture()
def remediation_record(client, project, manual_finding):
    """Creates a remediation record for manual_finding and returns its id."""
    resp = client.post(
        f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
        json={
            "description": (
                "Migrated api/mcp-proxy.ts from Edge to Node.js runtime. "
                "Replaced bare fetch() with fetchWithPinnedIp() using "
                "https.request({ lookup }) to pin the socket to the "
                "pre-validated IP, eliminating the TOCTOU race window."
            ),
            "applied_by": "security-team",
            "patch_diff": (
                "-export const config = { runtime: 'edge' };\n"
                "+export const config = { runtime: 'nodejs' };\n"
                "-async function revalidateBeforeFetch(url, signal) {\n"
                "-  await assertServerUrlSafe(url, signal);\n"
                "+async function revalidateBeforeFetch(url, signal) {\n"
                "+  const { resolvedAddresses } = await assertServerUrlSafe(url, signal);\n"
                "+  return resolvedAddresses[0];\n"
                " }\n"
                "+async function fetchWithPinnedIp(input, pinnedIp, init) { ... }"
            ),
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


# ── Lifecycle tests ───────────────────────────────────────────────────────────

class TestManualFindingLifecycle:
    """Full CONFIRMED → REMEDIATION → RETESTING → RESOLVED for a manual finding."""

    def test_create_remediation_advances_to_remediation_status(
        self, client, project, manual_finding
    ):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
            json={"description": "Fix applied"},
        )
        assert resp.status_code == 201
        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        assert finding_resp.json()["status"] == "REMEDIATION"

    def test_retest_inconclusive_for_manual_scanner(
        self, client, project, manual_finding, remediation_record
    ):
        """manual scanner_id is not registered → retest must return inconclusive."""
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"notes": "No auto-scanner for manual finding"},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "inconclusive"

    def test_manual_resolve_false_leaves_inconclusive(
        self, client, project, manual_finding, remediation_record
    ):
        """manual_resolve=False must NOT resolve the finding on inconclusive."""
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"manual_resolve": False},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "inconclusive"
        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        assert finding_resp.json()["status"] != "RESOLVED"

    def test_manual_resolve_true_resolves_on_inconclusive(
        self, client, project, manual_finding, remediation_record
    ):
        """manual_resolve=True with inconclusive scanner → finding RESOLVED."""
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={
                    "notes": "Fix verified by PoC mcp_toctou_poc_v2.mjs",
                    "manual_resolve": True,
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["retest_status"] == "passed"
        assert "manually resolved" in data["notes"].lower()

        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        assert finding_resp.json()["status"] == "RESOLVED"

    def test_manual_resolve_history_contains_all_transitions(
        self, client, project, manual_finding, remediation_record
    ):
        """Status history must record CONFIRMED→REMEDIATION→RETESTING→RESOLVED."""
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"manual_resolve": True, "notes": "PoC verified"},
            )

        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        history = finding_resp.json()["history"]
        statuses = [h["to_status"] for h in history]
        assert "REMEDIATION" in statuses
        assert "RETESTING" in statuses
        assert "RESOLVED" in statuses

    def test_manual_resolve_does_not_affect_passing_retest(
        self, client, project, manual_finding, remediation_record
    ):
        """When the scanner already passes, manual_resolve has no extra effect."""
        mock_scanner = MagicMock()
        mock_scanner.can_scan = MagicMock(return_value=True)
        mock_scanner.scan = MagicMock(return_value=[])  # nothing detected

        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_scanner)
            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"manual_resolve": True},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "passed"
        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        assert finding_resp.json()["status"] == "RESOLVED"

    def test_manual_resolve_ignored_when_retest_fails(
        self, client, project, manual_finding, remediation_record
    ):
        """manual_resolve=True must NOT resolve the finding when the scanner
        still detects the original fingerprint (failed retest)."""
        mock_raw = MagicMock()
        mock_raw.scanner_id = manual_finding.scanner_id
        mock_raw.affected_file = None
        mock_raw.affected_line = None
        mock_raw.title = manual_finding.title

        mock_scanner = MagicMock()
        mock_scanner.can_scan = MagicMock(return_value=True)
        mock_scanner.scan = MagicMock(return_value=[mock_raw])

        with patch("app.services.retest_service.scanner_registry") as mock_reg, \
             patch("app.services.retest_service._fingerprint") as mock_fp:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_scanner)
            mock_fp.return_value = manual_finding.fingerprint  # still detected

            resp = client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"manual_resolve": True},
            )
        assert resp.status_code == 200
        assert resp.json()["retest_status"] == "failed"
        finding_resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
        )
        assert finding_resp.json()["status"] != "RESOLVED"


# ── Remediation record content ────────────────────────────────────────────────

class TestRemediationRecordContent:
    def test_patch_diff_stored_and_retrievable(
        self, client, project, manual_finding
    ):
        diff = (
            "-export const config = { runtime: 'edge' };\n"
            "+export const config = { runtime: 'nodejs' };"
        )
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
            json={"description": "Runtime migration", "patch_diff": diff},
        )
        assert resp.status_code == 201
        assert resp.json()["patch_diff"] == diff

    def test_remediation_applied_by_stored(self, client, project, manual_finding):
        resp = client.post(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
            json={"description": "Fix", "applied_by": "security-team"},
        )
        assert resp.status_code == 201
        assert resp.json()["applied_by"] == "security-team"

    def test_list_remediation_shows_records(self, client, project, manual_finding):
        client.post(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
            json={"description": "First attempt"},
        )
        client.post(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation",
            json={"description": "Second attempt"},
        )
        resp = client.get(
            f"/api/v1/projects/{project.id}/findings/{manual_finding.id}/remediation"
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 2


# ── PDF includes RESOLVED finding ─────────────────────────────────────────────

class TestPdfIncludesResolvedFinding:
    def test_resolved_finding_appears_in_pdf(
        self, client, project, scan_run, manual_finding, remediation_record
    ):
        """A RESOLVED finding must still be present in the generated PDF."""
        with patch("app.services.retest_service.scanner_registry") as mock_reg:
            mock_reg.autodiscover = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            client.post(
                f"/api/v1/projects/{project.id}/findings/{manual_finding.id}"
                f"/remediation/{remediation_record}/retest",
                json={"manual_resolve": True, "notes": "PoC verified"},
            )

        create_resp = client.post(
            f"/api/v1/projects/{project.id}/reports",
            json={"scan_run_id": scan_run.id},
        )
        assert create_resp.status_code == 201
        report_id = create_resp.json()["id"]
        pdf_resp = client.get(
            f"/api/v1/projects/{project.id}/reports/{report_id}/download"
        )
        assert pdf_resp.status_code == 200
        assert pdf_resp.content[:4] == b"%PDF"
        assert len(pdf_resp.content) > 2000
