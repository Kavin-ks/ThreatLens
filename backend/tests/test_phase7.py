"""
Phase 7 tests: CVSS scoring, AI triage (mocked), global endpoints,
dashboard stats, scanner config.
"""
import json
import pytest
from fastapi.testclient import TestClient

from app.models.finding import Finding, FindingStatus, Confidence
from app.models.project import Project
from app.models.scan import ScanRun, ScanStatus


# ─── Module-level fixtures ────────────────────────────────────────────────────

@pytest.fixture()
def sample_project(db):
    p = Project(name="Phase7 Project", target_path="/tmp/phase7repo")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@pytest.fixture()
def sample_scan(db, sample_project):
    run = ScanRun(
        project_id=sample_project.id,
        status=ScanStatus.COMPLETED,
        scanner_config=json.dumps({"target_path": "/tmp/phase7repo"}),
        summary=json.dumps({"total_raw": 1}),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@pytest.fixture()
def sample_finding(db, sample_project, sample_scan):
    f = Finding(
        project_id=sample_project.id,
        scan_run_id=sample_scan.id,
        scanner_id="bandit_scanner",
        title="SQL Injection in login handler",
        description="Unsanitised user input passed directly to SQL query.",
        category="injection",
        severity="HIGH",
        confidence=Confidence.CONFIRMED,
        status=FindingStatus.CONFIRMED,
        fingerprint="phase7fp001",
        cwe_id="CWE-89",
        owasp_category="A03:2021",
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


# ─── CVSS utility ─────────────────────────────────────────────────────────────

class TestCvssCalculator:
    def test_critical_full_score(self):
        from app.utils.cvss import calculate_cvss31
        score, sev = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0
        assert sev == "CRITICAL"

    def test_high_scope_unchanged(self):
        from app.utils.cvss import calculate_cvss31
        score, sev = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        assert score == 9.1
        assert sev == "CRITICAL"

    def test_medium_score(self):
        from app.utils.cvss import calculate_cvss31
        score, sev = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
        assert 4.0 <= score < 7.0
        assert sev == "MEDIUM"

    def test_zero_impact(self):
        from app.utils.cvss import calculate_cvss31
        score, sev = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0
        assert sev == "NONE"

    def test_missing_metric_raises(self):
        from app.utils.cvss import calculate_cvss31
        with pytest.raises(ValueError):
            calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H")

    def test_invalid_value_raises(self):
        from app.utils.cvss import calculate_cvss31
        with pytest.raises(ValueError):
            calculate_cvss31("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")

    def test_score_to_severity_boundaries(self):
        from app.utils.cvss import score_to_severity
        assert score_to_severity(0.0) == "NONE"
        assert score_to_severity(3.9) == "LOW"
        assert score_to_severity(4.0) == "MEDIUM"
        assert score_to_severity(6.9) == "MEDIUM"
        assert score_to_severity(7.0) == "HIGH"
        assert score_to_severity(8.9) == "HIGH"
        assert score_to_severity(9.0) == "CRITICAL"
        assert score_to_severity(10.0) == "CRITICAL"

    def test_default_vectors_are_valid(self):
        from app.utils.cvss import default_vector_for_severity, calculate_cvss31
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            vec = default_vector_for_severity(sev)
            assert vec is not None
            score, _ = calculate_cvss31(vec)
            assert 0.0 <= score <= 10.0


# ─── CVSS API endpoint ────────────────────────────────────────────────────────

class TestCvssEndpoint:
    def test_calculate_and_store_cvss(
        self, client: TestClient, sample_project, sample_finding
    ):
        project_id = sample_project.id
        finding_id = sample_finding.id
        resp = client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/cvss",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cvss_score"] == 9.1
        assert data["severity_label"] == "CRITICAL"
        assert "CVSS:3.1" in data["cvss_vector"]

    def test_cvss_persisted_in_finding(
        self, client: TestClient, sample_project, sample_finding
    ):
        project_id = sample_project.id
        finding_id = sample_finding.id
        client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/cvss",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        )
        resp = client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}")
        assert resp.status_code == 200
        finding = resp.json()
        assert finding["cvss_score"] == 9.1
        assert finding["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_invalid_vector_returns_422(
        self, client: TestClient, sample_project, sample_finding
    ):
        resp = client.post(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/cvss",
            json={"vector": "CVSS:3.1/AV:N/AC:L"},
        )
        assert resp.status_code == 422

    def test_cvss_wrong_project_404(self, client: TestClient, sample_finding):
        resp = client.post(
            f"/api/v1/projects/nonexistent/findings/{sample_finding.id}/cvss",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        )
        assert resp.status_code == 404


# ─── AI analysis (mocked) ─────────────────────────────────────────────────────

def _make_mock_triage(monkeypatch):
    """Patch run_ai_triage so tests work without a real API key."""
    from app.models.ai_analysis import AiAnalysis
    from sqlalchemy import select

    def _fake_triage(db, finding):
        existing = db.execute(
            select(AiAnalysis).where(AiAnalysis.finding_id == finding.id)
        ).scalar_one_or_none()
        if existing:
            return existing
        a = AiAnalysis(
            finding_id=finding.id,
            model_used="mock",
            technical_explanation="Test technical explanation.",
            impact_assessment="Test impact.",
            false_positive_likelihood="low",
            false_positive_reasoning="Unlikely to be false positive.",
            remediation_recommendation="Fix the code.",
            analyst_summary="High-risk finding.",
            raw_response_json="{}",
        )
        db.add(a)
        db.commit()
        db.refresh(a)
        return a

    monkeypatch.setattr("app.api.v1.findings.run_ai_triage", _fake_triage)


class TestAiAnalysis:
    def test_ai_analyze_returns_analysis(
        self, monkeypatch, client: TestClient, sample_project, sample_finding
    ):
        _make_mock_triage(monkeypatch)
        resp = client.post(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == sample_finding.id
        assert data["technical_explanation"] is not None
        assert data["false_positive_likelihood"] == "low"

    def test_ai_analyze_idempotent(
        self, monkeypatch, client: TestClient, sample_project, sample_finding
    ):
        _make_mock_triage(monkeypatch)
        url = f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        r1 = client.post(url)
        r2 = client.post(url)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["finding_id"] == r2.json()["finding_id"]

    def test_get_ai_analysis_after_run(
        self, monkeypatch, client: TestClient, sample_project, sample_finding
    ):
        _make_mock_triage(monkeypatch)
        client.post(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        resp = client.get(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        assert resp.status_code == 200
        assert resp.json()["finding_id"] == sample_finding.id

    def test_get_ai_analysis_not_found(
        self, client: TestClient, sample_project, sample_finding
    ):
        resp = client.get(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        assert resp.status_code == 404

    def test_ai_disabled_returns_400(
        self, client: TestClient, sample_project, sample_finding
    ):
        """When ENABLE_AI_TRIAGE=false (default), endpoint returns 400."""
        resp = client.post(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        assert resp.status_code == 400

    def test_finding_includes_ai_analysis(
        self, monkeypatch, client: TestClient, sample_project, sample_finding
    ):
        _make_mock_triage(monkeypatch)
        client.post(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}/analyze"
        )
        resp = client.get(
            f"/api/v1/projects/{sample_project.id}/findings/{sample_finding.id}"
        )
        assert resp.status_code == 200
        assert resp.json()["ai_analysis"] is not None


# ─── Global findings ──────────────────────────────────────────────────────────

class TestGlobalFindings:
    def test_list_all_empty(self, client: TestClient):
        resp = client.get("/api/v1/findings/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_all_has_finding(
        self, client: TestClient, sample_project, sample_finding
    ):
        resp = client.get("/api/v1/findings/")
        assert resp.status_code == 200
        ids = [f["id"] for f in resp.json()]
        assert sample_finding.id in ids

    def test_filter_by_severity(self, client: TestClient, sample_finding):
        sev = sample_finding.severity
        resp = client.get(f"/api/v1/findings/?severity={sev}")
        assert resp.status_code == 200
        for f in resp.json():
            assert f["severity"] == sev

    def test_filter_by_project(self, client: TestClient, sample_project, sample_finding):
        resp = client.get(f"/api/v1/findings/?project_id={sample_project.id}")
        assert resp.status_code == 200
        for f in resp.json():
            assert f["project_id"] == sample_project.id

    def test_filter_by_status(self, client: TestClient, sample_finding):
        resp = client.get("/api/v1/findings/?status=CONFIRMED")
        assert resp.status_code == 200
        for f in resp.json():
            assert f["status"] == "CONFIRMED"

    def test_search_by_title_fragment(self, client: TestClient, sample_finding):
        fragment = sample_finding.title[:6]
        resp = client.get(f"/api/v1/findings/?search={fragment}")
        assert resp.status_code == 200
        ids = [f["id"] for f in resp.json()]
        assert sample_finding.id in ids

    def test_findings_include_project_id(self, client: TestClient, sample_finding):
        resp = client.get("/api/v1/findings/")
        assert resp.status_code == 200
        for f in resp.json():
            assert "project_id" in f


# ─── Global scans ─────────────────────────────────────────────────────────────

class TestGlobalScans:
    def test_list_all_empty(self, client: TestClient):
        resp = client.get("/api/v1/scans/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_all_has_scan(self, client: TestClient, sample_scan):
        resp = client.get("/api/v1/scans/")
        assert resp.status_code == 200
        ids = [s["id"] for s in resp.json()]
        assert sample_scan.id in ids

    def test_filter_by_project(self, client: TestClient, sample_project, sample_scan):
        resp = client.get(f"/api/v1/scans/?project_id={sample_project.id}")
        assert resp.status_code == 200
        for s in resp.json():
            assert s["project_id"] == sample_project.id

    def test_filter_by_status(self, client: TestClient, sample_scan):
        resp = client.get("/api/v1/scans/?status=completed")
        assert resp.status_code == 200
        for s in resp.json():
            assert s["status"] == "completed"


# ─── Dashboard stats ──────────────────────────────────────────────────────────

class TestDashboardStats:
    def test_stats_empty_db(self, client: TestClient):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_projects"] == 0
        assert data["total_findings"] == 0

    def test_stats_with_project(self, client: TestClient, sample_project):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_projects"] >= 1
        assert data["active_projects"] >= 1

    def test_stats_with_finding(self, client: TestClient, sample_finding):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] >= 1
        sev_dist = data["severity_distribution"]
        total_in_dist = sum(sev_dist.values())
        assert total_in_dist >= 1

    def test_stats_keys_present(self, client: TestClient):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        required = {
            "total_projects", "active_projects", "total_findings",
            "confirmed_findings", "resolved_findings", "critical_findings",
            "high_findings", "total_scans", "running_scans",
            "severity_distribution", "status_distribution", "recent_scans_count",
        }
        assert required.issubset(data.keys())

    def test_confirmed_count_increments(self, client: TestClient, sample_finding):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        # sample_finding has status=CONFIRMED
        assert resp.json()["confirmed_findings"] >= 1


# ─── Scanner config ───────────────────────────────────────────────────────────

class TestScannerConfig:
    def test_get_default_config(self, client: TestClient, sample_project):
        resp = client.get(f"/api/v1/projects/{sample_project.id}/scanner-config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["project_id"] == sample_project.id
        assert data["enabled_scanners"] is None
        assert data["authorized_targets"] == []

    def test_update_enabled_scanners(self, client: TestClient, sample_project):
        resp = client.patch(
            f"/api/v1/projects/{sample_project.id}/scanner-config",
            json={"enabled_scanners": ["bandit_scanner", "dependency_scanner"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled_scanners"] == ["bandit_scanner", "dependency_scanner"]

    def test_update_authorized_targets(self, client: TestClient, sample_project):
        resp = client.patch(
            f"/api/v1/projects/{sample_project.id}/scanner-config",
            json={"authorized_targets": ["http://localhost:8080", "http://localhost:3000"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "http://localhost:8080" in data["authorized_targets"]

    def test_config_persists_across_requests(self, client: TestClient, sample_project):
        client.patch(
            f"/api/v1/projects/{sample_project.id}/scanner-config",
            json={"enabled_scanners": ["only_this_scanner"]},
        )
        resp = client.get(f"/api/v1/projects/{sample_project.id}/scanner-config")
        assert resp.status_code == 200
        assert resp.json()["enabled_scanners"] == ["only_this_scanner"]

    def test_reenable_all_scanners_via_empty_list(self, client: TestClient, sample_project):
        client.patch(
            f"/api/v1/projects/{sample_project.id}/scanner-config",
            json={"enabled_scanners": ["one_scanner"]},
        )
        client.patch(
            f"/api/v1/projects/{sample_project.id}/scanner-config",
            json={"enabled_scanners": []},
        )
        resp = client.get(f"/api/v1/projects/{sample_project.id}/scanner-config")
        assert resp.status_code == 200
        assert resp.json()["enabled_scanners"] == []

    def test_config_wrong_project_404(self, client: TestClient):
        resp = client.get("/api/v1/projects/nonexistent/scanner-config")
        assert resp.status_code == 404
