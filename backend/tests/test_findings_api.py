"""Tests for the Findings API — list, get, filter, status update."""
import pytest
from datetime import datetime, timezone


def _create_project(client, name="FindingTestProject"):
    resp = client.post("/api/v1/projects/", json={"name": name})
    assert resp.status_code == 201
    return resp.json()


def _create_scan_run(db, project_id, status="completed"):
    from app.models.scan import ScanRun, ScanStatus
    import json
    run = ScanRun(
        project_id=project_id,
        status=ScanStatus.COMPLETED,
        scanner_config=json.dumps({"scanner_ids": None, "target_path": None}),
        summary=json.dumps({"total_raw": 2, "total_confirmed": 2, "by_severity": {}}),
    )
    db.add(run)
    db.flush()
    return run


def _create_finding(db, project_id, scan_run_id, **kwargs):
    from app.models.finding import Finding, SecurityCategory, Severity, Confidence, FindingStatus
    defaults = dict(
        project_id=project_id,
        scan_run_id=scan_run_id,
        scanner_id="secrets.hardcoded_credentials",
        title="Hardcoded Secret: Test Key",
        description="A test finding.",
        category=SecurityCategory.SECRETS,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        status=FindingStatus.DETECTED,
    )
    defaults.update(kwargs)
    finding = Finding(**defaults)
    db.add(finding)
    db.flush()
    return finding


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_empty(client):
    project = _create_project(client, "EmptyFindingsProject")
    resp = client.get(f"/api/v1/projects/{project['id']}/findings/")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_findings_invalid_project(client):
    resp = client.get("/api/v1/projects/nonexistent/findings/")
    assert resp.status_code == 404


def test_list_findings_returns_summary_fields(client, db):
    project = _create_project(client, "SummaryFieldsProject")
    run = _create_scan_run(db, project["id"])
    _create_finding(db, project["id"], run.id)
    db.commit()

    resp = client.get(f"/api/v1/projects/{project['id']}/findings/")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    f = findings[0]
    assert "id" in f
    assert "title" in f
    assert "severity" in f
    assert "confidence" in f
    assert "status" in f
    assert "scanner_id" in f
    assert "scan_run_id" in f


def test_list_findings_filter_by_severity(client, db):
    project = _create_project(client, "SeverityFilterProject")
    run = _create_scan_run(db, project["id"])
    from app.models.finding import Severity
    _create_finding(db, project["id"], run.id, severity=Severity.CRITICAL, title="Critical Finding")
    _create_finding(db, project["id"], run.id, severity=Severity.LOW, title="Low Finding")
    db.commit()

    resp = client.get(f"/api/v1/projects/{project['id']}/findings/", params={"severity": "CRITICAL"})
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_list_findings_filter_by_status(client, db):
    project = _create_project(client, "StatusFilterProject")
    run = _create_scan_run(db, project["id"])
    from app.models.finding import FindingStatus
    _create_finding(db, project["id"], run.id, status=FindingStatus.CONFIRMED, title="Confirmed Finding")
    _create_finding(db, project["id"], run.id, status=FindingStatus.REJECTED, title="Rejected Finding")
    db.commit()

    resp = client.get(f"/api/v1/projects/{project['id']}/findings/", params={"status": "CONFIRMED"})
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["status"] == "CONFIRMED"


def test_list_findings_filter_by_scan_id(client, db):
    project = _create_project(client, "ScanIdFilterProject")
    run_a = _create_scan_run(db, project["id"])
    run_b = _create_scan_run(db, project["id"])
    _create_finding(db, project["id"], run_a.id, title="Finding in scan A")
    _create_finding(db, project["id"], run_b.id, title="Finding in scan B")
    db.commit()

    resp = client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        params={"scan_id": run_a.id},
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["scan_run_id"] == run_a.id


# ---------------------------------------------------------------------------
# get_finding
# ---------------------------------------------------------------------------

def test_get_finding(client, db):
    project = _create_project(client, "GetFindingProject")
    run = _create_scan_run(db, project["id"])
    finding = _create_finding(db, project["id"], run.id, title="Detail Test Finding")
    db.commit()

    resp = client.get(f"/api/v1/projects/{project['id']}/findings/{finding.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == finding.id
    assert data["title"] == "Detail Test Finding"
    assert "evidence" in data
    assert "history" in data
    assert isinstance(data["evidence"], list)
    assert isinstance(data["history"], list)


def test_get_finding_not_found(client):
    project = _create_project(client, "GetNotFoundProject")
    resp = client.get(f"/api/v1/projects/{project['id']}/findings/nonexistent")
    assert resp.status_code == 404


def test_get_finding_wrong_project(client, db):
    project_a = _create_project(client, "WrongProjA")
    project_b = _create_project(client, "WrongProjB")
    run = _create_scan_run(db, project_a["id"])
    finding = _create_finding(db, project_a["id"], run.id)
    db.commit()

    resp = client.get(f"/api/v1/projects/{project_b['id']}/findings/{finding.id}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# update_finding_status
# ---------------------------------------------------------------------------

def test_update_finding_status(client, db):
    project = _create_project(client, "StatusUpdateProject")
    run = _create_scan_run(db, project["id"])
    finding = _create_finding(db, project["id"], run.id)
    db.commit()

    resp = client.patch(
        f"/api/v1/projects/{project['id']}/findings/{finding.id}/status",
        json={"status": "CONFIRMED", "note": "Manually verified."},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CONFIRMED"
    # History should record the transition
    assert len(data["history"]) >= 1
    history_entry = data["history"][-1]
    assert history_entry["to_status"] == "CONFIRMED"
    assert history_entry["note"] == "Manually verified."


def test_update_finding_status_invalid_finding(client):
    project = _create_project(client, "InvalidFindingUpdate")
    resp = client.patch(
        f"/api/v1/projects/{project['id']}/findings/nonexistent/status",
        json={"status": "CONFIRMED"},
    )
    assert resp.status_code == 404
