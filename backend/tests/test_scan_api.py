"""Tests for the scan trigger and status API."""
import pytest


def _create_project(client, name="Test Project", target_path=None):
    resp = client.post("/api/v1/projects/", json={
        "name": name,
        "target_path": target_path,
    })
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------

def test_list_scans_empty(client):
    project = _create_project(client, "EmptyScanProject")
    resp = client.get(f"/api/v1/projects/{project['id']}/scans/")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_invalid_project(client):
    resp = client.get("/api/v1/projects/nonexistent/scans/")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# trigger_scan
# ---------------------------------------------------------------------------

def test_trigger_scan_creates_pending_run(client):
    project = _create_project(client, "ScanTriggerTest")
    resp = client.post(f"/api/v1/projects/{project['id']}/scans/", json={})
    assert resp.status_code == 202
    data = resp.json()
    assert data["project_id"] == project["id"]
    assert data["status"] in ("pending", "running", "completed")
    assert "id" in data
    assert "scanner_results" in data
    assert isinstance(data["scanner_results"], list)


def test_trigger_scan_invalid_project(client):
    resp = client.post("/api/v1/projects/nonexistent/scans/", json={})
    assert resp.status_code == 404


def test_trigger_scan_with_scanner_ids(client):
    project = _create_project(client, "SelectiveScanTest")
    resp = client.post(
        f"/api/v1/projects/{project['id']}/scans/",
        json={"scanner_ids": ["secrets.hardcoded_credentials"]},
    )
    assert resp.status_code == 202
    data = resp.json()
    config = __import__("json").loads(data["scanner_config"])
    assert config["scanner_ids"] == ["secrets.hardcoded_credentials"]


# ---------------------------------------------------------------------------
# get_scan
# ---------------------------------------------------------------------------

def test_get_scan(client):
    project = _create_project(client, "GetScanTest")
    trigger_resp = client.post(f"/api/v1/projects/{project['id']}/scans/", json={})
    scan_id = trigger_resp.json()["id"]

    resp = client.get(f"/api/v1/projects/{project['id']}/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id
    assert data["project_id"] == project["id"]
    assert "scanner_results" in data


def test_get_scan_not_found(client):
    project = _create_project(client, "NotFoundScanTest")
    resp = client.get(f"/api/v1/projects/{project['id']}/scans/nonexistent")
    assert resp.status_code == 404


def test_get_scan_wrong_project(client):
    """A scan from project A is not visible under project B."""
    project_a = _create_project(client, "ProjectA")
    project_b = _create_project(client, "ProjectB")
    trigger_resp = client.post(f"/api/v1/projects/{project_a['id']}/scans/", json={})
    scan_id = trigger_resp.json()["id"]

    resp = client.get(f"/api/v1/projects/{project_b['id']}/scans/{scan_id}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# list_scanners
# ---------------------------------------------------------------------------

def test_list_scanners(client):
    resp = client.get("/api/v1/scanners/")
    assert resp.status_code == 200
    scanners = resp.json()
    assert isinstance(scanners, list)
    assert len(scanners) >= 1
    scanner = scanners[0]
    assert "scanner_id" in scanner
    assert "name" in scanner
    assert "description" in scanner
    assert "requires_running_app" in scanner
    assert "cwe_ids" in scanner


def test_scanners_include_static_and_dynamic(client):
    resp = client.get("/api/v1/scanners/")
    ids = {s["scanner_id"] for s in resp.json()}
    # Static scanners
    assert "secrets.hardcoded_credentials" in ids
    # Dynamic scanners
    assert "headers.http_security" in ids
    assert "xss.reflected" in ids
    # Dynamic vs static flag
    scanners = {s["scanner_id"]: s for s in resp.json()}
    assert scanners["headers.http_security"]["requires_running_app"] is True
    assert scanners["secrets.hardcoded_credentials"]["requires_running_app"] is False
