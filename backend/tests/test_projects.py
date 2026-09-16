"""Tests for the Project CRUD API."""
import pytest


def test_list_projects_empty(client):
    response = client.get("/api/v1/projects/")
    assert response.status_code == 200
    assert response.json() == []


def test_create_project(client):
    response = client.post("/api/v1/projects/", json={
        "name": "Test Assessment",
        "description": "A test security assessment project",
        "target_path": "/tmp/test-app",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Assessment"
    assert data["status"] == "active"
    assert "id" in data
    assert "created_at" in data


def test_create_project_minimal(client):
    response = client.post("/api/v1/projects/", json={"name": "Minimal Project"})
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Minimal Project"
    assert data["target_path"] is None
    assert data["target_url"] is None


def test_create_project_validation_fails(client):
    response = client.post("/api/v1/projects/", json={"name": ""})
    assert response.status_code == 422


def test_get_project(client):
    create_resp = client.post("/api/v1/projects/", json={"name": "GetTest"})
    project_id = create_resp.json()["id"]

    response = client.get(f"/api/v1/projects/{project_id}")
    assert response.status_code == 200
    assert response.json()["id"] == project_id


def test_get_project_not_found(client):
    response = client.get("/api/v1/projects/nonexistent-id")
    assert response.status_code == 404


def test_update_project(client):
    create_resp = client.post("/api/v1/projects/", json={"name": "Original Name"})
    project_id = create_resp.json()["id"]

    response = client.patch(f"/api/v1/projects/{project_id}", json={"name": "Updated Name"})
    assert response.status_code == 200
    assert response.json()["name"] == "Updated Name"


def test_delete_project(client):
    create_resp = client.post("/api/v1/projects/", json={"name": "ToDelete"})
    project_id = create_resp.json()["id"]

    response = client.delete(f"/api/v1/projects/{project_id}")
    assert response.status_code == 204

    get_response = client.get(f"/api/v1/projects/{project_id}")
    assert get_response.status_code == 404


def test_list_projects_returns_summary(client):
    client.post("/api/v1/projects/", json={"name": "Summary Test"})
    response = client.get("/api/v1/projects/")
    assert response.status_code == 200
    projects = response.json()
    assert len(projects) >= 1
    p = projects[0]
    assert "total_findings" in p
    assert "confirmed_findings" in p
    assert "critical_count" in p
