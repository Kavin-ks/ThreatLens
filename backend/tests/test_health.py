"""Tests for the health check endpoint."""


def test_health_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "timestamp" in data
    assert "version" in data
    assert "components" in data
    assert "database" in data["components"]


def test_health_database_connected(client):
    response = client.get("/health")
    data = response.json()
    assert data["components"]["database"]["status"] == "ok"


def test_readiness(client):
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_root(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
