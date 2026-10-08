import pytest
from fastapi.testclient import TestClient
from sentinel_evidence.api.app import app

client = TestClient(app)

def test_get_events_pagination():
    response = client.get("/api/v1/cases/case-1/events?page=1&size=1")
    assert response.status_code == 200
    data = response.json()
    assert data["page"] == 1
    assert data["size"] == 1
    assert len(data["items"]) == 1

def test_get_claims():
    response = client.get("/api/v1/cases/case-1/claims")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 5

def test_get_ai_explanation():
    response = client.get("/api/v1/cases/case-1/claims/C1/explain")
    assert response.status_code == 200
    data = response.json()
    assert "explanation" in data
    assert "This is an AI-generated explanation" in data["disclaimer"]

def test_case_isolation():
    response = client.get("/api/v1/cases/case-2/events")
    assert response.status_code == 403
    assert "Not authorized" in response.json()["detail"]
