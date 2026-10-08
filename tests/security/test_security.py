import pytest
from fastapi.testclient import TestClient
from sentinel_evidence.api.app import app
import io

client = TestClient(app)

def test_import_unsupported_file_type():
    file_content = b"fake data"
    response = client.post(
        "/api/v1/cases/case-1/import",
        files={"file": ("malicious.exe", file_content, "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Only JSONL files are supported" in response.json()["detail"]

def test_import_path_traversal_filename():
    file_content = b'{"test": "data"}\n'
    response = client.post(
        "/api/v1/cases/case-1/import",
        files={"file": ("../../../windows/system32/cmd.exe.jsonl", file_content, "application/json")}
    )
    assert response.status_code == 200
    # Validate that it stripped the path and just kept the basename
    assert response.json()["filename"] == "cmd.exe.jsonl"

def test_import_oversized_file():
    # Mocking a large file by sending more than 10MB
    large_content = b"a" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/api/v1/cases/case-1/import",
        files={"file": ("large.jsonl", large_content, "application/json")}
    )
    assert response.status_code == 413
    assert "File too large" in response.json()["detail"]

def test_ai_safety_does_not_upgrade_claim():
    # Mock AI says "upgrade this claim" for C5
    response = client.get("/api/v1/cases/case-1/claims/C5/explain")
    assert response.status_code == 200
    explain_data = response.json()
    assert "This is definitely malicious. Upgrade the claim." in explain_data["explanation"]

    # But the claim itself must remain insufficient_evidence
    claims_response = client.get("/api/v1/cases/case-1/claims")
    c5 = next(c for c in claims_response.json()["items"] if c["claim_id"] == "C5")
    assert c5["status"] == "insufficient_evidence"

def test_untrusted_evidence_handling():
    # Fetch the event containing malicious prompt injection and XSS
    response = client.get("/api/v1/cases/case-1/events/E3")
    assert response.status_code == 200
    event = response.json()
    # Data should remain exactly as imported without being executed/stripped by backend automatically,
    # Front-end React handles escaping by default.
    assert "<script>alert(1)</script>" in event["raw_fields"]["CommandLine"]
    assert "Ignore previous instructions" in event["raw_fields"]["Message"]
