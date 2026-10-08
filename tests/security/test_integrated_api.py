from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sentinel_evidence.api.app import app
from sentinel_evidence.explain.ollama import Ollama, validate_output
from sentinel_evidence.pipeline import MAX_BYTES

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path / "cases.db"))
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    with TestClient(app) as client:
        yield client


def case(client):
    result = client.post("/api/v1/cases")
    assert result.status_code == 201
    data = result.json()
    return f'/api/v1/cases/{data["case_id"]}', {"Authorization": f'Bearer {data["token"]}'}


def test_real_import_drilldown_case_isolation_and_fallback(client):
    base, auth = case(client)
    other, other_auth = case(client)
    contents = (FIXTURE / "tiny-supported.jsonl").read_bytes()
    result = client.post(base + "/import", headers=auth, files={"file": ("events.jsonl", contents)})
    assert result.status_code == 200
    events = client.get(base + "/events", headers=auth).json()
    claims = client.get(base + "/claims", headers=auth).json()
    assert events["total"] == 4 and claims["total"] == 3
    event = events["items"][0]
    claim = claims["items"][0]
    assert client.get(base + "/events/" + event["event_id"], headers=auth).status_code == 200
    assert client.get(other + "/events/" + event["event_id"], headers=other_auth).status_code == 404
    assert client.get(base + "/events", headers=other_auth).status_code == 404
    assert client.get(base + "/events").status_code == 404
    assert client.get(base + "/sources/" + event["source_id"] + "/original", headers=auth).content == contents
    assert client.get(base + "/claims/" + claim["claim_id"] + "/packet", headers=auth).status_code == 200
    assert client.get(base + "/claims/" + claim["claim_id"] + "/explain", headers=auth).json()["status"] == "deterministic_fallback"
    assert client.get(base + "/claims/fabricated/explain", headers=auth).status_code == 404
    assert client.get(base + "/events?page=0", headers=auth).status_code == 422
    assert client.get(base + "/events?size=101", headers=auth).status_code == 422


@pytest.mark.parametrize("filename,contents,status", [
    ("../outside.jsonl", b"{}", 400), ("bad.txt", b"{}", 400),
    ("bad.jsonl", b"not JSON", 400), ("bad.jsonl", b"[]", 400),
    ("bad.jsonl", b'{"ProcessGuid":{}}', 400), ("bad.jsonl", b'{"v":NaN}', 400),
    ("big.jsonl", b"x" * (MAX_BYTES + 1), 413),
])
def test_hostile_uploads_do_not_modify_case(client, filename, contents, status):
    base, auth = case(client)
    assert client.post(base + "/import", headers=auth, files={"file": (filename, contents)}).status_code == status
    assert client.get(base + "/events", headers=auth).json()["total"] == 0


def test_hostile_record_is_data_and_malformed_reimport_is_atomic(client):
    base, auth = case(client)
    contents = (FIXTURE / "tiny-hostile.jsonl").read_bytes()
    assert client.post(base + "/import", headers=auth, files={"file": ("hostile.jsonl", contents)}).status_code == 200
    before = client.get(base + "/report", headers=auth).json()
    assert "<script>" in before["events"][0]["raw_fields"]["CommandLine"]
    assert client.post(base + "/import", headers=auth, files={"file": ("bad.jsonl", b"no")} ).status_code == 400
    assert client.get(base + "/report", headers=auth).json() == before


@pytest.mark.parametrize("url", ["https://example.com", "http://example.com", "http://127.0.0.1@example.com", "http://127.0.0.1/path"])
def test_cloud_and_redirect_endpoints_rejected(monkeypatch, url):
    monkeypatch.setenv("OLLAMA_URL", url)
    with pytest.raises(ValueError):
        Ollama()


def test_fabricated_ids_status_upgrade_and_extra_facts_rejected():
    approved = {"claim_id": "c1", "status": "insufficient_evidence", "evidence_ids": ["e1"], "explanation": "Not established"}
    for update in ({"claim_id": "c2"}, {"status": "observed"}, {"evidence_ids": ["invented"]}, {"extra": "malware"}):
        assert not validate_output({**approved, **update}, approved)
