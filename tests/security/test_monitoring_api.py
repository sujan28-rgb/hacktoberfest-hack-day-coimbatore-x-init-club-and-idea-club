from pathlib import Path
from fastapi.testclient import TestClient
from sentinel_evidence.api.app import app

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def test_authorization_notifications_and_historical_drilldown(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path / "cases.db"))
    monkeypatch.delenv("SENTINEL_EVIDENCE_WORKSPACE", raising=False)
    with TestClient(app) as client:
        case = client.post("/api/v1/cases").json()
        other = client.post("/api/v1/cases").json()
        base = "/api/v1/cases/" + case["case_id"]
        auth = {"Authorization": "Bearer " + case["token"]}
        wrong = {"Authorization": "Bearer " + other["token"]}
        for endpoint in ("/monitor", "/notifications"):
            assert client.get(base + endpoint).status_code == 404
            assert client.get(base + endpoint, headers=wrong).status_code == 404
        assert client.post(base + "/monitor/start", headers=auth).status_code == 400
        assert client.get(base + "/monitor", headers=auth).json()["configured"] is False
        good = (FIXTURES / "tiny-supported.jsonl").read_bytes()
        assert client.post(base + "/import", headers=auth, files={"file": ("events.jsonl", good)}).status_code == 200
        notifications = client.get(base + "/notifications", headers=auth).json()
        assert notifications["unread"] == 3
        item = notifications["items"][0]
        path = base + "/notifications/" + item["notification_id"] + "/read"
        assert client.post(path, headers=wrong).status_code == 404
        assert client.post(path, headers=auth).status_code == 200
        assert client.get(base + "/notifications", headers=auth).json()["unread"] == 2
        client.post(base + "/import", headers=auth, files={"file": ("benign.jsonl", b'{"EventID":22}\n')})
        revision = "?revision=" + item["revision_id"]
        assert client.get(base + "/claims/" + item["claim_id"] + revision, headers=auth).status_code == 200
        event_id = item["supporting_event_ids"][0]
        assert client.get(base + "/events/" + event_id + revision, headers=auth).status_code == 200
        assert client.get(base + "/report?revision=missing", headers=auth).status_code == 404
        other_base = "/api/v1/cases/" + other["case_id"]
        assert client.get(other_base + "/report" + revision, headers=wrong).status_code == 404


def test_worker_lifecycle_authorized_start_pause_and_no_manual_race(tmp_path, monkeypatch):
    workspace = tmp_path / "authorized"
    workspace.mkdir()
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path / "cases.db"))
    monkeypatch.setenv("SENTINEL_EVIDENCE_WORKSPACE", str(workspace))
    with TestClient(app) as client:
        case = client.post("/api/v1/cases").json()
        auth = {"Authorization": "Bearer " + case["token"]}
        base = "/api/v1/cases/" + case["case_id"]
        assert app.state.monitor.thread.is_alive()
        assert client.post(base + "/monitor/start", headers=auth).status_code == 200
        assert client.post(base + "/import", headers=auth, files={"file": ("a.jsonl", b'{"EventID":1}')}).status_code == 409
        assert client.post(base + "/monitor/pause", headers=auth).json()["state"] == "paused"
        assert client.post(base + "/import", headers=auth, files={"file": ("a.jsonl", b'{"EventID":1}')}).status_code == 200
    assert not app.state.monitor.thread.is_alive()
