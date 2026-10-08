import json
import os
from pathlib import Path
import pytest
from sentinel_evidence.db.cases import CaseStore
from sentinel_evidence.pipeline import analyze
from sentinel_evidence.monitoring.service import MonitorManager
from sentinel_evidence.monitoring.source import WorkspaceSource
from sentinel_evidence.notifications import changes

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture
def setup(tmp_path):
    workspace = tmp_path / "authorized"
    workspace.mkdir()
    store = CaseStore(tmp_path / "cases.db")
    case = store.create()
    manager = MonitorManager(store, workspace)
    manager.enable(case["case_id"])
    return workspace, store, case["case_id"], manager


def test_idle_workspace_and_benign_events_do_not_notify(setup):
    workspace, store, case_id, manager = setup
    manager.scan_once()
    assert store.notifications(case_id)["total"] == 0
    (workspace / "benign.jsonl").write_text('{"EventID":1,"Computer":"LAB","ProcessGuid":"normal","UtcTime":"2026-10-08T10:00:00Z","Image":"notepad.exe"}\n')
    manager.scan_once()
    assert len(store.report(case_id)["events"]) == 1
    assert store.notifications(case_id)["total"] == 0
    assert manager.status(case_id)["files_processed"] == 1


def test_shared_engine_deduplication_restart_and_unrelated_append(setup, monkeypatch):
    workspace, store, case_id, manager = setup
    path = workspace / "events.jsonl"
    contents = (FIXTURES / "tiny-supported.jsonl").read_bytes()
    path.write_bytes(contents)
    manager.scan_once()
    report = store.report(case_id)
    uploaded = analyze(contents, path.name)
    assert report["events"] == uploaded["events"]
    assert report["claims"] == uploaded["claims"]
    assert report["sources"][0]["collection_metadata"]["file_owner_uid"] == os.getuid()
    assert store.notifications(case_id)["total"] == 3
    with monkeypatch.context() as unchanged:
        unchanged.setattr("sentinel_evidence.monitoring.service.prepare_source",
                          lambda *args: pytest.fail("Unchanged evidence must not be normalized again"))
        manager.scan_once()
    assert manager.status(case_id)["files_processed"] == 0
    assert store.report(case_id) == report
    assert store.notifications(case_id)["total"] == 3
    restarted = MonitorManager(store, workspace)
    restarted.scan_once()
    assert store.report(case_id) == report
    assert store.notifications(case_id)["total"] == 3
    path.write_bytes(contents + b'{"EventID":22,"Computer":"LAB","ProcessGuid":"unrelated"}\n')
    manager.scan_once()
    assert store.notifications(case_id)["total"] == 3
    assert manager.status(case_id)["new_findings"] == 0
    assert manager.status(case_id)["new_claims"] == 0
    old_notification = store.notifications(case_id)["items"][0]
    archived = store.report(case_id, old_notification["revision_id"])
    assert archived["events"] == report["events"]
    assert store.original(case_id, report["sources"][0]["source_id"]) == contents


def test_new_source_correlates_with_existing_process_and_preserves_identity(setup):
    workspace, store, case_id, manager = setup
    lines = (FIXTURES / "tiny-supported.jsonl").read_bytes().splitlines(keepends=True)
    (workspace / "processes.jsonl").write_bytes(b"".join(lines[:2]))
    manager.scan_once()
    previous = store.report(case_id)["events"][0]
    (workspace / "activity.jsonl").write_bytes(b"".join(lines[2:]))
    manager.scan_once()
    report = store.report(case_id)
    assert len(report["sources"]) == 2
    assert len(report["claims"]) == 3
    assert previous in report["events"]
    assert manager.status(case_id)["files_processed"] == 1
    assert manager.status(case_id)["new_claims"] == 2
    assert store.notifications(case_id)["total"] == 3


@pytest.mark.parametrize("invalid", [b"{unfinished", b'{"EventID":1e999}',
                                    b'{"nested":' + b'[' * 70 + b'0' + b']' * 70 + b'}'])
def test_invalid_changed_source_isolated_and_recovers(setup, invalid):
    workspace, store, case_id, manager = setup
    good = (FIXTURES / "tiny-supported.jsonl").read_bytes()
    path = workspace / "events.jsonl"
    path.write_bytes(good)
    manager.scan_once()
    previous = store.report(case_id)
    path.write_bytes(invalid)
    (workspace / "extra.jsonl").write_bytes(b'{"EventID":22,"Computer":"OTHER"}\n')
    manager.scan_once()
    assert manager.status(case_id)["state"] == "error"
    assert store.notifications(case_id)["total"] == 3
    assert all(e in store.report(case_id)["events"] for e in previous["events"])
    path.write_bytes(good)
    manager.scan_once()
    assert manager.status(case_id)["state"] == "monitoring"
    assert store.notifications(case_id)["total"] == 3


def test_missing_source_and_collector_outage_preserve_last_good_analysis(setup, monkeypatch):
    workspace, store, case_id, manager = setup
    path = workspace / "events.jsonl"
    path.write_bytes((FIXTURES / "tiny-supported.jsonl").read_bytes())
    manager.scan_once()
    previous = store.report(case_id)
    path.unlink()
    manager.scan_once()
    assert manager.status(case_id)["state"] == "error"
    assert store.report(case_id) == previous
    def fail():
        raise OSError("offline")
    monkeypatch.setattr(manager.source, "poll", fail)
    manager.scan_once()
    assert manager.status(case_id)["state"] == "error"
    assert store.report(case_id) == previous
    assert store.notifications(case_id)["total"] == 3


def test_pause_resume_and_evidence_withdrawal(setup):
    workspace, store, case_id, manager = setup
    path = workspace / "events.jsonl"
    contents = (FIXTURES / "tiny-supported.jsonl").read_bytes()
    path.write_bytes(contents)
    manager.scan_once()
    previous = store.report(case_id)
    manager.pause(case_id)
    path.write_bytes(b"".join(line for line in contents.splitlines(keepends=True) if json.loads(line)["EventID"] != 3))
    manager.scan_once()
    assert store.report(case_id) == previous
    manager.enable(case_id)
    manager.scan_once()
    notifications = store.notifications(case_id)
    assert notifications["total"] == 4
    latest = notifications["items"][0]
    assert latest["type"] == "claim_withdrawn" and latest["historical"]
    assert latest["status"] == "supported_inference"
    assert any(c["claim_id"] == latest["claim_id"] for c in store.report(case_id, latest["revision_id"])["claims"])
    manager.scan_once()
    assert store.notifications(case_id)["total"] == 4


def test_symlinks_hardlinks_nested_and_unsupported_files_not_collected(setup, tmp_path):
    workspace, store, case_id, manager = setup
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes((FIXTURES / "tiny-supported.jsonl").read_bytes())
    (workspace / "symlink.jsonl").symlink_to(outside)
    os.link(outside, workspace / "hardlink.jsonl")
    (workspace / "nested").mkdir()
    (workspace / "nested" / "private.jsonl").write_bytes(outside.read_bytes())
    (workspace / "not-supported.txt").write_bytes(outside.read_bytes())
    manager.scan_once()
    assert not store.report(case_id)["events"]
    assert manager.status(case_id)["state"] == "error"
    assert len(manager.status(case_id)["errors"]) == 2
    assert store.notifications(case_id)["total"] == 0


def test_status_changes_not_ai_or_certainty_upgrades():
    report = analyze((FIXTURES / "tiny-supported.jsonl").read_bytes())
    previous = json.loads(json.dumps(report))
    report["claims"][0]["status"] = "hypothesis"
    report["claims"][0]["unmet_prerequisites"] = ["Conflicting evidence"]
    result = changes(previous, report)
    assert len(result) == 1
    assert result[0]["type"] == "claim_changed" and result[0]["status"] == "hypothesis"
    assert changes(report, report) == []
    upgrade = changes(report, previous)
    assert upgrade[0]["type"] == "claim_supported"
    assert "malware" not in json.dumps(result).lower()


def test_optional_desktop_sink_failure_does_not_break_in_app_notifications(setup):
    workspace, store, case_id, manager = setup
    class BrokenSink:
        def deliver(self, notification):
            raise OSError("desktop unavailable")
    manager.sink = BrokenSink()
    (workspace / "events.jsonl").write_bytes((FIXTURES / "tiny-supported.jsonl").read_bytes())
    manager.scan_once()
    assert manager.status(case_id)["state"] == "monitoring"
    assert store.notifications(case_id)["unread"] == 3


def test_resume_after_manual_import_restores_monitored_selection(setup):
    workspace, store, case_id, manager = setup
    contents = (FIXTURES / "tiny-supported.jsonl").read_bytes()
    (workspace / "events.jsonl").write_bytes(contents)
    manager.scan_once()
    expected = store.report(case_id)["claims"]
    manager.pause(case_id)
    manual = b'{"EventID":22}\n'
    store.save(case_id, analyze(manual), manual)
    assert not store.report(case_id)["claims"]
    manager.enable(case_id)
    manager.scan_once()
    assert store.report(case_id)["claims"] == expected


def test_local_owner_change_requires_reauthorization(setup, monkeypatch):
    workspace, store, case_id, manager = setup
    (workspace / "events.jsonl").write_bytes((FIXTURES / "tiny-supported.jsonl").read_bytes())
    original_uid = os.getuid()
    monkeypatch.setattr("sentinel_evidence.monitoring.service.os.getuid", lambda: original_uid + 1)
    manager.scan_once()
    assert manager.status(case_id)["state"] == "error"
    assert not store.report(case_id)["events"]
