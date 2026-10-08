"""Persistent background monitoring; all findings come from the shared engine."""
import hashlib
import logging
import os
import socket
import threading
from datetime import datetime, timezone
from sentinel_evidence.pipeline import prepare_source, investigate
from sentinel_evidence.notifications import claim_states, digest
from sentinel_evidence.monitoring.source import WorkspaceSource

logger = logging.getLogger(__name__)


def now():
    return datetime.now(timezone.utc).isoformat()


class MonitorManager:
    def __init__(self, store, workspace=None, interval=5, source=None, sink=None):
        self.store = store
        self.workspace = workspace
        self.source = source
        self.interval = max(1, min(300, interval))
        self.sink = sink
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.prepared = {}

    def start(self):
        self.thread = threading.Thread(target=self._loop, name="sentinel-monitor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake.set()
        if self.thread:
            self.thread.join()

    def _source(self):
        if self.source is None:
            if not self.workspace:
                raise ValueError("Set SENTINEL_EVIDENCE_WORKSPACE to authorize an evidence folder first")
            try:
                self.source = WorkspaceSource(self.workspace)
            except (OSError, ValueError) as error:
                raise ValueError("Configured evidence workspace is unavailable") from error
        return self.source

    def status(self, case_id):
        state = self.store.monitor(case_id) or {
            "enabled": False, "state": "not_configured", "last_scan": None,
            "last_success": None, "files_discovered": 0, "files_processed": 0,
            "events_processed": 0, "new_findings": 0, "new_claims": 0, "errors": {},
        }
        # Rejected-content fingerprints are internal deduplication bookkeeping.
        return {k: v for k, v in {
            **state, "configured": bool(self.workspace or self.source),
            "interval_seconds": self.interval,
            "unread_notifications": self.store.notifications(case_id, size=1)["unread"],
            "revision_id": (self.store.report(case_id).get("run") or {}).get("run_id"),
        }.items() if k != "rejected"}

    def enable(self, case_id):
        with self.lock:
            source = self._source()
            state = self.store.monitor(case_id)
            if state and state["workspace_key"] != source.key:
                raise ValueError("The authorized workspace changed. Create a new investigation to authorize it.")
            if state is None:
                state = {**self.status(case_id), "rejected": {}, "owner_account": f"uid:{os.getuid()}",
                         "collector_device": socket.gethostname(), "workspace": source.label}
            state.update(state="monitoring", enabled=True, error=None)
            self.store.set_monitor(case_id, source.key, True, state)
        self.wake.set()
        return self.status(case_id)

    def pause(self, case_id):
        # Wait for any in-flight transaction before acknowledging pause.
        with self.lock:
            state = self.store.monitor(case_id)
            if state:
                state.update(state="paused", enabled=False)
                self.store.set_monitor(case_id, state["workspace_key"], False, state)
        return self.status(case_id)

    def retry(self, case_id):
        with self.lock:
            state = self.store.monitor(case_id)
            if not state or not state["enabled"]:
                raise ValueError("Start or resume monitoring before retrying")
            state["rejected"] = {}
            self.store.set_monitor(case_id, state["workspace_key"], True, state)
        self.wake.set()
        return self.status(case_id)

    def _loop(self):
        while not self.stop_event.is_set():
            self.wake.clear()
            try:
                self.scan_once()
            except Exception:
                # A storage outage must not stop all future retry attempts.
                logger.exception("Monitoring scan failed; the worker will retry")
            self.wake.wait(self.interval)

    def scan_once(self):
        for case_id in self.store.enabled_monitors():
            if self.stop_event.is_set():
                break
            self.scan_case(case_id)

    def scan_case(self, case_id):
        with self.lock:
            state = self.store.monitor(case_id)
            if not state or not state["enabled"]:
                return
            state.update(state="processing", last_scan=now(), error=None,
                         files_processed=0, events_processed=0, new_findings=0, new_claims=0)
            self.store.set_monitor(case_id, state["workspace_key"], True, state)
            try:
                self._scan(case_id, state)
            except Exception as error:
                state.update(state="error", error=str(error) if isinstance(error, ValueError) else "Evidence source unavailable; previous investigation preserved")
                self.store.set_monitor(case_id, state["workspace_key"], True, state)
                logger.warning("Monitoring source failed for case %s: %s", case_id, type(error).__name__)

    def _scan(self, case_id, state):
        if state.get("owner_account") != f"uid:{os.getuid()}" or state.get("collector_device") != socket.gethostname():
            raise ValueError("The local account or collector device changed; authorize a new investigation")
        source = self._source()
        if source.key != state["workspace_key"]:
            raise ValueError("Configured workspace no longer matches the authorized workspace")
        batch = source.poll()
        cached = self.store.monitor_inputs(case_id)
        updated = dict(cached)
        state.update(files_discovered=batch.discovered, ignored_files=batch.ignored, errors=dict(batch.errors))
        rejected = state.setdefault("rejected", {})
        present = {s.name for s in batch.snapshots} | set(batch.errors)
        for name in list(rejected):
            if name not in present:
                rejected.pop(name)
        for name in cached.keys() - present:
            state["errors"][name] = "Source missing; retaining its last valid evidence"
        changed = 0
        for snapshot in batch.snapshots:
            contents_hash = hashlib.sha256(snapshot.contents).hexdigest()
            existing = cached.get(snapshot.name)
            metadata = {**snapshot.metadata, "owner_account": state.get("owner_account"),
                        "collector_device": state.get("collector_device")}
            if existing and existing["contents"] == snapshot.contents and existing["metadata"] == metadata:
                rejected.pop(snapshot.name, None)
                continue
            if rejected.get(snapshot.name, {}).get("hash") == contents_hash:
                state["errors"][snapshot.name] = rejected[snapshot.name]["error"]
                continue
            try:
                prepared = prepare_source(snapshot.contents, snapshot.name, metadata)
                updated[snapshot.name] = {"contents": snapshot.contents, "metadata": metadata}
                self.prepared[(case_id, snapshot.name)] = (contents_hash, prepared)
                rejected.pop(snapshot.name, None)
                changed += 1
            except (ValueError, TypeError, RecursionError, OverflowError):
                error = "Malformed or unsupported JSONL; previous valid evidence retained"
                rejected[snapshot.name] = {"hash": contents_hash, "error": error}
                state["errors"][snapshot.name] = error
        generated = []
        current_revision = (self.store.report(case_id).get("run") or {}).get("run_id")
        if changed or (updated and current_revision != state.get("monitor_revision_id")):
            prepared = []
            blobs = {}
            for name, entry in sorted(updated.items()):
                fingerprint = hashlib.sha256(entry["contents"]).hexdigest()
                item = self.prepared.get((case_id, name))
                if item is None or item[0] != fingerprint:
                    item = (fingerprint, prepare_source(entry["contents"], name, entry["metadata"]))
                    self.prepared[(case_id, name)] = item
                prepared.append(item[1])
                blobs[fingerprint] = entry["contents"]
            report = investigate(prepared)
            previous = self.store.report(case_id)
            old_findings = {(f["rule_name"], tuple(
                digest(e["raw_fields"])
                for e in previous["events"] if e["event_id"] in f["matched_event_ids"]
            )) for f in previous["findings"]}
            new_findings = {(f["rule_name"], tuple(
                digest(e["raw_fields"])
                for e in report["events"] if e["event_id"] in f["matched_event_ids"]
            )) for f in report["findings"]}
            state.update(files_processed=changed, events_processed=len(report["events"]),
                         new_findings=len(new_findings - old_findings),
                         new_claims=len(claim_states(report).keys() - claim_states(previous).keys()))
            state.update(state="error" if state["errors"] else "monitoring", last_success=now())
            state["monitor_revision_id"] = report["run"]["run_id"]
            generated = self.store.save(case_id, report, blobs, updated, state)
        else:
            state.update(state="error" if state["errors"] else "monitoring", last_success=now())
            self.store.set_monitor(case_id, state["workspace_key"], True, state)
        if self.sink:
            for item in generated:
                try:
                    self.sink.deliver(item)
                except Exception:
                    logger.warning("Optional notification sink failed; in-app notification remains available")
