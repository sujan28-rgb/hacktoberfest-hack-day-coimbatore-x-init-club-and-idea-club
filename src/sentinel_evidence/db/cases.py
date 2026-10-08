"""Case-scoped SQLite storage. Imports become visible in one transaction."""
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from sentinel_evidence.report.export import encode
from sentinel_evidence.notifications import changes, digest


def empty_report():
    return {"events": [], "claims": [], "findings": [], "sources": [], "edges": [], "identities": {}, "run": None}


class CaseStore:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, report TEXT
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    case_id TEXT NOT NULL, source_hash TEXT NOT NULL,
                    original BLOB NOT NULL,
                    PRIMARY KEY(case_id, source_hash),
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS case_revisions (
                    case_id TEXT NOT NULL, revision_id TEXT NOT NULL, report TEXT NOT NULL,
                    PRIMARY KEY(case_id, revision_id), FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS case_updates (
                    case_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS notifications (
                    notification_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
                    created_at TEXT NOT NULL, payload TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE INDEX IF NOT EXISTS idx_notifications_case ON notifications(case_id, created_at);
                CREATE TABLE IF NOT EXISTS monitors (
                    case_id TEXT PRIMARY KEY, workspace_key TEXT NOT NULL,
                    enabled INTEGER NOT NULL, state TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS monitor_inputs (
                    case_id TEXT NOT NULL, name TEXT NOT NULL, contents BLOB NOT NULL,
                    metadata TEXT NOT NULL, PRIMARY KEY(case_id, name),
                    FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self):
        case_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES (?, ?, NULL)",
                       (case_id, hashlib.sha256(token.encode()).hexdigest()))
        return {"case_id": case_id, "token": token}

    def authorized(self, case_id, token):
        with self.connect() as db:
            row = db.execute("SELECT token_hash FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return bool(row and secrets.compare_digest(row[0], hashlib.sha256(token.encode()).hexdigest()))

    def save(self, case_id, report, contents, monitor_inputs=None, monitor_state=None):
        blobs = contents if isinstance(contents, dict) else {report["sources"][0]["source_id"]: contents}
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT report FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if row is None:
                raise KeyError(case_id)
            previous = json.loads(row[0]) if row[0] else empty_report()
            # Archive the current report on first use after upgrading an older database.
            if previous["run"]:
                db.execute("INSERT OR IGNORE INTO case_revisions VALUES (?, ?, ?)",
                           (case_id, previous["run"]["run_id"], encode(previous)))
            for source_hash, blob in blobs.items():
                db.execute("INSERT OR IGNORE INTO evidence VALUES (?, ?, ?)", (case_id, source_hash, blob))
            db.execute("INSERT OR IGNORE INTO case_revisions VALUES (?, ?, ?)",
                       (case_id, report["run"]["run_id"], encode(report)))
            db.execute("INSERT INTO case_updates VALUES (?, 1) ON CONFLICT(case_id) DO UPDATE SET sequence=sequence+1", (case_id,))
            sequence = db.execute("SELECT sequence FROM case_updates WHERE case_id=?", (case_id,)).fetchone()[0]
            generated = changes(previous, report)
            for item in generated:
                item.update(case_id=case_id, notification_id=digest([case_id, sequence, item["semantic_key"], item["type"]]),
                            created_at=datetime.now(timezone.utc).isoformat(), read=False)
                db.execute("INSERT INTO notifications(notification_id, case_id, created_at, payload) VALUES (?, ?, ?, ?)",
                           (item["notification_id"], case_id, item["created_at"], encode(item)))
            db.execute("UPDATE cases SET report=? WHERE case_id=?", (encode(report), case_id))
            if monitor_inputs is not None:
                for name, entry in monitor_inputs.items():
                    db.execute("INSERT OR REPLACE INTO monitor_inputs VALUES (?, ?, ?, ?)",
                               (case_id, name, entry["contents"], encode(entry["metadata"])))
            if monitor_state is not None:
                db.execute("UPDATE monitors SET state=? WHERE case_id=?", (encode(monitor_state), case_id))
        return generated

    def report(self, case_id, revision=None):
        with self.connect() as db:
            if revision:
                row = db.execute("SELECT report FROM case_revisions WHERE case_id=? AND revision_id=?", (case_id, revision)).fetchone()
                if row is None:
                    raise KeyError(revision)
            else:
                row = db.execute("SELECT report FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else empty_report()

    def original(self, case_id, source_hash):
        with self.connect() as db:
            row = db.execute("SELECT original FROM evidence WHERE case_id=? AND source_hash=?",
                             (case_id, source_hash)).fetchone()
        return row[0] if row else None

    def notifications(self, case_id, page=1, size=30):
        with self.connect() as db:
            rows = db.execute("SELECT payload, read FROM notifications WHERE case_id=? ORDER BY created_at DESC, notification_id LIMIT ? OFFSET ?",
                              (case_id, size, (page - 1) * size)).fetchall()
            total, unread = db.execute("SELECT COUNT(*), COALESCE(SUM(read=0), 0) FROM notifications WHERE case_id=?", (case_id,)).fetchone()
        return {"items": [{**json.loads(payload), "read": bool(read)} for payload, read in rows],
                "total": total, "unread": unread, "page": page, "size": size}

    def read_notification(self, case_id, notification_id):
        with self.connect() as db:
            return db.execute("UPDATE notifications SET read=1 WHERE case_id=? AND notification_id=?",
                              (case_id, notification_id)).rowcount > 0

    def monitor(self, case_id):
        with self.connect() as db:
            row = db.execute("SELECT workspace_key, enabled, state FROM monitors WHERE case_id=?", (case_id,)).fetchone()
        return {"workspace_key": row[0], "enabled": bool(row[1]), **json.loads(row[2])} if row else None

    def set_monitor(self, case_id, workspace_key, enabled, state):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO monitors VALUES (?, ?, ?, ?)",
                       (case_id, workspace_key, int(enabled), encode(state)))

    def enabled_monitors(self):
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT case_id FROM monitors WHERE enabled=1").fetchall()]

    def monitor_inputs(self, case_id):
        with self.connect() as db:
            rows = db.execute("SELECT name, contents, metadata FROM monitor_inputs WHERE case_id=?", (case_id,)).fetchall()
        return {name: {"contents": contents, "metadata": json.loads(metadata)} for name, contents, metadata in rows}
