"""Case-scoped SQLite storage. Imports become visible in one transaction."""
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from sentinel_evidence.report.export import encode


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

    def save(self, case_id, report, contents):
        with self.connect() as db:
            # One selected source per case in the MVP. Replacement is explicit in the UI.
            db.execute("DELETE FROM evidence WHERE case_id=?", (case_id,))
            db.execute("INSERT INTO evidence VALUES (?, ?, ?)",
                       (case_id, report["sources"][0]["source_id"], contents))
            db.execute("UPDATE cases SET report=? WHERE case_id=?", (encode(report), case_id))

    def report(self, case_id):
        with self.connect() as db:
            row = db.execute("SELECT report FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else {
            "events": [], "claims": [], "findings": [], "sources": [], "edges": [], "identities": {}, "run": None}

    def original(self, case_id, source_hash):
        with self.connect() as db:
            row = db.execute("SELECT original FROM evidence WHERE case_id=? AND source_hash=?",
                             (case_id, source_hash)).fetchone()
        return row[0] if row else None
