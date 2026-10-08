"""SQLite evidence repository."""

import json
import sqlite3
from pathlib import Path
from typing import Optional, List
from sentinel_evidence.contracts import Source, Event, EventKind

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class EvidenceRepository:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        """Initialize SQLite tables and indexes."""
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        with self.conn:
            self.conn.executescript(schema_sql)

    def insert_source(self, source: Source) -> bool:
        """Insert source manifest into SQLite inside a transaction."""
        query = """
        INSERT INTO sources (file_hash, file_path, line_number, raw_hash)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(file_hash) DO NOTHING;
        """
        with self.conn:
            cursor = self.conn.execute(
                query, (source.file_hash, source.file_path, source.line_number, source.raw_hash)
            )
            return cursor.rowcount > 0

    def insert_events_batch(self, events: List[Event]) -> None:
        """Atomically insert a batch of events inside a single transaction."""
        query = """
        INSERT OR REPLACE INTO events (
            event_id, kind, timestamp, host, process_guid, pid, image,
            command_line, parent_process_guid, parent_image, user, file_hash, raw_fields
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                e.event_id,
                e.kind.value if isinstance(e.kind, EventKind) else str(e.kind),
                e.timestamp.isoformat(),
                e.host,
                e.process_guid,
                e.pid,
                e.image,
                e.command_line,
                e.parent_process_guid,
                e.parent_image,
                e.user,
                e.source.file_hash,
                json.dumps(e.fields),
            )
            for e in events
        ]
        with self.conn:
            self.conn.executemany(query, rows)

    def get_event_count(self) -> int:
        """Get total event count."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM events")
        return cursor.fetchone()[0]

    def close(self) -> None:
        self.conn.close()
