"""SQLite evidence repository."""

import json
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from sentinel_evidence.contracts import Source, Event, Run

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
        INSERT INTO sources (
            source_id, content_hash, declared_host, collection_metadata,
            export_metadata, byte_size, acquisition_time_if_known,
            exporter_version, original_source_mapping
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(content_hash) DO NOTHING;
        """
        with self.conn:
            cursor = self.conn.execute(
                query,
                (
                    source.source_id,
                    source.content_hash,
                    source.declared_host,
                    json.dumps(source.collection_metadata),
                    json.dumps(source.export_metadata),
                    source.byte_size,
                    source.acquisition_time_if_known,
                    source.exporter_version,
                    json.dumps(source.original_source_mapping),
                ),
            )
            return cursor.rowcount > 0

    def insert_events_batch(self, events: List[Event]) -> None:
        """Atomically insert a batch of events inside a single transaction."""
        query = """
        INSERT OR REPLACE INTO events (
            event_id, source_id, source_locator, original_timestamp_text,
            normalized_timestamp, timestamp_status, host, provider, channel,
            original_event_id, event_record_id, process_guid, parent_process_guid,
            raw_fields, parse_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = [
            (
                e.event_id,
                e.source_id,
                e.source_locator,
                e.original_timestamp_text,
                e.normalized_timestamp,
                e.timestamp_status,
                e.host,
                e.provider,
                e.channel,
                e.original_event_id,
                e.event_record_id,
                e.process_guid,
                e.parent_process_guid,
                json.dumps(e.raw_fields),
                e.parse_status,
            )
            for e in events
        ]
        with self.conn:
            self.conn.executemany(query, rows)

    def get_source_by_hash(self, content_hash: str) -> Optional[Source]:
        """Lookup source manifest by SHA-256 content hash."""
        cursor = self.conn.execute("SELECT * FROM sources WHERE content_hash = ?", (content_hash,))
        row = cursor.fetchone()
        if not row:
            return None
        return Source(
            source_id=row["source_id"],
            content_hash=row["content_hash"],
            declared_host=row["declared_host"],
            collection_metadata=json.loads(row["collection_metadata"] or "{}"),
            export_metadata=json.loads(row["export_metadata"] or "{}"),
            byte_size=row["byte_size"],
            acquisition_time_if_known=row["acquisition_time_if_known"],
            exporter_version=row["exporter_version"],
            original_source_mapping=json.loads(row["original_source_mapping"] or "{}"),
        )

    def get_event_count(self, source_id: Optional[str] = None) -> int:
        """Get total event count or filtered by source_id."""
        if source_id:
            cursor = self.conn.execute("SELECT COUNT(*) FROM events WHERE source_id = ?", (source_id,))
        else:
            cursor = self.conn.execute("SELECT COUNT(*) FROM events")
        return cursor.fetchone()[0]

    def close(self) -> None:
        self.conn.close()
