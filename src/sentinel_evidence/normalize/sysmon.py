"""Sysmon and Windows Event normalization module."""

import hashlib
from datetime import datetime
from typing import Dict, Any
from sentinel_evidence.contracts import Event, EventKind, Source
from sentinel_evidence.normalize.time import parse_timestamp_text
from sentinel_evidence.normalize.identity import extract_identity_fields


def compute_deterministic_event_id(source_id: str, source_locator: str) -> str:
    """Derives a stable, deterministic Event ID from source_id and locator."""
    seed = f"{source_id}:{source_locator}".encode("utf-8")
    return f"EVT-{hashlib.sha256(seed).hexdigest()[:16]}"


def normalize_sysmon_event(source_file_hash: str, file_path: str, line_number: int, raw_fields: Dict[str, Any]) -> Event:
    """
    Normalizes raw telemetry log record into an Event contract object.
    Preserves raw fields completely.
    """
    locator = f"line:{line_number}"
    event_id = compute_deterministic_event_id(source_file_hash, locator)

    original_ts_text = (
        raw_fields.get("UtcTime") or
        raw_fields.get("TimeCreated") or
        raw_fields.get("timestamp") or
        ""
    )
    dt_obj, _ = parse_timestamp_text(original_ts_text)
    ts = dt_obj if dt_obj else datetime.utcnow()

    process_guid, parent_process_guid, pid, host = extract_identity_fields(raw_fields)

    source = Source(
        file_hash=source_file_hash,
        file_path=file_path,
        line_number=line_number,
        raw_hash=hashlib.sha256(str(raw_fields).encode("utf-8")).hexdigest()
    )

    return Event(
        event_id=event_id,
        kind=EventKind.PROCESS_CREATE if raw_fields.get("EventID") == 1 else EventKind.UNKNOWN,
        timestamp=ts,
        host=host,
        process_guid=process_guid,
        pid=pid,
        image=raw_fields.get("Image"),
        command_line=raw_fields.get("CommandLine"),
        parent_process_guid=parent_process_guid,
        parent_image=raw_fields.get("ParentImage"),
        user=raw_fields.get("User"),
        source=source,
        fields=raw_fields
    )
