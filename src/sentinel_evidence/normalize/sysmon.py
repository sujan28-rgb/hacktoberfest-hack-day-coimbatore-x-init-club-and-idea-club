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


def normalize_sysmon_event(source_file_hash: str, file_path: str, line_number: int, raw_fields: Dict[str, Any], raw_bytes: bytes | None = None) -> Event:
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
    ts, timestamp_status = parse_timestamp_text(original_ts_text)

    process_guid, parent_process_guid, pid, host = extract_identity_fields(raw_fields)

    source = Source(
        file_hash=source_file_hash,
        file_path=file_path,
        line_number=line_number,
        raw_hash=hashlib.sha256(raw_bytes if raw_bytes is not None else str(raw_fields).encode("utf-8")).hexdigest()
    )

    kinds = {1: EventKind.PROCESS_CREATE, 3: EventKind.NETWORK_CONNECT,
             5: EventKind.PROCESS_TERMINATE, 7: EventKind.IMAGE_LOAD,
             11: EventKind.FILE_CREATE, 13: EventKind.REGISTRY_SET,
             22: EventKind.DNS_QUERY, 23: EventKind.FILE_DELETE}
    try:
        kind = kinds.get(int(raw_fields.get("EventID", 0)), EventKind.UNKNOWN)
    except (ValueError, TypeError):
        kind = EventKind.UNKNOWN
    fields = dict(raw_fields)
    for original, normalized in (("DestinationIp", "dest_ip"), ("DestinationPort", "dest_port"), ("TargetFilename", "target_filename")):
        if original in raw_fields:
            fields[normalized] = raw_fields[original]

    return Event(
        event_id=event_id,
        kind=kind,
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
        fields=fields,
        raw_fields=dict(raw_fields),
        original_timestamp_text=str(original_ts_text),
        timestamp_status=timestamp_status,
        parse_status="error" if "_parse_error" in raw_fields else "parsed",
    )
