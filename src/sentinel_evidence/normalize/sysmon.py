"""Sysmon and Windows Event normalization module."""

import hashlib
from typing import Dict, Any
from sentinel_evidence.contracts import Event
from sentinel_evidence.normalize.time import parse_timestamp_text
from sentinel_evidence.normalize.identity import extract_identity_fields


def compute_deterministic_event_id(source_id: str, source_locator: str) -> str:
    """Derives a stable, deterministic Event ID from source_id and locator."""
    seed = f"{source_id}:{source_locator}".encode("utf-8")
    return f"EVT-{hashlib.sha256(seed).hexdigest()[:16]}"


def normalize_sysmon_event(source_id: str, source_locator: str, raw_fields: Dict[str, Any]) -> Event:
    """
    Normalizes raw telemetry log record into an Event contract object.
    Preserves raw fields completely.
    """
    event_id = compute_deterministic_event_id(source_id, source_locator)

    original_ts_text = (
        raw_fields.get("UtcTime") or
        raw_fields.get("TimeCreated") or
        raw_fields.get("timestamp") or
        ""
    )
    normalized_ts, ts_status = parse_timestamp_text(original_ts_text)

    process_guid, parent_process_guid, _, host = extract_identity_fields(raw_fields)

    orig_event_id = (
        str(raw_fields.get("EventID")) if raw_fields.get("EventID") is not None
        else str(raw_fields.get("event_id")) if raw_fields.get("event_id") is not None
        else None
    )

    provider = str(raw_fields.get("Provider_Name") or raw_fields.get("Provider") or raw_fields.get("provider") or "Microsoft-Windows-Sysmon")
    channel = str(raw_fields.get("Channel") or raw_fields.get("channel") or "Operational")

    event_record_id = raw_fields.get("EventRecordID") or raw_fields.get("event_record_id")
    if event_record_id is not None:
        try:
            event_record_id = int(event_record_id)
        except (ValueError, TypeError):
            event_record_id = None

    return Event(
        event_id=event_id,
        source_id=source_id,
        source_locator=source_locator,
        original_timestamp_text=str(original_ts_text),
        normalized_timestamp=normalized_ts,
        timestamp_status=ts_status,
        host=host,
        provider=provider,
        channel=channel,
        original_event_id=orig_event_id,
        event_record_id=event_record_id,
        process_guid=process_guid,
        parent_process_guid=parent_process_guid,
        raw_fields=raw_fields,
        parse_status="sysmon_normalized" if orig_event_id else "raw_normalized"
    )
