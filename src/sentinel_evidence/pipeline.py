"""One deterministic engine used by HTTP, CLI, and evaluation."""
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from sentinel_evidence.contracts import Run, ClaimStatus, SupportSet
from sentinel_evidence.normalize.sysmon import normalize_sysmon_event
from sentinel_evidence.adapters.detector import detect, DETECTOR_VERSION
from sentinel_evidence.correlate.edges import correlate
from sentinel_evidence.correlate.scenarios import run_scenarios
from sentinel_evidence.claims.compile import compile_claims
from sentinel_evidence.claims.validate import validate_claims
from sentinel_evidence.report.export import plain, encode

MAX_BYTES = 10 * 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_EVENTS = 10000


def reject_constant(value):
    raise ValueError("Non-finite JSON number")


def prepare_source(contents: bytes, filename="evidence.jsonl", collection_metadata=None):
    """Shared intake/normalization boundary for uploads and local collectors."""
    if not contents or len(contents) > MAX_BYTES:
        raise ValueError("Evidence must contain between 1 byte and 10 MiB")
    digest = hashlib.sha256(contents).hexdigest()
    events = []
    for number, line in enumerate(contents.splitlines(keepends=True), 1):
        if number > MAX_EVENTS or len(line) > MAX_LINE:
            raise ValueError("Evidence exceeds record count or line size limit")
        if not line.strip():
            continue
        try:
            raw = json.loads(line.decode("utf-8"), parse_constant=reject_constant)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError(f"Invalid JSON at line {number}") from error
        if not isinstance(raw, dict):
            raise ValueError(f"Expected an object at line {number}")
        pending = [(raw, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 64:
                raise ValueError(f"Record nesting exceeds limit at line {number}")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"Non-finite number at line {number}")
            if isinstance(value, dict):
                pending.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
        for key in ("Computer", "host", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine", "UtcTime", "TimeCreated"):
            if key in raw and raw[key] is not None and not isinstance(raw[key], str):
                raise ValueError(f"Invalid {key} at line {number}")
        events.append(normalize_sysmon_event(digest, filename, number, raw, line))
    if not events:
        raise ValueError("No evidence records")
    source = {
        "source_id": digest, "content_hash": digest, "declared_host": "",
        "collection_metadata": collection_metadata or {},
        "export_metadata": {"profile": "flat-sysmon-jsonl-v1"},
        "byte_size": len(contents), "exporter_version": "not supplied",
        "original_source_mapping": filename,
    }
    return events, source


def investigate(prepared_sources):
    """Correlate all selected sources together without duplicating processing logic."""
    started_at = datetime.now(timezone.utc)
    unique = {}
    for events, source in prepared_sources:
        unique.setdefault(source["source_id"], (events, source))
    events = [event for batch, _ in unique.values() for event in batch]
    sources = [source for _, source in unique.values()]
    if len(events) > MAX_EVENTS or sum(s["byte_size"] for s in sources) > MAX_BYTES:
        raise ValueError("Combined evidence exceeds investigation limits")
    findings = detect(events)
    edges, identities = correlate(events)
    claims = [c for c, _ in validate_claims(compile_claims(run_scenarios(events, edges, findings)))]
    # Conflicting exports of the same explicitly identified record stay visible.
    records = {}
    by_id = {e.event_id: e for e in events}
    for event in events:
        record_id = event.raw_fields.get("EventRecordID")
        channel = event.raw_fields.get("Channel")
        if record_id is not None and channel:
            records.setdefault((event.host, str(channel), str(record_id)), []).append(event)
    for claim in claims:
        supporting = {ref for support in claim.support_sets for ref in support.evidence_ids}
        contradictions = {}
        for ref in supporting:
            event = by_id.get(ref)
            if event is None:
                continue
            key = (event.host, str(event.raw_fields.get("Channel")), str(event.raw_fields.get("EventRecordID")))
            for other in records.get(key, []):
                if other.event_id != ref and other.raw_fields != event.raw_fields:
                    contradictions[other.event_id] = other
        if contradictions:
            claim.contradictory_evidence = [
                SupportSet([e.event_id], e.raw_fields, "Conflicting record with the same host, channel and record ID")
                for e in contradictions.values()
            ]
            if claim.status in {ClaimStatus.OBSERVED, ClaimStatus.SUPPORTED_INFERENCE}:
                claim.status = ClaimStatus.HYPOTHESIS
            claim.unmet_prerequisites.append("Conflicting original record values require review")
    report = plain({"events": events, "findings": findings, "edges": edges, "claims": claims,
                    "identities": identities})
    report["sources"] = sources
    # Include source selection even when no events remain after an evidence change.
    output_hash = hashlib.sha256(encode(report).encode()).hexdigest()
    policy = Path(__file__).parent / "correlate" / "scenarios.yaml"
    run = Run(
        run_id=output_hash[:24], started_at=started_at, completed_at=datetime.now(timezone.utc),
        source_hashes=sorted(unique), parser_version="sysmon-flat-v1",
        detector_version=DETECTOR_VERSION, rule_version=DETECTOR_VERSION,
        policy_version=hashlib.sha256(policy.read_bytes()).hexdigest(),
        parameters={"correlation_window_seconds": 300},
        limits={"bytes": MAX_BYTES, "line_bytes": MAX_LINE, "records": MAX_EVENTS},
        software_revision="sentinel-evidence-0.1.0",
        output_hashes={"deterministic_report": output_hash},
    )
    run.timestamps = {"started_at": run.started_at.isoformat(), "completed_at": run.completed_at.isoformat()}
    report["run"] = {k: v for k, v in plain(run).items() if k not in {"events", "findings", "edges", "claims"}}
    return report


def analyze(contents: bytes, filename="evidence.jsonl"):
    return investigate([prepare_source(contents, filename)])
