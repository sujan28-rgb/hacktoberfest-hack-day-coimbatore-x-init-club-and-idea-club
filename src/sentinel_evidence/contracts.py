"""Canonical dataclass schemas for Sentinel Evidence."""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class Source:
    source_id: str
    content_hash: str
    declared_host: Optional[str] = None
    collection_metadata: Dict[str, Any] = field(default_factory=dict)
    export_metadata: Dict[str, Any] = field(default_factory=dict)
    byte_size: int = 0
    acquisition_time_if_known: Optional[str] = None
    exporter_version: Optional[str] = None
    original_source_mapping: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    event_id: str  # deterministic internal record ID
    source_id: str
    source_locator: str
    original_timestamp_text: str
    normalized_timestamp: Optional[str] = None
    timestamp_status: str = "raw"  # raw, parsed, ambiguous, invalid
    host: str = ""
    provider: str = ""
    channel: str = ""
    original_event_id: Optional[str] = None  # native Windows/Sysmon Event ID
    event_record_id: Optional[int] = None
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    raw_fields: Dict[str, Any] = field(default_factory=dict)
    parse_status: str = "unparsed"  # unparsed, sysmon_normalized, partial, error


@dataclass
class Finding:
    finding_id: str
    detector: str
    detector_version: str
    rule_id: str
    source_event_refs: List[str] = field(default_factory=list)
    original_severity: str = "unknown"
    matched_fields: Dict[str, Any] = field(default_factory=dict)
    mapping_status: str = "unlinked"


@dataclass
class Edge:
    edge_id: str
    source_entity: str
    target_entity: str
    relationship_type: str
    supporting_events: List[str] = field(default_factory=list)
    identity_assumptions: Dict[str, Any] = field(default_factory=dict)
    temporal_constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Claim:
    claim_id: str
    predicate_type: str
    bound_entities: List[str] = field(default_factory=list)
    support_sets: List[Dict[str, Any]] = field(default_factory=list)
    contradictory_evidence: List[Dict[str, Any]] = field(default_factory=list)
    unmet_prerequisites: List[str] = field(default_factory=list)
    status: str = "insufficient_evidence"  # observed, supported_inference, hypothesis, insufficient_evidence


@dataclass
class Run:
    run_id: str
    source_hashes: List[str] = field(default_factory=list)
    parser_version: str = "0.1.0"
    detector_version: str = "0.1.0"
    rule_version: str = "0.1.0"
    policy_version: str = "0.1.0"
    model_digest: Optional[str] = None
    prompt_digest: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    limits: Dict[str, Any] = field(default_factory=dict)
    software_revision: str = "0.1.0"
    timestamps: Dict[str, str] = field(default_factory=dict)
    output_hashes: Dict[str, str] = field(default_factory=dict)
