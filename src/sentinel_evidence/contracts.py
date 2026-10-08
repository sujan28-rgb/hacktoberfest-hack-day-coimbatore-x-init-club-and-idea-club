"""
Sentinel Evidence — Canonical Contracts

Shared data classes used across all pipeline stages.
These are schema-only definitions — no business logic.

Canonical identity: (host, ProcessGuid)
Bounded PID fallback: (host, pid, time_interval)
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Source — provenance of a raw record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    """Points back to the exact raw record in the ingested JSONL."""
    file_hash: str          # SHA-256 of the source JSONL file
    file_path: str          # Original file path
    line_number: int        # 1-based line in source file
    raw_hash: str           # SHA-256 of the raw JSON line


# ---------------------------------------------------------------------------
# Event — normalised telemetry record
# ---------------------------------------------------------------------------

class EventKind(str, Enum):
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_CONNECT = "network_connect"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    REGISTRY_SET = "registry_set"
    IMAGE_LOAD = "image_load"
    DNS_QUERY = "dns_query"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Event:
    """A single normalised telemetry event."""
    event_id: str                   # deterministic: SHA-256(source + normalized fields)
    kind: EventKind
    timestamp: Optional[datetime]
    host: str
    process_guid: Optional[str]     # Sysmon ProcessGuid when available
    pid: Optional[int]
    image: Optional[str]            # process image path
    command_line: Optional[str]
    parent_process_guid: Optional[str]
    parent_image: Optional[str]
    user: Optional[str]
    source: Source
    fields: dict[str, Any] = field(default_factory=dict)  # extra normalised fields
    raw_fields: dict[str, Any] = field(default_factory=dict)
    original_timestamp_text: str = ""
    timestamp_status: str = "unknown"
    parse_status: str = "parsed"

    def identity_key(self) -> tuple[str, Optional[str]]:
        """Canonical identity: (host, ProcessGuid)."""
        return (self.host, self.process_guid)

    def pid_fallback_key(self) -> tuple[str, Optional[int]]:
        """Bounded PID fallback key (host, pid). Time bounds applied externally."""
        return (self.host, self.pid)


# ---------------------------------------------------------------------------
# Finding — detector output attached to events
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """Output from a detector adapter (e.g. 'flagged process')."""
    finding_id: str
    rule_name: str
    severity: Severity
    description: str
    matched_event_ids: tuple[str, ...]   # events that triggered this finding
    tags: tuple[str, ...] = ()           # e.g. ATT&CK technique IDs


# ---------------------------------------------------------------------------
# Edge — typed relationship between events
# ---------------------------------------------------------------------------

class EdgeKind(str, Enum):
    PARENT_CHILD = "parent_child"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACTIVITY = "file_activity"
    REGISTRY_ACTIVITY = "registry_activity"
    IMAGE_LOAD = "image_load"
    TEMPORAL_PROXIMITY = "temporal_proximity"  # explicit: not causal


@dataclass(frozen=True)
class Edge:
    """A typed, directed relationship between two events or entities."""
    edge_id: str
    kind: EdgeKind
    source_event_id: str      # the originating event
    target_event_id: str      # the related event
    host: str
    confidence: float         # 0.0–1.0; ambiguous PID gets lower confidence
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Claim — the core output of the Scenarios + Claims pipeline
# ---------------------------------------------------------------------------

class ClaimStatus(str, Enum):
    """
    observed             — directly seen in raw evidence
    supported_inference  — logically follows from multiple pieces of evidence
    hypothesis           — plausible but not fully supported
    insufficient_evidence — support set incomplete or sole evidence removed
    """
    OBSERVED = "observed"
    SUPPORTED_INFERENCE = "supported_inference"
    HYPOTHESIS = "hypothesis"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class PredicateType(str, Enum):
    """Typed predicates for claims — see predicates.py for full registry."""
    PROCESS_EXECUTED = "process_executed"
    PARENT_CHILD_EXECUTION = "parent_child_execution"
    OUTBOUND_CONNECTION_BY_PROCESS = "outbound_connection_by_process"
    FILE_CREATED_BY_PROCESS = "file_created_by_process"
    SUSPICIOUS_PARENT_CHILD = "suspicious_parent_child"
    FLAGGED_PROCESS_NETWORK = "flagged_process_network"
    FLAGGED_PROCESS_FILE_CREATE = "flagged_process_file_create"


@dataclass
class SupportSet:
    """Exact references to evidence supporting a claim."""
    evidence_ids: list[str]          # event_ids / finding_ids / edge_ids
    relevant_fields: dict[str, Any]  # key field values from the evidence
    description: str                 # human-readable summary of what this set proves


@dataclass
class Claim:
    """
    A typed, evidence-grounded claim.

    Every accepted factual claim (status != insufficient_evidence) MUST have
    at least one valid SupportSet. Contradictory evidence and unmet
    prerequisites are always preserved.
    """
    claim_id: str
    predicate_type: PredicateType
    bound_entities: dict[str, Any]       # e.g. {"process_guid": ..., "host": ...}
    support_sets: list[SupportSet]
    contradictory_evidence: list[SupportSet]
    unmet_prerequisites: list[str]
    status: ClaimStatus
    scenario_id: Optional[str] = None    # which scenario produced this claim
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_valid_support(self) -> bool:
        """A claim is validly supported if it has at least one support set."""
        return len(self.support_sets) > 0


# ---------------------------------------------------------------------------
# Run — a single pipeline execution
# ---------------------------------------------------------------------------

@dataclass
class Run:
    """Represents one execution of the pipeline."""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    source_hashes: list[str] = field(default_factory=list)
    parser_version: str = ""
    detector_version: str = ""
    rule_version: str = ""
    policy_version: str = ""
    model_digest: Optional[str] = None
    prompt_digest: Optional[str] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    software_revision: str = ""
    timestamps: dict[str, Any] = field(default_factory=dict)
    output_hashes: dict[str, str] = field(default_factory=dict)


def make_deterministic_id(*parts: str) -> str:
    """Generate a deterministic SHA-256 ID from component strings."""
    content = "|".join(parts)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
