"""API response models for the mock case-management interface.

These models intentionally remain separate from the canonical pipeline
contracts so the API mock cannot replace or weaken the evidence model.
"""

from typing import Any, Literal

from pydantic import BaseModel


class ApiSource(BaseModel):
    source_id: str
    content_hash: str
    declared_host: str
    collection_metadata: dict[str, Any]
    export_metadata: dict[str, Any]
    byte_size: int
    acquisition_time_if_known: str | None = None
    exporter_version: str
    original_source_mapping: str


class ApiEvent(BaseModel):
    event_id: str
    source_id: str
    source_locator: str
    original_timestamp_text: str
    normalized_timestamp: str
    timestamp_status: str
    host: str
    provider: str
    channel: str
    event_record_id: str
    process_guid: str | None = None
    parent_process_guid: str | None = None
    raw_fields: dict[str, Any]
    parse_status: str


class ApiFinding(BaseModel):
    finding_id: str
    detector: str
    detector_version: str
    rule_id: str
    source_event_refs: list[str]
    original_severity: str
    matched_fields: dict[str, Any]
    mapping_status: str


ClaimStatus = Literal[
    "observed",
    "supported_inference",
    "hypothesis",
    "insufficient_evidence",
]


class ApiClaimSupport(BaseModel):
    event_id: str
    fields: list[str]


class ApiClaim(BaseModel):
    claim_id: str
    predicate_type: str
    bound_entities: list[str]
    support_sets: list[ApiClaimSupport]
    contradictory_evidence: list[str]
    unmet_prerequisites: list[str]
    status: ClaimStatus
