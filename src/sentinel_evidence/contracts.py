from typing import List, Optional, Any, Dict, Literal
from pydantic import BaseModel, Field

class Source(BaseModel):
    source_id: str
    content_hash: str
    declared_host: str
    collection_metadata: Dict[str, Any]
    export_metadata: Dict[str, Any]
    byte_size: int
    acquisition_time_if_known: Optional[str] = None
    exporter_version: str
    original_source_mapping: str

class Event(BaseModel):
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
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    raw_fields: Dict[str, Any]
    parse_status: str

class Finding(BaseModel):
    finding_id: str
    detector: str
    detector_version: str
    rule_id: str
    source_event_refs: List[str]
    original_severity: str
    matched_fields: Dict[str, Any]
    mapping_status: str

class Edge(BaseModel):
    edge_id: str
    source_entity: str
    target_entity: str
    relationship_type: str
    supporting_events: List[str]
    identity_assumptions: List[str]
    temporal_constraints: List[str]

ClaimStatus = Literal["observed", "supported_inference", "hypothesis", "insufficient_evidence"]

class ClaimSupport(BaseModel):
    event_id: str
    fields: List[str]

class Claim(BaseModel):
    claim_id: str
    predicate_type: str
    bound_entities: List[str]
    support_sets: List[ClaimSupport]
    contradictory_evidence: List[str]
    unmet_prerequisites: List[str]
    status: ClaimStatus

class Run(BaseModel):
    run_id: str
    source_hashes: List[str]
    parser_version: str
    detector_version: str
    rule_version: str
    policy_version: str
    model_digest: str
    prompt_digest: str
    parameters: Dict[str, Any]
    limits: Dict[str, Any]
    software_revision: str
    timestamps: Dict[str, str]
    output_hashes: List[str]
