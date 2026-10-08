"""
Sentinel Evidence — Claim Compiler

Transforms ScenarioMatch results into typed Claims with:
  - Exact support sets referencing evidence IDs and relevant fields
  - Proper status assignment (observed / supported_inference / hypothesis / insufficient_evidence)
  - Contradictory evidence preservation
  - Unmet prerequisites tracking

Evidence constraints enforced:
  - Connection ≠ exfiltration
  - File creation ≠ persistence
  - Process creation / command line ≠ successful execution
  - Temporal proximity ≠ causality
  - Ambiguous PID ≠ verified identity
  - Missing evidence ≠ proof of absence
  - Repeated exports ≠ independent corroboration
  - Suspicious patterns ≠ confirmed malicious behavior
"""

from __future__ import annotations

from typing import Any

from sentinel_evidence.contracts import (
    Claim,
    ClaimStatus,
    PredicateType,
    SupportSet,
    make_deterministic_id,
)
from sentinel_evidence.correlate.scenarios import ScenarioMatch


# ---------------------------------------------------------------------------
# Scenario → Predicate mapping
# ---------------------------------------------------------------------------

_SCENARIO_PREDICATE_MAP: dict[str, PredicateType] = {
    "suspicious_parent_child": PredicateType.SUSPICIOUS_PARENT_CHILD,
    "flagged_process_network": PredicateType.FLAGGED_PROCESS_NETWORK,
    "flagged_process_file_create": PredicateType.FLAGGED_PROCESS_FILE_CREATE,
}


# ---------------------------------------------------------------------------
# Support set builders
# ---------------------------------------------------------------------------

def _build_support_set_suspicious_parent_child(match: ScenarioMatch) -> SupportSet:
    """Build a support set for the suspicious parent/child scenario."""
    parent = match.matched_events.get("parent")
    child = match.matched_events.get("child")
    edge = match.matched_edges[0] if match.matched_edges else None

    evidence_ids = []
    relevant_fields: dict[str, Any] = {}

    if parent:
        evidence_ids.append(parent.event_id)
        relevant_fields["parent_image"] = parent.image
        relevant_fields["parent_process_guid"] = parent.process_guid
        relevant_fields["parent_command_line"] = parent.command_line
    if child:
        evidence_ids.append(child.event_id)
        relevant_fields["child_image"] = child.image
        relevant_fields["child_process_guid"] = child.process_guid
        relevant_fields["child_command_line"] = child.command_line
        relevant_fields["child_parent_process_guid"] = child.parent_process_guid
    if edge:
        evidence_ids.append(edge.edge_id)
        relevant_fields["edge_kind"] = edge.kind.value
        relevant_fields["edge_confidence"] = edge.confidence

    for finding in match.matched_findings:
        evidence_ids.append(finding.finding_id)
        relevant_fields.setdefault("findings", []).append({
            "finding_id": finding.finding_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
        })

    return SupportSet(
        evidence_ids=evidence_ids,
        relevant_fields=relevant_fields,
        description=(
            f"Parent process '{parent.image if parent else 'unknown'}' created "
            f"child process '{child.image if child else 'unknown'}' on host "
            f"'{match.host}', linked by ProcessGuid. "
            f"Flagged by {len(match.matched_findings)} finding(s)."
        ),
    )


def _build_support_set_flagged_process_network(match: ScenarioMatch) -> SupportSet:
    """Build a support set for the flagged process + network connection scenario."""
    process = match.matched_events.get("flagged_process")
    connection = match.matched_events.get("connection")
    edge = match.matched_edges[0] if match.matched_edges else None

    evidence_ids = []
    relevant_fields: dict[str, Any] = {}

    if process:
        evidence_ids.append(process.event_id)
        relevant_fields["process_image"] = process.image
        relevant_fields["process_guid"] = process.process_guid
        relevant_fields["process_command_line"] = process.command_line
    if connection:
        evidence_ids.append(connection.event_id)
        relevant_fields["connection_timestamp"] = str(connection.timestamp)
        relevant_fields["dest_ip"] = connection.fields.get("dest_ip")
        relevant_fields["dest_port"] = connection.fields.get("dest_port")
    if edge:
        evidence_ids.append(edge.edge_id)
        relevant_fields["edge_kind"] = edge.kind.value
        relevant_fields["edge_confidence"] = edge.confidence

    for finding in match.matched_findings:
        evidence_ids.append(finding.finding_id)
        relevant_fields.setdefault("findings", []).append({
            "finding_id": finding.finding_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
        })

    return SupportSet(
        evidence_ids=evidence_ids,
        relevant_fields=relevant_fields,
        description=(
            f"Flagged process '{process.image if process else 'unknown'}' made an "
            f"outbound network connection on host '{match.host}'. "
            f"NOTE: Connection does NOT prove exfiltration."
        ),
    )


def _build_support_set_flagged_process_file_create(match: ScenarioMatch) -> SupportSet:
    """Build a support set for the flagged process + file creation scenario."""
    process = match.matched_events.get("flagged_process")
    file_event = match.matched_events.get("file_event")
    edge = match.matched_edges[0] if match.matched_edges else None

    evidence_ids = []
    relevant_fields: dict[str, Any] = {}

    if process:
        evidence_ids.append(process.event_id)
        relevant_fields["process_image"] = process.image
        relevant_fields["process_guid"] = process.process_guid
        relevant_fields["process_command_line"] = process.command_line
    if file_event:
        evidence_ids.append(file_event.event_id)
        relevant_fields["file_timestamp"] = str(file_event.timestamp)
        relevant_fields["target_filename"] = file_event.fields.get("target_filename")
    if edge:
        evidence_ids.append(edge.edge_id)
        relevant_fields["edge_kind"] = edge.kind.value
        relevant_fields["edge_confidence"] = edge.confidence

    for finding in match.matched_findings:
        evidence_ids.append(finding.finding_id)
        relevant_fields.setdefault("findings", []).append({
            "finding_id": finding.finding_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
        })

    return SupportSet(
        evidence_ids=evidence_ids,
        relevant_fields=relevant_fields,
        description=(
            f"Flagged process '{process.image if process else 'unknown'}' created a file "
            f"on host '{match.host}'. "
            f"NOTE: File creation does NOT prove persistence."
        ),
    )


_SUPPORT_SET_BUILDERS = {
    "suspicious_parent_child": _build_support_set_suspicious_parent_child,
    "flagged_process_network": _build_support_set_flagged_process_network,
    "flagged_process_file_create": _build_support_set_flagged_process_file_create,
}


# ---------------------------------------------------------------------------
# Status determination
# ---------------------------------------------------------------------------

def _determine_status(match: ScenarioMatch) -> ClaimStatus:
    """
    Determine claim status based on scenario match quality.

    - OBSERVED: All constraints satisfied, high confidence, direct evidence.
    - SUPPORTED_INFERENCE: All constraints satisfied, but the claim is an
      inference from multiple evidence pieces (not a single direct observation).
    - HYPOTHESIS: Some constraints violated, but enough evidence exists
      to form a plausible hypothesis.
    - INSUFFICIENT_EVIDENCE: Critical constraints violated or no findings.
    """
    if not match.is_fully_satisfied:
        # Some constraints violated
        violated = match.constraints_violated
        critical_violations = [
            v for v in violated
            if "ProcessGuid" in v or "PID-only" in v or "must flag" in v or "finding" in v.lower()
        ]
        if critical_violations:
            return ClaimStatus.INSUFFICIENT_EVIDENCE
        return ClaimStatus.HYPOTHESIS

    # All constraints satisfied — determine if observed or inferred
    if match.identity_confidence >= 0.95 and len(match.matched_findings) > 0:
        return ClaimStatus.SUPPORTED_INFERENCE
    elif match.identity_confidence >= 0.8:
        return ClaimStatus.SUPPORTED_INFERENCE
    else:
        return ClaimStatus.HYPOTHESIS


# ---------------------------------------------------------------------------
# Bound entities builder
# ---------------------------------------------------------------------------

def _build_bound_entities(match: ScenarioMatch) -> dict[str, Any]:
    """Extract the bound entities from a scenario match."""
    entities: dict[str, Any] = {"host": match.host}
    for role, event in match.matched_events.items():
        entities[f"{role}_event_id"] = event.event_id
        if event.process_guid:
            entities[f"{role}_process_guid"] = event.process_guid
        if event.image:
            entities[f"{role}_image"] = event.image
    return entities


# ---------------------------------------------------------------------------
# Claim compiler — the main entry point
# ---------------------------------------------------------------------------

def compile_claim(match: ScenarioMatch) -> Claim:
    """
    Compile a single ScenarioMatch into a typed Claim.

    Builds support sets, determines status, and captures unmet prerequisites.
    Contradictory evidence is populated during validation (validate.py).
    """
    predicate = _SCENARIO_PREDICATE_MAP.get(match.scenario_id)
    if predicate is None:
        raise ValueError(f"No predicate mapping for scenario: {match.scenario_id}")

    builder = _SUPPORT_SET_BUILDERS.get(match.scenario_id)
    if builder is None:
        raise ValueError(f"No support set builder for scenario: {match.scenario_id}")

    support_set = builder(match)
    status = _determine_status(match)

    # Build unmet prerequisites from violated constraints
    unmet = list(match.constraints_violated)

    # Deterministic claim_id from scenario_id + evidence IDs
    claim_id = make_deterministic_id(
        match.scenario_id,
        *sorted(support_set.evidence_ids),
    )

    return Claim(
        claim_id=claim_id,
        predicate_type=predicate,
        bound_entities=_build_bound_entities(match),
        support_sets=[support_set] if status != ClaimStatus.INSUFFICIENT_EVIDENCE else [],
        contradictory_evidence=[],  # populated by validate.py
        unmet_prerequisites=unmet,
        status=status,
        scenario_id=match.scenario_id,
    )


def compile_claims(matches: list[ScenarioMatch]) -> list[Claim]:
    """Compile a list of scenario matches into typed claims."""
    return [compile_claim(m) for m in matches]
