"""
Sentinel Evidence — Scenario Matcher

Implements the three MVP scenarios from the README:
  1. Suspicious parent/child execution
  2. Flagged process + outbound network connection
  3. Flagged process + file creation

Design principles:
  - Deterministic: same inputs always produce same matches.
  - Bounded: uses explicit policy thresholds from policies/scenarios.yaml.
  - Provenance-preserving: every match records which events, edges, and
    findings contributed.

Evidence constraints (enforced here):
  - Ambiguous PID-only identity NEVER satisfies a scenario.
  - Temporal proximity alone is NOT treated as causality.
  - Connection ≠ exfiltration; file creation ≠ persistence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from sentinel_evidence.contracts import (
    Edge,
    EdgeKind,
    Event,
    EventKind,
    Finding,
    make_deterministic_id,
)

# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

_DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "policies" / "scenarios.yaml"


def load_scenario_policies(path: Optional[Path] = None) -> list[dict[str, Any]]:
    """Load scenario definitions from YAML policy file."""
    policy_path = path or _DEFAULT_POLICY_PATH
    if not policy_path.exists():
        raise FileNotFoundError(f"Scenario policy file not found: {policy_path}")
    with open(policy_path) as f:
        data = yaml.safe_load(f)
    return data.get("scenarios", [])


# ---------------------------------------------------------------------------
# Scenario match result
# ---------------------------------------------------------------------------

@dataclass
class ScenarioMatch:
    """Result of a successful scenario match."""
    scenario_id: str
    scenario_name: str
    matched_events: dict[str, Event]     # role → Event
    matched_edges: list[Edge]
    matched_findings: list[Finding]
    host: str
    identity_confidence: float
    constraints_satisfied: list[str]
    constraints_violated: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_fully_satisfied(self) -> bool:
        return len(self.constraints_violated) == 0


# ---------------------------------------------------------------------------
# Index builders — for efficient lookup
# ---------------------------------------------------------------------------

def _index_events_by_kind(events: list[Event]) -> dict[EventKind, list[Event]]:
    idx: dict[EventKind, list[Event]] = {}
    for e in events:
        idx.setdefault(e.kind, []).append(e)
    return idx


def _index_events_by_id(events: list[Event]) -> dict[str, Event]:
    return {e.event_id: e for e in events}


def _index_edges_by_kind(edges: list[Edge]) -> dict[EdgeKind, list[Edge]]:
    idx: dict[EdgeKind, list[Edge]] = {}
    for e in edges:
        idx.setdefault(e.kind, []).append(e)
    return idx


def _index_findings_by_event(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Map event_id → list of findings that matched that event."""
    idx: dict[str, list[Finding]] = {}
    for f in findings:
        for eid in f.matched_event_ids:
            idx.setdefault(eid, []).append(f)
    return idx


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

def _has_guid_identity(event: Event) -> bool:
    """Check whether an event has a ProcessGuid-based identity (not PID-only)."""
    return event.process_guid is not None and event.process_guid != ""


def _same_guid_identity(a: Event, b: Event) -> bool:
    """Two events share the same canonical (host, ProcessGuid) identity."""
    if not _has_guid_identity(a) or not _has_guid_identity(b):
        return False
    return a.host == b.host and a.process_guid == b.process_guid


# ---------------------------------------------------------------------------
# Scenario 1: Suspicious Parent/Child Execution
# ---------------------------------------------------------------------------

def _match_suspicious_parent_child(
    events_by_kind: dict[EventKind, list[Event]],
    events_by_id: dict[str, Event],
    edges_by_kind: dict[EdgeKind, list[Edge]],
    findings_by_event: dict[str, list[Finding]],
    policy: dict[str, Any],
) -> list[ScenarioMatch]:
    """
    Match: parent creates child, linked by parent_child edge via ProcessGuid,
    and at least one finding flags the parent or child.
    """
    matches: list[ScenarioMatch] = []
    min_conf = policy.get("min_identity_confidence", 0.8)
    parent_child_edges = edges_by_kind.get(EdgeKind.PARENT_CHILD, [])
    seen: set[str] = set()  # deduplicate by edge_id

    for edge in parent_child_edges:
        if edge.edge_id in seen:
            continue
        if edge.confidence < min_conf:
            continue

        parent_event = events_by_id.get(edge.source_event_id)
        child_event = events_by_id.get(edge.target_event_id)

        if parent_event is None or child_event is None:
            continue

        # Identity constraint: parent_child edge must be ProcessGuid-based
        constraints_satisfied = []
        constraints_violated = []

        if _has_guid_identity(parent_event) and child_event.parent_process_guid == parent_event.process_guid:
            constraints_satisfied.append("parent_child edge links parent and child via ProcessGuid")
        else:
            constraints_violated.append("parent_child edge must link parent and child via ProcessGuid")

        # At least one finding must flag the parent or child
        parent_findings = findings_by_event.get(parent_event.event_id, [])
        child_findings = findings_by_event.get(child_event.event_id, [])
        all_findings = parent_findings + child_findings

        if all_findings:
            constraints_satisfied.append("at least one finding flags the parent or child process")
        else:
            constraints_violated.append("at least one finding must flag the parent or child process")

        # Ambiguous PID check
        if not _has_guid_identity(parent_event) or not _has_guid_identity(child_event):
            constraints_violated.append("ambiguous PID-only identity does not satisfy this scenario")

        match = ScenarioMatch(
            scenario_id=policy["id"],
            scenario_name=policy["name"],
            matched_events={"parent": parent_event, "child": child_event},
            matched_edges=[edge],
            matched_findings=all_findings,
            host=parent_event.host,
            identity_confidence=edge.confidence,
            constraints_satisfied=constraints_satisfied,
            constraints_violated=constraints_violated,
        )
        matches.append(match)
        seen.add(edge.edge_id)

    return matches


# ---------------------------------------------------------------------------
# Scenario 2: Flagged Process + Outbound Network Connection
# ---------------------------------------------------------------------------

def _match_flagged_process_network(
    events_by_kind: dict[EventKind, list[Event]],
    events_by_id: dict[str, Event],
    edges_by_kind: dict[EdgeKind, list[Edge]],
    findings_by_event: dict[str, list[Finding]],
    policy: dict[str, Any],
) -> list[ScenarioMatch]:
    """
    Match: flagged process + network_connect event sharing (host, ProcessGuid),
    linked by a network_connection edge.
    """
    matches: list[ScenarioMatch] = []
    min_conf = policy.get("min_identity_confidence", 0.8)
    net_edges = edges_by_kind.get(EdgeKind.NETWORK_CONNECTION, [])
    seen: set[str] = set()

    for edge in net_edges:
        if edge.edge_id in seen:
            continue
        if edge.confidence < min_conf:
            continue

        process_event = events_by_id.get(edge.source_event_id)
        network_event = events_by_id.get(edge.target_event_id)

        if process_event is None or network_event is None:
            continue

        constraints_satisfied = []
        constraints_violated = []

        # Temporal ordering
        if network_event.timestamp >= process_event.timestamp:
            constraints_satisfied.append("connection event follows process creation temporally")
        else:
            constraints_violated.append("connection event must follow process creation temporally")

        # Identity: ProcessGuid required
        if _same_guid_identity(process_event, network_event):
            constraints_satisfied.append("process identity resolved via ProcessGuid")
        else:
            constraints_violated.append("process identity must be resolved via ProcessGuid, not PID alone")

        # Finding must flag the process
        process_findings = findings_by_event.get(process_event.event_id, [])
        if process_findings:
            constraints_satisfied.append("finding flags the process")
        else:
            constraints_violated.append("a finding must flag the process")

        match = ScenarioMatch(
            scenario_id=policy["id"],
            scenario_name=policy["name"],
            matched_events={"flagged_process": process_event, "connection": network_event},
            matched_edges=[edge],
            matched_findings=process_findings,
            host=process_event.host,
            identity_confidence=edge.confidence,
            constraints_satisfied=constraints_satisfied,
            constraints_violated=constraints_violated,
        )
        matches.append(match)
        seen.add(edge.edge_id)

    return matches


# ---------------------------------------------------------------------------
# Scenario 3: Flagged Process + File Creation
# ---------------------------------------------------------------------------

def _match_flagged_process_file_create(
    events_by_kind: dict[EventKind, list[Event]],
    events_by_id: dict[str, Event],
    edges_by_kind: dict[EdgeKind, list[Edge]],
    findings_by_event: dict[str, list[Finding]],
    policy: dict[str, Any],
) -> list[ScenarioMatch]:
    """
    Match: flagged process + file_create event sharing (host, ProcessGuid),
    linked by a file_activity edge.
    """
    matches: list[ScenarioMatch] = []
    min_conf = policy.get("min_identity_confidence", 0.8)
    file_edges = edges_by_kind.get(EdgeKind.FILE_ACTIVITY, [])
    seen: set[str] = set()

    for edge in file_edges:
        if edge.edge_id in seen:
            continue
        if edge.confidence < min_conf:
            continue

        process_event = events_by_id.get(edge.source_event_id)
        file_event = events_by_id.get(edge.target_event_id)

        if process_event is None or file_event is None:
            continue

        constraints_satisfied = []
        constraints_violated = []

        # Temporal ordering
        if file_event.timestamp >= process_event.timestamp:
            constraints_satisfied.append("file_create event follows process creation temporally")
        else:
            constraints_violated.append("file_create event must follow process creation temporally")

        # Identity: ProcessGuid required
        if _same_guid_identity(process_event, file_event):
            constraints_satisfied.append("process identity resolved via ProcessGuid")
        else:
            constraints_violated.append("process identity must be resolved via ProcessGuid, not PID alone")

        # Finding must flag the process
        process_findings = findings_by_event.get(process_event.event_id, [])
        if process_findings:
            constraints_satisfied.append("finding flags the process")
        else:
            constraints_violated.append("a finding must flag the process")

        match = ScenarioMatch(
            scenario_id=policy["id"],
            scenario_name=policy["name"],
            matched_events={"flagged_process": process_event, "file_event": file_event},
            matched_edges=[edge],
            matched_findings=process_findings,
            host=process_event.host,
            identity_confidence=edge.confidence,
            constraints_satisfied=constraints_satisfied,
            constraints_violated=constraints_violated,
        )
        matches.append(match)
        seen.add(edge.edge_id)

    return matches


# ---------------------------------------------------------------------------
# Dispatcher — maps scenario_id to matcher function
# ---------------------------------------------------------------------------

_MATCHERS = {
    "suspicious_parent_child": _match_suspicious_parent_child,
    "flagged_process_network": _match_flagged_process_network,
    "flagged_process_file_create": _match_flagged_process_file_create,
}


def run_scenarios(
    events: list[Event],
    edges: list[Edge],
    findings: list[Finding],
    policy_path: Optional[Path] = None,
) -> list[ScenarioMatch]:
    """
    Run all defined scenarios against the provided events, edges, and findings.

    Returns a list of ScenarioMatch objects — both fully satisfied and
    partially satisfied (with constraints_violated populated).
    """
    policies = load_scenario_policies(policy_path)
    events_by_kind = _index_events_by_kind(events)
    events_by_id = _index_events_by_id(events)
    edges_by_kind = _index_edges_by_kind(edges)
    findings_by_event = _index_findings_by_event(findings)

    all_matches: list[ScenarioMatch] = []

    for policy in policies:
        scenario_id = policy["id"]
        matcher = _MATCHERS.get(scenario_id)
        if matcher is None:
            continue
        matches = matcher(
            events_by_kind, events_by_id, edges_by_kind, findings_by_event, policy
        )
        all_matches.extend(matches)

    return all_matches
