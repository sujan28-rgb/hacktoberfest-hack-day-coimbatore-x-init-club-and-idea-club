"""
Sentinel Evidence — Predicate Registry

Each predicate type defines:
  - required_evidence: what evidence kinds must be present
  - required_identity: identity requirements (e.g. guid-based)
  - prohibitions: what the predicate explicitly does NOT assert
  - min_support_sets: minimum number of support sets required

Evidence constraints (README):
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

from dataclasses import dataclass, field
from typing import Any

from sentinel_evidence.contracts import PredicateType


@dataclass(frozen=True)
class PredicateRequirements:
    """What a predicate requires to be validly asserted."""
    predicate_type: PredicateType
    description: str
    required_evidence: list[str]       # e.g. ["process_create", "network_connect"]
    required_identity: str             # "guid" or "pid_bounded"
    prohibitions: list[str]            # what must NOT be claimed via this predicate
    min_support_sets: int = 1
    required_edge_kinds: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PREDICATE_REGISTRY: dict[PredicateType, PredicateRequirements] = {

    PredicateType.PROCESS_EXECUTED: PredicateRequirements(
        predicate_type=PredicateType.PROCESS_EXECUTED,
        description="A process was observed to be created (process_create event exists).",
        required_evidence=["process_create"],
        required_identity="guid",
        prohibitions=[
            "Process creation does not prove successful execution of the command line.",
        ],
        min_support_sets=1,
    ),

    PredicateType.PARENT_CHILD_EXECUTION: PredicateRequirements(
        predicate_type=PredicateType.PARENT_CHILD_EXECUTION,
        description="A parent process created a child process, confirmed via ProcessGuid linkage.",
        required_evidence=["process_create", "process_create"],
        required_identity="guid",
        prohibitions=[
            "Parent-child creation does not prove the child executed successfully.",
            "Parent-child relationship does not prove malicious intent.",
        ],
        min_support_sets=1,
        required_edge_kinds=["parent_child"],
    ),

    PredicateType.OUTBOUND_CONNECTION_BY_PROCESS: PredicateRequirements(
        predicate_type=PredicateType.OUTBOUND_CONNECTION_BY_PROCESS,
        description="A process made an outbound network connection.",
        required_evidence=["process_create", "network_connect"],
        required_identity="guid",
        prohibitions=[
            "Connection does not prove exfiltration.",
            "Connection does not prove data theft.",
            "Connection does not prove command-and-control communication.",
        ],
        min_support_sets=1,
        required_edge_kinds=["network_connection"],
    ),

    PredicateType.FILE_CREATED_BY_PROCESS: PredicateRequirements(
        predicate_type=PredicateType.FILE_CREATED_BY_PROCESS,
        description="A process created a file on disk.",
        required_evidence=["process_create", "file_create"],
        required_identity="guid",
        prohibitions=[
            "File creation does not prove persistence.",
            "File creation does not prove payload drop.",
            "File creation does not prove malware installation.",
        ],
        min_support_sets=1,
        required_edge_kinds=["file_activity"],
    ),

    PredicateType.SUSPICIOUS_PARENT_CHILD: PredicateRequirements(
        predicate_type=PredicateType.SUSPICIOUS_PARENT_CHILD,
        description="A parent/child process execution is flagged by a detector finding.",
        required_evidence=["process_create", "process_create"],
        required_identity="guid",
        prohibitions=[
            "Suspicious patterns do not confirm malicious behavior.",
            "A detection finding does not constitute proof of compromise.",
        ],
        min_support_sets=1,
        required_edge_kinds=["parent_child"],
    ),

    PredicateType.FLAGGED_PROCESS_NETWORK: PredicateRequirements(
        predicate_type=PredicateType.FLAGGED_PROCESS_NETWORK,
        description="A flagged process made an outbound network connection.",
        required_evidence=["process_create", "network_connect"],
        required_identity="guid",
        prohibitions=[
            "Connection does not prove exfiltration.",
            "Suspicious patterns do not confirm malicious behavior.",
        ],
        min_support_sets=1,
        required_edge_kinds=["network_connection"],
    ),

    PredicateType.FLAGGED_PROCESS_FILE_CREATE: PredicateRequirements(
        predicate_type=PredicateType.FLAGGED_PROCESS_FILE_CREATE,
        description="A flagged process created a file on disk.",
        required_evidence=["process_create", "file_create"],
        required_identity="guid",
        prohibitions=[
            "File creation does not prove persistence.",
            "Suspicious patterns do not confirm malicious behavior.",
        ],
        min_support_sets=1,
        required_edge_kinds=["file_activity"],
    ),
}


def get_predicate_requirements(predicate_type: PredicateType) -> PredicateRequirements:
    """Look up the requirements for a predicate type. Raises KeyError if unknown."""
    reqs = PREDICATE_REGISTRY.get(predicate_type)
    if reqs is None:
        raise KeyError(f"Unknown predicate type: {predicate_type}")
    return reqs


def is_registered_predicate(predicate_type: PredicateType) -> bool:
    """Check whether a predicate type is in the registry."""
    return predicate_type in PREDICATE_REGISTRY
