"""
Sentinel Evidence — Claim Type Definitions

Re-exports canonical types from contracts.py and adds any claims-specific
type helpers.
"""

from sentinel_evidence.contracts import (
    Claim,
    ClaimStatus,
    PredicateType,
    SupportSet,
)

__all__ = [
    "Claim",
    "ClaimStatus",
    "PredicateType",
    "SupportSet",
]
