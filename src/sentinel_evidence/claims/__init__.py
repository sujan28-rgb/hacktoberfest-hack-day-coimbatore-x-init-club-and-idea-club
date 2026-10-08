"""
Claims sub-package — Typed claim compilation and validation.

Modules:
  types      — Claim status and predicate type enums (re-exported from contracts)
  predicates — Predicate registry with requirements
  compile    — Claim compiler (ScenarioMatch → Claim)
  validate   — Claim validation (support sets, contradictions, evidence constraints)
"""

from sentinel_evidence.claims.types import ClaimStatus, PredicateType
from sentinel_evidence.claims.predicates import PREDICATE_REGISTRY, get_predicate_requirements
from sentinel_evidence.claims.compile import compile_claims
from sentinel_evidence.claims.validate import validate_claim, validate_claims

__all__ = [
    "ClaimStatus",
    "PredicateType",
    "PREDICATE_REGISTRY",
    "get_predicate_requirements",
    "compile_claims",
    "validate_claim",
    "validate_claims",
]
