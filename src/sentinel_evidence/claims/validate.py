"""
Sentinel Evidence — Claim Validation

Validates compiled claims against predicate requirements, evidence constraints,
identity certainty, and contradictions.

Key rules:
  1. Every accepted factual claim MUST have at least one valid support set.
  2. Predicate requirements from the registry must be satisfied.
  3. Identity must be guid-based (ambiguous PID ≠ verified identity).
  4. Contradictory evidence is preserved, never silently dropped.
  5. Removing sole supporting evidence withdraws or downgrades the claim.
  6. Unsupported predicates/conclusions are rejected.
  7. Duplicate exports do NOT count as independent corroboration.

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
from typing import Any, Optional

from sentinel_evidence.contracts import (
    Claim,
    ClaimStatus,
    Event,
    Finding,
    SupportSet,
)
from sentinel_evidence.claims.predicates import (
    PREDICATE_REGISTRY,
    get_predicate_requirements,
    is_registered_predicate,
)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of validating a single claim."""
    claim_id: str
    is_valid: bool
    original_status: ClaimStatus
    validated_status: ClaimStatus
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core validators
# ---------------------------------------------------------------------------

def _validate_predicate_registered(claim: Claim) -> list[str]:
    """Ensure the predicate type is in the registry."""
    if not is_registered_predicate(claim.predicate_type):
        return [f"Unknown predicate type: {claim.predicate_type}"]
    return []


def _validate_support_sets(claim: Claim) -> list[str]:
    """
    Validate that accepted claims have valid support sets.
    A claim with status other than insufficient_evidence MUST have
    at least one support set with at least one evidence_id.
    """
    errors = []

    if claim.status in (ClaimStatus.OBSERVED, ClaimStatus.SUPPORTED_INFERENCE):
        if not claim.support_sets:
            errors.append(
                f"Claim {claim.claim_id} has status '{claim.status.value}' "
                f"but no support sets."
            )
        else:
            for i, ss in enumerate(claim.support_sets):
                if not ss.evidence_ids:
                    errors.append(
                        f"Support set {i} for claim {claim.claim_id} has no evidence IDs."
                    )

    # Check minimum support sets from predicate requirements
    if is_registered_predicate(claim.predicate_type):
        reqs = get_predicate_requirements(claim.predicate_type)
        if claim.status != ClaimStatus.INSUFFICIENT_EVIDENCE:
            if len(claim.support_sets) < reqs.min_support_sets:
                errors.append(
                    f"Claim {claim.claim_id} requires at least {reqs.min_support_sets} "
                    f"support set(s) but has {len(claim.support_sets)}."
                )

    return errors


def _validate_identity_certainty(claim: Claim) -> list[str]:
    """
    Ensure that claims requiring guid identity actually have guid-based entities.
    Ambiguous PID-only identity NEVER creates verified relationships.
    """
    errors = []

    if not is_registered_predicate(claim.predicate_type):
        return errors

    reqs = get_predicate_requirements(claim.predicate_type)
    if reqs.required_identity == "guid":
        # Check that bound_entities contain at least one process_guid
        has_guid = any(
            "process_guid" in k and v is not None and v != ""
            for k, v in claim.bound_entities.items()
        )
        if not has_guid and claim.status in (ClaimStatus.OBSERVED, ClaimStatus.SUPPORTED_INFERENCE):
            errors.append(
                f"Claim {claim.claim_id} requires guid-based identity but "
                f"no valid ProcessGuid found in bound_entities."
            )

    return errors


def _validate_no_duplicate_corroboration(claim: Claim) -> list[str]:
    """
    Ensure that duplicate/repeated exports of the same evidence are not
    counted as independent corroboration.
    """
    warnings = []
    all_evidence_ids: list[str] = []

    for ss in claim.support_sets:
        all_evidence_ids.extend(ss.evidence_ids)

    if len(all_evidence_ids) != len(set(all_evidence_ids)):
        warnings.append(
            f"Claim {claim.claim_id}: duplicate evidence IDs found across "
            f"support sets. Repeated exports do not count as independent corroboration."
        )

    return warnings


# ---------------------------------------------------------------------------
# Evidence removal check
# ---------------------------------------------------------------------------

def check_evidence_removal(
    claim: Claim,
    available_evidence_ids: set[str],
) -> Claim:
    """
    Check whether a claim's support is still valid given the set of available
    evidence. If sole supporting evidence is removed, the claim is downgraded
    to INSUFFICIENT_EVIDENCE.

    Returns a new Claim with updated status and support sets.
    """
    valid_support_sets = []
    for ss in claim.support_sets:
        remaining_ids = [eid for eid in ss.evidence_ids if eid in available_evidence_ids]
        if remaining_ids:
            valid_support_sets.append(SupportSet(
                evidence_ids=remaining_ids,
                relevant_fields=ss.relevant_fields,
                description=ss.description,
            ))

    if not valid_support_sets:
        # All support removed — downgrade
        return Claim(
            claim_id=claim.claim_id,
            predicate_type=claim.predicate_type,
            bound_entities=claim.bound_entities,
            support_sets=[],
            contradictory_evidence=claim.contradictory_evidence,
            unmet_prerequisites=claim.unmet_prerequisites + [
                "All supporting evidence has been removed."
            ],
            status=ClaimStatus.INSUFFICIENT_EVIDENCE,
            scenario_id=claim.scenario_id,
            metadata=claim.metadata,
        )
    else:
        # Some support remains — check if we need to downgrade
        new_status = claim.status
        # If support sets lost evidence, downgrade from OBSERVED to SUPPORTED_INFERENCE
        total_original = sum(len(ss.evidence_ids) for ss in claim.support_sets)
        total_remaining = sum(len(ss.evidence_ids) for ss in valid_support_sets)
        if total_remaining < total_original and claim.status == ClaimStatus.OBSERVED:
            new_status = ClaimStatus.SUPPORTED_INFERENCE

        return Claim(
            claim_id=claim.claim_id,
            predicate_type=claim.predicate_type,
            bound_entities=claim.bound_entities,
            support_sets=valid_support_sets,
            contradictory_evidence=claim.contradictory_evidence,
            unmet_prerequisites=claim.unmet_prerequisites,
            status=new_status,
            scenario_id=claim.scenario_id,
            metadata=claim.metadata,
        )


# ---------------------------------------------------------------------------
# Contradiction detection
# ---------------------------------------------------------------------------

def add_contradictory_evidence(
    claim: Claim,
    contradictions: list[SupportSet],
) -> Claim:
    """
    Add contradictory evidence to a claim, preserving it for downstream
    inspection. Contradictions are NEVER silently dropped.
    """
    return Claim(
        claim_id=claim.claim_id,
        predicate_type=claim.predicate_type,
        bound_entities=claim.bound_entities,
        support_sets=claim.support_sets,
        contradictory_evidence=claim.contradictory_evidence + contradictions,
        unmet_prerequisites=claim.unmet_prerequisites,
        status=claim.status,
        scenario_id=claim.scenario_id,
        metadata=claim.metadata,
    )


# ---------------------------------------------------------------------------
# Main validation entry points
# ---------------------------------------------------------------------------

def validate_claim(claim: Claim) -> ValidationResult:
    """
    Validate a single claim against all rules.

    Returns a ValidationResult. If validation fails, the claim's status
    should be downgraded to INSUFFICIENT_EVIDENCE.
    """
    errors: list[str] = []
    warnings: list[str] = []

    errors.extend(_validate_predicate_registered(claim))
    errors.extend(_validate_support_sets(claim))
    errors.extend(_validate_identity_certainty(claim))
    warnings.extend(_validate_no_duplicate_corroboration(claim))

    is_valid = len(errors) == 0
    validated_status = claim.status if is_valid else ClaimStatus.INSUFFICIENT_EVIDENCE

    return ValidationResult(
        claim_id=claim.claim_id,
        is_valid=is_valid,
        original_status=claim.status,
        validated_status=validated_status,
        errors=errors,
        warnings=warnings,
    )


def validate_claims(claims: list[Claim]) -> list[tuple[Claim, ValidationResult]]:
    """
    Validate all claims. Returns list of (potentially-updated Claim, ValidationResult).

    Claims that fail validation have their status downgraded.
    """
    results = []
    for claim in claims:
        vr = validate_claim(claim)
        if not vr.is_valid:
            # Downgrade the claim
            downgraded = Claim(
                claim_id=claim.claim_id,
                predicate_type=claim.predicate_type,
                bound_entities=claim.bound_entities,
                support_sets=claim.support_sets,
                contradictory_evidence=claim.contradictory_evidence,
                unmet_prerequisites=claim.unmet_prerequisites + vr.errors,
                status=ClaimStatus.INSUFFICIENT_EVIDENCE,
                scenario_id=claim.scenario_id,
                metadata=claim.metadata,
            )
            results.append((downgraded, vr))
        else:
            results.append((claim, vr))

    return results
