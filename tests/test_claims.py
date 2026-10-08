"""
Tests for the Claim Compiler and Validator.

Verifies:
  1. Every accepted factual claim has exact supporting events/fields.
  2. Contradictions and unmet prerequisites remain visible.
  3. Ambiguous identities never create verified relationships.
  4. Removing sole supporting evidence withdraws or downgrades the claim.
  5. Unsupported predicates/conclusions are rejected.
  6. Duplicate exports do not count as independent corroboration.
  7. Output matches canonical contracts and is consumable downstream.
  8. Incomplete and contradictory inputs are handled correctly.
"""

from datetime import datetime

import pytest

from sentinel_evidence.contracts import (
    Claim,
    ClaimStatus,
    Edge,
    EdgeKind,
    Event,
    EventKind,
    Finding,
    PredicateType,
    Severity,
    Source,
    SupportSet,
)
from sentinel_evidence.correlate.scenarios import run_scenarios
from sentinel_evidence.claims.compile import compile_claims, compile_claim
from sentinel_evidence.claims.validate import (
    validate_claim,
    validate_claims,
    check_evidence_removal,
    add_contradictory_evidence,
    ValidationResult,
)
from sentinel_evidence.claims.predicates import (
    get_predicate_requirements,
    is_registered_predicate,
    PREDICATE_REGISTRY,
)


# ===================================================================
# Claim compilation from scenario matches
# ===================================================================

class TestClaimCompilation:
    """Test claim compilation from scenario matches."""

    def test_compile_parent_child_claim(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Compile a fully-supported parent/child scenario into a claim."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        pc_claims = [c for c in claims if c.predicate_type == PredicateType.SUSPICIOUS_PARENT_CHILD]

        assert len(pc_claims) == 1
        claim = pc_claims[0]

        # Canonical contract fields
        assert claim.claim_id  # non-empty
        assert claim.predicate_type == PredicateType.SUSPICIOUS_PARENT_CHILD
        assert claim.bound_entities  # non-empty
        assert claim.scenario_id == "suspicious_parent_child"

        # Accepted claim MUST have valid support
        assert claim.has_valid_support()
        assert len(claim.support_sets) >= 1

        # Support set references exact evidence
        ss = claim.support_sets[0]
        assert parent_event.event_id in ss.evidence_ids
        assert child_event.event_id in ss.evidence_ids
        assert parent_child_edge.edge_id in ss.evidence_ids
        assert parent_finding.finding_id in ss.evidence_ids

        # Relevant fields captured
        assert ss.relevant_fields.get("parent_image") == parent_event.image
        assert ss.relevant_fields.get("child_image") == child_event.image

        # Status should be supported_inference (not observed — it's a correlation)
        assert claim.status in (ClaimStatus.SUPPORTED_INFERENCE, ClaimStatus.OBSERVED)

        # No unmet prerequisites for fully-satisfied scenario
        assert claim.unmet_prerequisites == []

    def test_compile_network_claim(
        self, flagged_process_event, network_event, network_edge, flagged_finding
    ):
        """Compile a flagged process + network connection claim."""
        matches = run_scenarios(
            events=[flagged_process_event, network_event],
            edges=[network_edge],
            findings=[flagged_finding],
        )
        claims = compile_claims(matches)
        net_claims = [c for c in claims if c.predicate_type == PredicateType.FLAGGED_PROCESS_NETWORK]

        assert len(net_claims) == 1
        claim = net_claims[0]
        assert claim.has_valid_support()

        # Support set references exact evidence
        ss = claim.support_sets[0]
        assert flagged_process_event.event_id in ss.evidence_ids
        assert network_event.event_id in ss.evidence_ids

        # NOTE in description: connection ≠ exfiltration
        assert "exfiltration" in ss.description.lower() or "NOT" in ss.description

    def test_compile_file_create_claim(
        self, flagged_process_event, file_create_event, file_edge, flagged_finding
    ):
        """Compile a flagged process + file creation claim."""
        matches = run_scenarios(
            events=[flagged_process_event, file_create_event],
            edges=[file_edge],
            findings=[flagged_finding],
        )
        claims = compile_claims(matches)
        file_claims = [c for c in claims if c.predicate_type == PredicateType.FLAGGED_PROCESS_FILE_CREATE]

        assert len(file_claims) == 1
        claim = file_claims[0]
        assert claim.has_valid_support()

        # NOTE in description: file creation ≠ persistence
        ss = claim.support_sets[0]
        assert "persistence" in ss.description.lower() or "NOT" in ss.description

    def test_compile_violated_scenario_produces_insufficient_claim(
        self, parent_event, child_event, parent_child_edge
    ):
        """A scenario with violated constraints produces insufficient_evidence claim."""
        # No findings → constraint violated
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[],
        )
        claims = compile_claims(matches)
        assert len(claims) >= 1

        claim = claims[0]
        # Should be insufficient or hypothesis (constraint violated)
        assert claim.status in (ClaimStatus.INSUFFICIENT_EVIDENCE, ClaimStatus.HYPOTHESIS)

        if claim.status == ClaimStatus.INSUFFICIENT_EVIDENCE:
            assert claim.support_sets == []  # no support when insufficient
        assert len(claim.unmet_prerequisites) > 0

    def test_deterministic_claim_ids(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Same inputs produce identical claim_ids (deterministic)."""
        args = dict(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims_a = compile_claims(run_scenarios(**args))
        claims_b = compile_claims(run_scenarios(**args))
        assert [c.claim_id for c in claims_a] == [c.claim_id for c in claims_b]


# ===================================================================
# Claim validation
# ===================================================================

class TestClaimValidation:
    """Test claim validation rules."""

    def test_valid_claim_passes(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """A properly-supported claim passes validation."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        results = validate_claims(claims)

        for claim, vr in results:
            if claim.status in (ClaimStatus.SUPPORTED_INFERENCE, ClaimStatus.OBSERVED):
                assert vr.is_valid, f"Expected valid: errors={vr.errors}"

    def test_claim_without_support_fails(self):
        """A claim with accepted status but no support sets fails validation."""
        bad_claim = Claim(
            claim_id="bad_001",
            predicate_type=PredicateType.SUSPICIOUS_PARENT_CHILD,
            bound_entities={"host": "WS01", "parent_process_guid": "{GUID}"},
            support_sets=[],  # no support!
            contradictory_evidence=[],
            unmet_prerequisites=[],
            status=ClaimStatus.SUPPORTED_INFERENCE,  # but no support
        )
        vr = validate_claim(bad_claim)
        assert not vr.is_valid
        assert vr.validated_status == ClaimStatus.INSUFFICIENT_EVIDENCE

    def test_claim_without_guid_fails(self):
        """A claim requiring guid identity but without any guid fails validation."""
        bad_claim = Claim(
            claim_id="bad_002",
            predicate_type=PredicateType.SUSPICIOUS_PARENT_CHILD,
            bound_entities={"host": "WS01"},  # no process_guid!
            support_sets=[SupportSet(
                evidence_ids=["evt_1"],
                relevant_fields={},
                description="test",
            )],
            contradictory_evidence=[],
            unmet_prerequisites=[],
            status=ClaimStatus.SUPPORTED_INFERENCE,
        )
        vr = validate_claim(bad_claim)
        assert not vr.is_valid
        assert any("guid" in e.lower() for e in vr.errors)

    def test_unknown_predicate_rejected(self):
        """A claim with an unregistered predicate type is rejected."""
        # We can't easily create an unknown PredicateType since it's an enum,
        # but we can test the registry function
        with pytest.raises(KeyError):
            get_predicate_requirements("definitely_not_a_real_predicate")

    def test_all_predicates_registered(self):
        """All PredicateType enum values should be in the registry."""
        for pt in PredicateType:
            assert is_registered_predicate(pt), f"{pt} not in registry"


# ===================================================================
# Evidence removal
# ===================================================================

class TestEvidenceRemoval:
    """Test the evidence removal rule."""

    def test_removing_sole_evidence_downgrades(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Removing the sole supporting evidence downgrades to insufficient."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        assert len(claims) >= 1
        claim = claims[0]
        assert claim.has_valid_support()

        # Remove ALL evidence
        updated = check_evidence_removal(claim, available_evidence_ids=set())
        assert updated.status == ClaimStatus.INSUFFICIENT_EVIDENCE
        assert updated.support_sets == []
        assert any("removed" in p.lower() for p in updated.unmet_prerequisites)

    def test_partial_evidence_removal(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """A remaining parent cannot establish a relationship after its child is removed."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        claim = claims[0]

        # Keep only the parent event
        updated = check_evidence_removal(
            claim,
            available_evidence_ids={parent_event.event_id},
        )
        # Some support remains
        assert not updated.support_sets
        assert updated.status == ClaimStatus.INSUFFICIENT_EVIDENCE

    def test_all_evidence_present_no_change(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """When all evidence is present, claim remains unchanged."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        claim = claims[0]

        all_ids = set()
        for ss in claim.support_sets:
            all_ids.update(ss.evidence_ids)

        updated = check_evidence_removal(claim, available_evidence_ids=all_ids)
        assert updated.status == claim.status
        assert len(updated.support_sets) == len(claim.support_sets)


# ===================================================================
# Contradictory evidence
# ===================================================================

class TestContradictoryEvidence:
    """Test that contradictions are preserved, not silently dropped."""

    def test_add_contradiction(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Adding contradictory evidence preserves it on the claim."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        claim = claims[0]

        contradiction = SupportSet(
            evidence_ids=["evt_contra_001"],
            relevant_fields={"note": "process terminated before child creation"},
            description="Parent process terminated before child was observed.",
        )
        updated = add_contradictory_evidence(claim, [contradiction])

        assert len(updated.contradictory_evidence) == 1
        assert updated.contradictory_evidence[0].evidence_ids == ["evt_contra_001"]
        # Original support sets preserved
        assert updated.support_sets == claim.support_sets

    def test_multiple_contradictions_preserved(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Multiple contradictions are all preserved."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)
        claim = claims[0]

        c1 = SupportSet(evidence_ids=["c1"], relevant_fields={}, description="Contradiction 1")
        c2 = SupportSet(evidence_ids=["c2"], relevant_fields={}, description="Contradiction 2")

        updated = add_contradictory_evidence(claim, [c1, c2])
        assert len(updated.contradictory_evidence) == 2


# ===================================================================
# Duplicate corroboration
# ===================================================================

class TestDuplicateCorroboration:
    """Test that duplicate exports don't count as independent corroboration."""

    def test_duplicate_evidence_flagged(self):
        """A claim with duplicate evidence IDs across support sets gets a warning."""
        claim = Claim(
            claim_id="dup_001",
            predicate_type=PredicateType.PROCESS_EXECUTED,
            bound_entities={"host": "WS01", "process_guid": "{GUID}"},
            support_sets=[
                SupportSet(evidence_ids=["evt_1", "evt_2"], relevant_fields={}, description="Set A"),
                SupportSet(evidence_ids=["evt_1", "evt_3"], relevant_fields={}, description="Set B"),
            ],
            contradictory_evidence=[],
            unmet_prerequisites=[],
            status=ClaimStatus.SUPPORTED_INFERENCE,
        )
        vr = validate_claim(claim)
        assert len(vr.warnings) > 0
        assert any("duplicate" in w.lower() for w in vr.warnings)


# ===================================================================
# Contract compliance
# ===================================================================

class TestContractCompliance:
    """Test that output matches canonical contracts."""

    def test_claim_has_all_canonical_fields(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Every compiled claim has all canonical contract fields."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)

        for claim in claims:
            assert hasattr(claim, "claim_id")
            assert hasattr(claim, "predicate_type")
            assert hasattr(claim, "bound_entities")
            assert hasattr(claim, "support_sets")
            assert hasattr(claim, "contradictory_evidence")
            assert hasattr(claim, "unmet_prerequisites")
            assert hasattr(claim, "status")
            assert isinstance(claim.claim_id, str)
            assert isinstance(claim.predicate_type, PredicateType)
            assert isinstance(claim.bound_entities, dict)
            assert isinstance(claim.support_sets, list)
            assert isinstance(claim.contradictory_evidence, list)
            assert isinstance(claim.unmet_prerequisites, list)
            assert isinstance(claim.status, ClaimStatus)

    def test_support_set_has_canonical_fields(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Every support set in a claim has evidence_ids, relevant_fields, description."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        claims = compile_claims(matches)

        for claim in claims:
            for ss in claim.support_sets:
                assert isinstance(ss.evidence_ids, list)
                assert isinstance(ss.relevant_fields, dict)
                assert isinstance(ss.description, str)
                assert len(ss.evidence_ids) > 0  # non-empty for accepted claims


# ===================================================================
# End-to-end pipeline
# ===================================================================

class TestEndToEnd:
    """Test the full scenarios → claims → validation pipeline."""

    def test_full_pipeline(
        self,
        parent_event, child_event, parent_child_edge, parent_finding,
        flagged_process_event, network_event, network_edge,
        file_create_event, file_edge, flagged_finding,
    ):
        """Run all 3 scenarios through compilation and validation."""
        # Step 1: Scenario matching
        matches = run_scenarios(
            events=[
                parent_event, child_event,
                flagged_process_event, network_event,
                file_create_event,
            ],
            edges=[parent_child_edge, network_edge, file_edge],
            findings=[parent_finding, flagged_finding],
        )
        assert len(matches) == 3

        # Step 2: Claim compilation
        claims = compile_claims(matches)
        assert len(claims) == 3

        # Step 3: Validation
        results = validate_claims(claims)
        assert len(results) == 3

        for claim, vr in results:
            assert vr.claim_id == claim.claim_id
            if claim.status in (ClaimStatus.SUPPORTED_INFERENCE, ClaimStatus.OBSERVED):
                assert vr.is_valid
                assert claim.has_valid_support()
