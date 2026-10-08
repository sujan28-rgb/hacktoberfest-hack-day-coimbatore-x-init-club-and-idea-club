"""
Tests for the Scenario Matcher.

Verifies:
  1. All three scenarios produce deterministic, bounded results.
  2. Ambiguous PID-only identity never satisfies a scenario.
  3. Missing findings cause constraint violations.
  4. Low-confidence edges are rejected.
  5. Temporal ordering is enforced.
  6. Same inputs always produce same outputs (determinism).
"""

from datetime import datetime

import pytest

from sentinel_evidence.contracts import (
    Edge,
    EdgeKind,
    Event,
    EventKind,
    Finding,
    Severity,
    Source,
)
from sentinel_evidence.correlate.scenarios import run_scenarios, ScenarioMatch


# ===================================================================
# Scenario 1: Suspicious Parent/Child
# ===================================================================

class TestSuspiciousParentChild:
    """Test the suspicious parent/child execution scenario."""

    def test_full_match(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Fully-supported scenario with ProcessGuid linkage and finding."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        pc_matches = [m for m in matches if m.scenario_id == "suspicious_parent_child"]
        assert len(pc_matches) == 1

        match = pc_matches[0]
        assert match.is_fully_satisfied
        assert match.host == "WORKSTATION-01"
        assert "parent" in match.matched_events
        assert "child" in match.matched_events
        assert len(match.matched_edges) == 1
        assert len(match.matched_findings) >= 1
        assert match.identity_confidence >= 0.8

    def test_deterministic(
        self, parent_event, child_event, parent_child_edge, parent_finding
    ):
        """Same inputs must always produce identical outputs."""
        args = dict(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[parent_finding],
        )
        matches_a = run_scenarios(**args)
        matches_b = run_scenarios(**args)

        assert len(matches_a) == len(matches_b)
        for a, b in zip(matches_a, matches_b):
            assert a.scenario_id == b.scenario_id
            assert a.is_fully_satisfied == b.is_fully_satisfied
            assert a.matched_events.keys() == b.matched_events.keys()

    def test_no_finding_violates_constraint(
        self, parent_event, child_event, parent_child_edge
    ):
        """Without a finding, the scenario should flag a constraint violation."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[parent_child_edge],
            findings=[],  # no findings!
        )
        pc_matches = [m for m in matches if m.scenario_id == "suspicious_parent_child"]
        assert len(pc_matches) == 1
        assert not pc_matches[0].is_fully_satisfied
        assert any("finding" in v.lower() for v in pc_matches[0].constraints_violated)

    def test_ambiguous_pid_only_rejected(
        self,
        ambiguous_parent_event,
        ambiguous_child_event,
        ambiguous_parent_child_edge,
        ambiguous_finding,
    ):
        """Ambiguous PID-only identity must NOT satisfy the scenario."""
        matches = run_scenarios(
            events=[ambiguous_parent_event, ambiguous_child_event],
            edges=[ambiguous_parent_child_edge],
            findings=[ambiguous_finding],
        )
        pc_matches = [m for m in matches if m.scenario_id == "suspicious_parent_child"]
        # Edge confidence 0.4 is below threshold 0.8 — should not match at all
        assert len(pc_matches) == 0

    def test_low_confidence_edge_rejected(
        self, parent_event, child_event, parent_finding
    ):
        """Edge with confidence below threshold should be rejected."""
        low_conf_edge = Edge(
            edge_id="edge_low_conf",
            kind=EdgeKind.PARENT_CHILD,
            source_event_id="evt_parent_001",
            target_event_id="evt_child_001",
            host="WORKSTATION-01",
            confidence=0.5,
        )
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[low_conf_edge],
            findings=[parent_finding],
        )
        pc_matches = [m for m in matches if m.scenario_id == "suspicious_parent_child"]
        assert len(pc_matches) == 0


# ===================================================================
# Scenario 2: Flagged Process + Network Connection
# ===================================================================

class TestFlaggedProcessNetwork:
    """Test the flagged process + network connection scenario."""

    def test_full_match(
        self, flagged_process_event, network_event, network_edge, flagged_finding
    ):
        """Fully-supported: flagged process with outbound connection."""
        matches = run_scenarios(
            events=[flagged_process_event, network_event],
            edges=[network_edge],
            findings=[flagged_finding],
        )
        net_matches = [m for m in matches if m.scenario_id == "flagged_process_network"]
        assert len(net_matches) == 1

        match = net_matches[0]
        assert match.is_fully_satisfied
        assert "flagged_process" in match.matched_events
        assert "connection" in match.matched_events

    def test_no_finding_violates_constraint(
        self, flagged_process_event, network_event, network_edge
    ):
        """Without a finding, the scenario flags constraint violation."""
        matches = run_scenarios(
            events=[flagged_process_event, network_event],
            edges=[network_edge],
            findings=[],
        )
        net_matches = [m for m in matches if m.scenario_id == "flagged_process_network"]
        assert len(net_matches) == 1
        assert not net_matches[0].is_fully_satisfied
        assert any("finding" in v.lower() for v in net_matches[0].constraints_violated)

    def test_wrong_temporal_order(self, mock_source, network_edge, flagged_finding):
        """Network event BEFORE process creation should violate temporal constraint."""
        # Process created AFTER network event — wrong order
        late_process = Event(
            event_id="evt_flagged_001",
            kind=EventKind.PROCESS_CREATE,
            timestamp=datetime(2026, 10, 8, 11, 0, 0),  # later
            host="WORKSTATION-01",
            process_guid="{GUID-FLAGGED-001}",
            pid=3000,
            image="C:\\Temp\\suspicious.exe",
            command_line="suspicious.exe",
            parent_process_guid=None,
            parent_image=None,
            user="CORP\\jdoe",
            source=mock_source,
        )
        early_net = Event(
            event_id="evt_net_001",
            kind=EventKind.NETWORK_CONNECT,
            timestamp=datetime(2026, 10, 8, 10, 0, 0),  # earlier
            host="WORKSTATION-01",
            process_guid="{GUID-FLAGGED-001}",
            pid=3000,
            image="C:\\Temp\\suspicious.exe",
            command_line=None,
            parent_process_guid=None,
            parent_image=None,
            user="CORP\\jdoe",
            source=mock_source,
        )
        matches = run_scenarios(
            events=[late_process, early_net],
            edges=[network_edge],
            findings=[flagged_finding],
        )
        net_matches = [m for m in matches if m.scenario_id == "flagged_process_network"]
        assert len(net_matches) == 1
        assert not net_matches[0].is_fully_satisfied
        assert any("temporal" in v.lower() for v in net_matches[0].constraints_violated)

    def test_different_guid_violates(self, mock_source, flagged_finding):
        """Process and network event with different ProcessGuids should violate."""
        proc = Event(
            event_id="evt_proc_diff",
            kind=EventKind.PROCESS_CREATE,
            timestamp=datetime(2026, 10, 8, 10, 0, 0),
            host="WORKSTATION-01",
            process_guid="{GUID-A}",
            pid=100,
            image="suspicious.exe",
            command_line=None,
            parent_process_guid=None,
            parent_image=None,
            user="test",
            source=mock_source,
        )
        net = Event(
            event_id="evt_net_diff",
            kind=EventKind.NETWORK_CONNECT,
            timestamp=datetime(2026, 10, 8, 10, 0, 5),
            host="WORKSTATION-01",
            process_guid="{GUID-B}",  # different!
            pid=200,
            image="suspicious.exe",
            command_line=None,
            parent_process_guid=None,
            parent_image=None,
            user="test",
            source=mock_source,
        )
        edge = Edge(
            edge_id="edge_diff",
            kind=EdgeKind.NETWORK_CONNECTION,
            source_event_id="evt_proc_diff",
            target_event_id="evt_net_diff",
            host="WORKSTATION-01",
            confidence=0.9,
        )
        finding = Finding(
            finding_id="f_diff",
            rule_name="Test",
            severity=Severity.HIGH,
            description="test",
            matched_event_ids=("evt_proc_diff",),
        )

        matches = run_scenarios(
            events=[proc, net],
            edges=[edge],
            findings=[finding],
        )
        net_matches = [m for m in matches if m.scenario_id == "flagged_process_network"]
        assert len(net_matches) == 1
        assert not net_matches[0].is_fully_satisfied
        assert any("ProcessGuid" in v for v in net_matches[0].constraints_violated)


# ===================================================================
# Scenario 3: Flagged Process + File Creation
# ===================================================================

class TestFlaggedProcessFileCreate:
    """Test the flagged process + file creation scenario."""

    def test_full_match(
        self, flagged_process_event, file_create_event, file_edge, flagged_finding
    ):
        """Fully-supported: flagged process creating a file."""
        matches = run_scenarios(
            events=[flagged_process_event, file_create_event],
            edges=[file_edge],
            findings=[flagged_finding],
        )
        file_matches = [m for m in matches if m.scenario_id == "flagged_process_file_create"]
        assert len(file_matches) == 1

        match = file_matches[0]
        assert match.is_fully_satisfied
        assert "flagged_process" in match.matched_events
        assert "file_event" in match.matched_events

    def test_no_finding_violates_constraint(
        self, flagged_process_event, file_create_event, file_edge
    ):
        """Without a finding, constraint is violated."""
        matches = run_scenarios(
            events=[flagged_process_event, file_create_event],
            edges=[file_edge],
            findings=[],
        )
        file_matches = [m for m in matches if m.scenario_id == "flagged_process_file_create"]
        assert len(file_matches) == 1
        assert not file_matches[0].is_fully_satisfied


# ===================================================================
# Edge cases
# ===================================================================

class TestEdgeCases:
    """Test boundary and edge cases for the scenario matcher."""

    def test_empty_inputs(self):
        """Empty inputs produce no matches."""
        matches = run_scenarios(events=[], edges=[], findings=[])
        assert matches == []

    def test_events_without_edges(self, parent_event, child_event, parent_finding):
        """Events without edges produce no matches."""
        matches = run_scenarios(
            events=[parent_event, child_event],
            edges=[],
            findings=[parent_finding],
        )
        assert matches == []

    def test_all_three_scenarios_simultaneously(
        self,
        parent_event, child_event, parent_child_edge, parent_finding,
        flagged_process_event, network_event, network_edge,
        file_create_event, file_edge, flagged_finding,
    ):
        """All three scenarios can match simultaneously on different evidence."""
        matches = run_scenarios(
            events=[
                parent_event, child_event,
                flagged_process_event, network_event,
                file_create_event,
            ],
            edges=[parent_child_edge, network_edge, file_edge],
            findings=[parent_finding, flagged_finding],
        )

        scenario_ids = {m.scenario_id for m in matches}
        assert "suspicious_parent_child" in scenario_ids
        assert "flagged_process_network" in scenario_ids
        assert "flagged_process_file_create" in scenario_ids
