"""
Shared test fixtures for Sentinel Evidence tests.

Provides contract-compatible mock events, findings, and edges
for all three MVP scenarios.
"""

import pytest
from datetime import datetime, timedelta

from sentinel_evidence.contracts import (
    Edge,
    EdgeKind,
    Event,
    EventKind,
    Finding,
    Severity,
    Source,
    make_deterministic_id,
)


# ---------------------------------------------------------------------------
# Common source fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_source():
    return Source(
        file_hash="abc123def456",
        file_path="/evidence/sysmon.jsonl",
        line_number=1,
        raw_hash="raw_hash_001",
    )


# ---------------------------------------------------------------------------
# Scenario 1: Suspicious Parent/Child — full support
# ---------------------------------------------------------------------------

@pytest.fixture
def parent_event(mock_source):
    return Event(
        event_id="evt_parent_001",
        kind=EventKind.PROCESS_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 0, 0),
        host="WORKSTATION-01",
        process_guid="{GUID-PARENT-001}",
        pid=1000,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
        parent_process_guid="{GUID-EXPLORER}",
        parent_image="C:\\Windows\\explorer.exe",
        user="CORP\\jdoe",
        source=mock_source,
    )


@pytest.fixture
def child_event(mock_source):
    return Event(
        event_id="evt_child_001",
        kind=EventKind.PROCESS_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 0, 1),
        host="WORKSTATION-01",
        process_guid="{GUID-CHILD-001}",
        pid=2000,
        image="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe -enc AAAA",
        parent_process_guid="{GUID-PARENT-001}",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\jdoe",
        source=mock_source,
    )


@pytest.fixture
def parent_child_edge():
    return Edge(
        edge_id="edge_pc_001",
        kind=EdgeKind.PARENT_CHILD,
        source_event_id="evt_parent_001",
        target_event_id="evt_child_001",
        host="WORKSTATION-01",
        confidence=0.95,
    )


@pytest.fixture
def parent_finding():
    return Finding(
        finding_id="finding_001",
        rule_name="Suspicious Command Shell",
        severity=Severity.HIGH,
        description="cmd.exe executing encoded powershell",
        matched_event_ids=("evt_parent_001",),
        tags=("T1059.001",),
    )


# ---------------------------------------------------------------------------
# Scenario 2: Flagged Process + Network Connection — full support
# ---------------------------------------------------------------------------

@pytest.fixture
def flagged_process_event(mock_source):
    return Event(
        event_id="evt_flagged_001",
        kind=EventKind.PROCESS_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 5, 0),
        host="WORKSTATION-01",
        process_guid="{GUID-FLAGGED-001}",
        pid=3000,
        image="C:\\Temp\\suspicious.exe",
        command_line="suspicious.exe --beacon",
        parent_process_guid="{GUID-PARENT-001}",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\jdoe",
        source=mock_source,
    )


@pytest.fixture
def network_event(mock_source):
    return Event(
        event_id="evt_net_001",
        kind=EventKind.NETWORK_CONNECT,
        timestamp=datetime(2026, 10, 8, 10, 5, 30),
        host="WORKSTATION-01",
        process_guid="{GUID-FLAGGED-001}",
        pid=3000,
        image="C:\\Temp\\suspicious.exe",
        command_line=None,
        parent_process_guid=None,
        parent_image=None,
        user="CORP\\jdoe",
        source=mock_source,
        fields={"dest_ip": "10.0.0.99", "dest_port": 443, "protocol": "tcp"},
    )


@pytest.fixture
def network_edge():
    return Edge(
        edge_id="edge_net_001",
        kind=EdgeKind.NETWORK_CONNECTION,
        source_event_id="evt_flagged_001",
        target_event_id="evt_net_001",
        host="WORKSTATION-01",
        confidence=0.95,
    )


@pytest.fixture
def flagged_finding():
    return Finding(
        finding_id="finding_002",
        rule_name="Known Malicious Binary",
        severity=Severity.CRITICAL,
        description="suspicious.exe is a known threat",
        matched_event_ids=("evt_flagged_001",),
        tags=("T1071",),
    )


# ---------------------------------------------------------------------------
# Scenario 3: Flagged Process + File Creation — full support
# ---------------------------------------------------------------------------

@pytest.fixture
def file_create_event(mock_source):
    return Event(
        event_id="evt_file_001",
        kind=EventKind.FILE_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 5, 45),
        host="WORKSTATION-01",
        process_guid="{GUID-FLAGGED-001}",
        pid=3000,
        image="C:\\Temp\\suspicious.exe",
        command_line=None,
        parent_process_guid=None,
        parent_image=None,
        user="CORP\\jdoe",
        source=mock_source,
        fields={"target_filename": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.dll"},
    )


@pytest.fixture
def file_edge():
    return Edge(
        edge_id="edge_file_001",
        kind=EdgeKind.FILE_ACTIVITY,
        source_event_id="evt_flagged_001",
        target_event_id="evt_file_001",
        host="WORKSTATION-01",
        confidence=0.95,
    )


# ---------------------------------------------------------------------------
# Ambiguous / PID-only fixtures (no ProcessGuid)
# ---------------------------------------------------------------------------

@pytest.fixture
def ambiguous_parent_event(mock_source):
    """Parent event with NO ProcessGuid — PID-only identity."""
    return Event(
        event_id="evt_ambig_parent",
        kind=EventKind.PROCESS_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 0, 0),
        host="WORKSTATION-01",
        process_guid=None,   # ambiguous!
        pid=5000,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe",
        parent_process_guid=None,
        parent_image=None,
        user="CORP\\jdoe",
        source=mock_source,
    )


@pytest.fixture
def ambiguous_child_event(mock_source):
    """Child event with NO ProcessGuid — PID-only identity."""
    return Event(
        event_id="evt_ambig_child",
        kind=EventKind.PROCESS_CREATE,
        timestamp=datetime(2026, 10, 8, 10, 0, 1),
        host="WORKSTATION-01",
        process_guid=None,   # ambiguous!
        pid=6000,
        image="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe",
        parent_process_guid=None,  # no guid linkage
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\jdoe",
        source=mock_source,
    )


@pytest.fixture
def ambiguous_parent_child_edge():
    """Edge between PID-only events — low confidence."""
    return Edge(
        edge_id="edge_ambig_pc",
        kind=EdgeKind.PARENT_CHILD,
        source_event_id="evt_ambig_parent",
        target_event_id="evt_ambig_child",
        host="WORKSTATION-01",
        confidence=0.4,  # below min_identity_confidence threshold
    )


@pytest.fixture
def ambiguous_finding():
    return Finding(
        finding_id="finding_ambig",
        rule_name="Suspicious Shell",
        severity=Severity.MEDIUM,
        description="suspicious process tree",
        matched_event_ids=("evt_ambig_parent",),
    )
