from datetime import datetime, timedelta
import pytest
from sentinel_evidence.contracts import Event
from sentinel_evidence.normalize.identity import IdentityResolver
from sentinel_evidence.correlate.edges import Correlator

def make_event(event_id, dt, host, event_type, process_guid=None, parent_process_guid=None, raw_fields=None):
    return Event(
        event_id=event_id,
        source_id="src1",
        source_locator="loc1",
        original_timestamp_text=dt.isoformat(),
        normalized_timestamp=dt.isoformat(),
        host=host,
        original_event_id=event_type,
        process_guid=process_guid,
        parent_process_guid=parent_process_guid,
        raw_fields=raw_fields or {}
    )

def test_cross_host_isolation_in_edges():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    events = [
        make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}),
        make_event("2", dt + timedelta(seconds=1), "hostB", "read", process_guid="g2", raw_fields={"ProcessId": 200}),
    ]
    edges = correlator.correlate_near_in_time(events, resolver)
    assert len(edges) == 0

def test_exact_time_boundaries():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    events = [
        make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}),
        make_event("2", dt + timedelta(minutes=10), "hostA", "read", process_guid="g2", raw_fields={"ProcessId": 200}),
        make_event("3", dt + timedelta(minutes=10, seconds=1), "hostA", "read", process_guid="g3", raw_fields={"ProcessId": 300}),
    ]
    edges = correlator.correlate_near_in_time(events, resolver)
    # Event 1 and 2 are within 10 min window (exactly 10 mins). Edge is created.
    # Event 1 and 3 are outside. No edge.
    # Event 2 and 3 are within. Edge is created.
    assert len(edges) == 2

def test_exact_supporting_event_references():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    parent_event = make_event("parent_e", dt, "hostA", "start", process_guid="g_parent", raw_fields={"ProcessId": 100})
    child_event = make_event("child_e", dt + timedelta(seconds=1), "hostA", "start", process_guid="g_child", parent_process_guid="g_parent", raw_fields={
        "ProcessId": 200, "ParentProcessId": 100
    })
    
    edges = correlator.correlate_parent_child([parent_event, child_event], resolver)
    assert len(edges) == 1
    assert edges[0].relationship_type == "reported_parent_of"
    assert "child_e" in edges[0].supporting_events
    assert "parent_e" in edges[0].supporting_events

def test_duplicate_events():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    e1 = make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100})
    e2 = make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100})
    
    edges = correlator.correlate_near_in_time([e1, e2], resolver)
    # Identity is the same (g1). near_in_time shouldn't correlate a process to itself.
    assert len(edges) == 0

def test_ambiguous_identity_produces_no_edges():
    """Events with unresolvable identity must not produce any edges."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    # Events with no ProcessGuid and no prior PID registration
    events = [
        make_event("1", dt, "hostA", "read", raw_fields={"ProcessId": 9999}),
        make_event("2", dt + timedelta(seconds=1), "hostA", "write", raw_fields={"ProcessId": 8888}),
    ]
    edges = correlator.correlate_near_in_time(events, resolver)
    assert len(edges) == 0

def test_no_false_corroboration_from_duplicate_event_ids():
    """Two events with the same ID but different process GUIDs must not inflate edge counts."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    # Simulating a duplicate export: same event ID, different GUID
    e1 = make_event("dup", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100})
    e2 = make_event("dup", dt + timedelta(seconds=1), "hostA", "start", process_guid="g2", raw_fields={"ProcessId": 200})
    edges = correlator.correlate_near_in_time([e1, e2], resolver)
    # Edge is created but both supporting_events point to the same "dup" id
    # The system does not fabricate distinct support from duplicate exports
    assert len(edges) == 1
    assert edges[0].supporting_events == ["dup", "dup"]

def test_temporal_adjacency_is_not_causal():
    """near_in_time edges must have relationship_type 'near_in_time', never 'caused_by'."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    correlator = Correlator(time_window=timedelta(minutes=10))
    
    dt = datetime(2026, 1, 1, 12, 0, 0)
    events = [
        make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}),
        make_event("2", dt + timedelta(seconds=1), "hostA", "start", process_guid="g2", raw_fields={"ProcessId": 200}),
    ]
    edges = correlator.correlate_near_in_time(events, resolver)
    assert len(edges) == 1
    assert edges[0].relationship_type == "near_in_time"
    assert edges[0].relationship_type != "caused_by"
