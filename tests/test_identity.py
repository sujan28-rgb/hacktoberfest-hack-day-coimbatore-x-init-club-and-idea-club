from datetime import datetime, timedelta
import pytest
from sentinel_evidence.contracts import Event
from sentinel_evidence.normalize.identity import IdentityResolver, ProcessIdentity

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

def test_deterministic_identity_resolution():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt1 = datetime(2026, 1, 1, 12, 0, 0)
    event1 = make_event("e1", dt1, "hostA", "test", process_guid="guid1", raw_fields={"ProcessId": 1234})
    identity1 = resolver.resolve_identity(event1)
    assert identity1.id == "hostA_guid1"
    # Duplicate event
    identity2 = resolver.resolve_identity(event1)
    assert identity1.id == identity2.id

def test_process_guid_precedence():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt1 = datetime(2026, 1, 1, 12, 0, 0)
    event1 = make_event("e1", dt1, "hostA", "test", process_guid="guid1", raw_fields={"ProcessId": 1234})
    event2 = make_event("e2", dt1 + timedelta(seconds=1), "hostA", "test", process_guid="guid2", raw_fields={"ProcessId": 1234})
    identity1 = resolver.resolve_identity(event1)
    identity2 = resolver.resolve_identity(event2)
    assert identity1.id != identity2.id

def test_pid_reuse_protection_and_ambiguity_preservation():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    # Process 1 starts
    resolver.resolve_identity(make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}))
    # Process 2 starts rapidly with same PID
    resolver.resolve_identity(make_event("2", dt + timedelta(seconds=0.5), "hostA", "start", process_guid="g2", raw_fields={"ProcessId": 100}))
    
    # Ambiguous fallback
    e_fallback = make_event("3", dt + timedelta(seconds=1), "hostA", "read", raw_fields={"ProcessId": 100})
    assert resolver.resolve_identity(e_fallback) is None

def test_pid_reuse_expiration():
    # If the pid reuse window expires, we also return Ambiguous / None
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    resolver.resolve_identity(make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}))
    
    # 10 minutes later (exceeds window)
    e_fallback = make_event("2", dt + timedelta(minutes=10), "hostA", "read", raw_fields={"ProcessId": 100})
    assert resolver.resolve_identity(e_fallback) is None

def test_cross_host_isolation():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    id1 = resolver.resolve_identity(make_event("1", dt, "hostA", "test", process_guid="g1", raw_fields={"ProcessId": 100}))
    id2 = resolver.resolve_identity(make_event("2", dt, "hostB", "test", process_guid="g1", raw_fields={"ProcessId": 100}))
    assert id1.id != id2.id

def test_ambiguity_preservation_no_data():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    e = make_event("1", datetime(2026, 1, 1, 12, 0, 0), "hostA", "test", raw_fields={})
    assert resolver.resolve_identity(e) is None
    
def test_multiple_pid_candidates_valid():
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    resolver.resolve_identity(make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}))
    resolver.resolve_identity(make_event("2", dt + timedelta(hours=1), "hostA", "start", process_guid="g2", raw_fields={"ProcessId": 100}))
    
    # Fallback closer to g2
    e_fallback = make_event("3", dt + timedelta(hours=1, minutes=2), "hostA", "read", raw_fields={"ProcessId": 100})
    fallback_id = resolver.resolve_identity(e_fallback)
    assert fallback_id is not None
    assert fallback_id.id == "hostA_g2"

def test_pid_only_no_prior_registration():
    """PID-only event with no previously registered GUID owner returns None."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    e = make_event("1", datetime(2026, 1, 1, 12, 0, 0), "hostA", "read", raw_fields={"ProcessId": 9999})
    assert resolver.resolve_identity(e) is None

def test_exact_pid_reuse_window_boundary():
    """PID fallback at exactly the boundary of the reuse window."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    resolver.resolve_identity(make_event("1", dt, "hostA", "start", process_guid="g1", raw_fields={"ProcessId": 100}))
    
    # Exactly at the boundary (5 min)
    e_at_boundary = make_event("2", dt + timedelta(minutes=5), "hostA", "read", raw_fields={"ProcessId": 100})
    result = resolver.resolve_identity(e_at_boundary)
    # 5 min == 5 min is NOT > pid_reuse_window, so it should resolve
    assert result is not None
    assert result.id == "hostA_g1"
    
    # 1 second past the boundary
    e_past_boundary = make_event("3", dt + timedelta(minutes=5, seconds=1), "hostA", "read", raw_fields={"ProcessId": 100})
    result = resolver.resolve_identity(e_past_boundary)
    assert result is None

def test_conflicting_parent_identity():
    """Parent with GUID resolves; parent with only PID and no match returns None."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    # Child references a parent GUID we've never seen
    child_event = make_event("c1", dt, "hostA", "start", process_guid="g_child", parent_process_guid="g_parent_unknown", raw_fields={
        "ProcessId": 200, "ParentProcessId": 500
    })
    parent_id = resolver.resolve_parent_identity(child_event)
    # Should create a new identity for the unseen parent GUID
    assert parent_id is not None
    assert parent_id.process_guid == "g_parent_unknown"
    
    # Now try parent with only PID, no GUID, and no registration
    child_event_no_guid = make_event("c2", dt + timedelta(seconds=1), "hostA", "start", process_guid="g_child2", raw_fields={
        "ProcessId": 300, "ParentProcessId": 9999
    })
    parent_id2 = resolver.resolve_parent_identity(child_event_no_guid)
    assert parent_id2 is None

def test_same_guid_different_hosts_are_distinct():
    """Identical GUIDs on different hosts must yield distinct identities."""
    resolver = IdentityResolver(pid_reuse_window=timedelta(minutes=5))
    dt = datetime(2026, 1, 1, 12, 0, 0)
    
    hosts = ["hostA", "hostB", "hostC"]
    identities = []
    for h in hosts:
        e = make_event(f"e_{h}", dt, h, "start", process_guid="same-guid", raw_fields={"ProcessId": 100})
        identities.append(resolver.resolve_identity(e))
    
    ids = [i.id for i in identities]
    assert len(set(ids)) == 3  # All three must be distinct
