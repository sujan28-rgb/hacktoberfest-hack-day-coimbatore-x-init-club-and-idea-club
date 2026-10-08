"""Bounded relationships using canonical events; time alone never proves a relation."""
from datetime import timedelta
from sentinel_evidence.contracts import EventKind, EdgeKind, Edge, make_deterministic_id
from sentinel_evidence.normalize.identity import IdentityResolver


def correlate(events, window_seconds=300):
    resolver = IdentityResolver(timedelta(seconds=window_seconds))
    creates = [e for e in events if e.kind == EventKind.PROCESS_CREATE and e.host and e.timestamp]
    by_guid = {}
    by_pid = {}
    terminations = {}
    for event in creates:
        by_guid.setdefault((event.host, event.process_guid), []).append(event)
        by_pid.setdefault((event.host, event.pid), []).append(event)
    for event in events:
        if event.kind == EventKind.PROCESS_TERMINATE and event.process_guid and event.timestamp:
            terminations.setdefault((event.host, event.process_guid), []).append(event.timestamp)
    for event in creates:
        resolver.resolve_identity(event)
    identities = {}
    edges = []
    for event in events:
        identity = resolver.resolve_identity(event)
        if identity and not event.process_guid:
            origins = by_pid.get((event.host, event.pid), [])
            origins = [e for e in origins if e.process_guid == identity.process_guid]
            if len(origins) != 1 or (event.image and origins[0].image and event.image.lower() != origins[0].image.lower()):
                identity = None
            elif any((t.tzinfo is None) == (event.timestamp.tzinfo is None) and t <= event.timestamp
                     for t in terminations.get((event.host, identity.process_guid), [])):
                identity = None
        identities[event.event_id] = {
            "entity_id": identity.id if identity else None,
            "method": identity.resolution_method if identity else "unresolved_or_ambiguous",
        }
        if not event.host or event.timestamp is None:
            continue
        kind = {EventKind.PROCESS_CREATE: EdgeKind.PARENT_CHILD,
                EventKind.NETWORK_CONNECT: EdgeKind.NETWORK_CONNECTION,
                EventKind.FILE_CREATE: EdgeKind.FILE_ACTIVITY}.get(event.kind)
        if kind is None:
            continue
        candidates = []
        guid = event.parent_process_guid if kind == EdgeKind.PARENT_CHILD else event.process_guid
        for origin in by_guid.get((event.host, guid), []) if guid else []:
            if origin.event_id == event.event_id or origin.host != event.host:
                continue
            if (origin.timestamp.tzinfo is None) != (event.timestamp.tzinfo is None):
                continue
            delta = (event.timestamp - origin.timestamp).total_seconds()
            if not 0 <= delta <= window_seconds:
                continue
            if guid and origin.process_guid == guid:
                if any((t.tzinfo is None) == (event.timestamp.tzinfo is None) and origin.timestamp <= t <= event.timestamp
                       for t in terminations.get((origin.host, origin.process_guid), [])):
                    continue
                candidates.append(origin)
        if len(candidates) != 1:
            continue
        origin = candidates[0]
        edges.append(Edge(
            make_deterministic_id(kind.value, origin.event_id, event.event_id),
            kind, origin.event_id, event.event_id, event.host, 1.0,
            {"identity": "host_process_guid", "window_seconds": window_seconds,
             "relationship_type": "reported_parent_of" if kind == EdgeKind.PARENT_CHILD else kind.value},
        ))
    return edges, identities
