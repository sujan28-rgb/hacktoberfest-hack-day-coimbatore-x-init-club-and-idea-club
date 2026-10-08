import uuid
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sentinel_evidence.contracts import Event, Edge
from sentinel_evidence.normalize.identity import IdentityResolver, _parse_ts

class Correlator:
    def __init__(self, time_window: timedelta):
        self.time_window = time_window
        
    def correlate_parent_child(self, events: List[Event], resolver: IdentityResolver) -> List[Edge]:
        edges = []
        entity_origin: Dict[str, str] = {}

        for event in events:
            child_id = resolver.resolve_identity(event)
            if child_id and child_id.id not in entity_origin:
                entity_origin[child_id.id] = event.event_id

            parent_id = resolver.resolve_parent_identity(event)
            if parent_id and parent_id.id not in entity_origin:
                entity_origin[parent_id.id] = event.event_id

            if child_id and parent_id:
                support = {event.event_id}
                parent_origin = entity_origin.get(parent_id.id)
                if parent_origin:
                    support.add(parent_origin)
                
                edge = Edge(
                    edge_id=str(uuid.uuid4()),
                    source_entity=parent_id.id,
                    target_entity=child_id.id,
                    relationship_type="reported_parent_of",
                    supporting_events=sorted(support),
                    identity_assumptions={
                        "parent_resolution_method": parent_id.resolution_method,
                        "child_resolution_method": child_id.resolution_method
                    },
                    temporal_constraints={
                        "pid_reuse_window_seconds": resolver.pid_reuse_window.total_seconds()
                    }
                )
                edges.append(edge)
        return edges

    def correlate_near_in_time(self, events: List[Event], resolver: IdentityResolver) -> List[Edge]:
        edges = []
        
        host_events: Dict[str, List[Event]] = {}
        for event in events:
            host_events.setdefault(event.host, []).append(event)
            
        for host, h_events in host_events.items():
            h_events.sort(key=lambda e: _parse_ts(e.normalized_timestamp))
            
            for i, current_event in enumerate(h_events):
                current_identity = resolver.resolve_identity(current_event)
                if not current_identity:
                    continue
                    
                current_ts = _parse_ts(current_event.normalized_timestamp)
                for j in range(i + 1, len(h_events)):
                    target_event = h_events[j]
                    target_ts = _parse_ts(target_event.normalized_timestamp)
                    
                    if target_ts - current_ts > self.time_window:
                        break 
                        
                    target_identity = resolver.resolve_identity(target_event)
                    if not target_identity or current_identity.id == target_identity.id:
                        continue
                        
                    edge = Edge(
                        edge_id=str(uuid.uuid4()),
                        source_entity=current_identity.id,
                        target_entity=target_identity.id,
                        relationship_type="near_in_time",
                        supporting_events=[current_event.event_id, target_event.event_id],
                        identity_assumptions={
                            "source_resolution_method": current_identity.resolution_method,
                            "target_resolution_method": target_identity.resolution_method
                        },
                        temporal_constraints={
                            "time_window_seconds": self.time_window.total_seconds(),
                            "time_delta_seconds": (target_ts - current_ts).total_seconds()
                        }
                    )
                    edges.append(edge)
                    
        return edges
