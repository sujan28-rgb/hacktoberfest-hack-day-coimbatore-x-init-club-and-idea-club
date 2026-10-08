"""Process identity extraction (ProcessGuid, ParentProcessGuid, PID, Host)."""

from typing import Dict, Any, Tuple, Optional, List
import hashlib
from datetime import datetime, timedelta
from sentinel_evidence.contracts import Event, EventKind

def extract_identity_fields(raw_fields: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int], str]:
    """
    Extracts raw identity fields from a telemetry record:
    Returns (process_guid, parent_process_guid, pid, host).
    Does NOT implement entity resolution or correlation logic.
    """
    process_guid = raw_fields.get("ProcessGuid") or raw_fields.get("process_guid")
    parent_process_guid = raw_fields.get("ParentProcessGuid") or raw_fields.get("parent_process_guid")

    pid_raw = raw_fields.get("ProcessId") or raw_fields.get("process_id") or raw_fields.get("PID")
    pid: Optional[int] = None
    if pid_raw is not None:
        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            pid = None

    host = raw_fields.get("Computer") or raw_fields.get("host") or raw_fields.get("DeclaredHost") or ""

    return process_guid, parent_process_guid, pid, str(host)

class ProcessIdentity:
    """Resolved identity for a single process on a single host."""

    def __init__(
        self,
        host: str,
        process_guid: Optional[str],
        pid: Optional[int],
        create_time: Optional[datetime],
    ):
        self.host = host
        self.process_guid = process_guid
        self.pid = pid
        self.create_time = create_time
        self.id = self._generate_id()
        self.resolution_method: str = self._resolution_method()

    def _generate_id(self) -> str:
        if self.process_guid:
            return f"{self.host}_{self.process_guid}"
        elif self.pid is not None and self.create_time:
            return f"{self.host}_pid_{self.pid}_{self.create_time.isoformat()}"
        else:
            return "ambiguous_" + hashlib.sha256(f"{self.host}:{self.pid}".encode()).hexdigest()[:16]

    def _resolution_method(self) -> str:
        if self.process_guid:
            return "guid"
        elif self.pid is not None and self.create_time:
            return "bounded_pid_fallback"
        else:
            return "ambiguous"

def _parse_ts(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min

class IdentityResolver:
    """Resolves process identity from normalized events."""

    def __init__(self, pid_reuse_window: timedelta):
        self.pid_reuse_window = pid_reuse_window
        self._pid_map: Dict[str, Dict[int, List[Tuple[datetime, ProcessIdentity]]]] = {}
        self._guid_map: Dict[str, Dict[str, ProcessIdentity]] = {}

    def resolve_identity(self, event: Event) -> Optional[ProcessIdentity]:
        host = event.host
        process_guid = event.process_guid
        pid = event.pid

        if not host or event.timestamp is None:
            return None
        if not process_guid and pid is None:
            return None

        if process_guid:
            if host not in self._guid_map:
                self._guid_map[host] = {}
            if process_guid in self._guid_map[host]:
                return self._guid_map[host][process_guid]

            ts = event.timestamp
            identity = ProcessIdentity(host=host, process_guid=process_guid, pid=pid, create_time=ts)
            self._guid_map[host][process_guid] = identity
            if pid is not None and event.kind == EventKind.PROCESS_CREATE:
                self._register_pid(host, pid, ts, identity)
            return identity

        if pid is not None:
            ts = event.timestamp
            return self._resolve_by_pid(host, pid, ts)

        return None

    def resolve_parent_identity(self, event: Event) -> Optional[ProcessIdentity]:
        host = event.host
        parent_guid = event.parent_process_guid
        parent_pid_raw = event.raw_fields.get("ParentProcessId")
        try:
            parent_pid = int(parent_pid_raw) if parent_pid_raw is not None else None
        except (ValueError, TypeError):
            parent_pid = None

        if parent_guid:
            if host in self._guid_map and parent_guid in self._guid_map[host]:
                return self._guid_map[host][parent_guid]
            ts = event.timestamp
            identity = ProcessIdentity(host=host, process_guid=parent_guid, pid=parent_pid, create_time=ts)
            if host not in self._guid_map:
                self._guid_map[host] = {}
            self._guid_map[host][parent_guid] = identity
            if parent_pid is not None:
                self._register_pid(host, parent_pid, ts, identity)
            return identity

        if parent_pid is not None:
            ts = event.timestamp
            return self._resolve_by_pid(host, parent_pid, ts)

        return None

    def _register_pid(self, host: str, pid: int, time: datetime, identity: ProcessIdentity):
        if host not in self._pid_map:
            self._pid_map[host] = {}
        if pid not in self._pid_map[host]:
            self._pid_map[host][pid] = []
        self._pid_map[host][pid].append((time, identity))
        self._pid_map[host][pid].sort(key=lambda x: x[0].isoformat() if x[0] else "")

    def _resolve_by_pid(self, host: str, pid: int, time: datetime) -> Optional[ProcessIdentity]:
        if host not in self._pid_map or pid not in self._pid_map[host]:
            return None

        if time is None:
            return None
        candidates = self._pid_map[host][pid]

        valid = [
            (ct, ident)
            for ct, ident in candidates
            if ct is not None and (ct.tzinfo is None) == (time.tzinfo is None)
            and ct <= time and (time - ct) <= self.pid_reuse_window
        ]

        if len(valid) == 0:
            return None

        if len(valid) > 1:
            return None

        return valid[0][1]
