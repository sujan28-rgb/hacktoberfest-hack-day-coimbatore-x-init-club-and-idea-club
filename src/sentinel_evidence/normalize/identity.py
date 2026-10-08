"""Process identity extraction (ProcessGuid, ParentProcessGuid, PID, Host)."""

from typing import Dict, Any, Tuple, Optional


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
