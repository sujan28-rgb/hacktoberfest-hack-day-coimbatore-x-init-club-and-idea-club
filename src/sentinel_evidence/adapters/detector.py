"""Explicit detector baseline; findings are indicators, never proof of malice."""
import re
from sentinel_evidence.contracts import Finding, Severity, EventKind, make_deterministic_id

DETECTOR_VERSION = "encoded-powershell-v1"


def detect(events):
    findings = []
    for event in events:
        if event.kind != EventKind.PROCESS_CREATE:
            continue
        image = (event.image or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if image in {"powershell.exe", "pwsh.exe"} and re.search(
            r"(?:^|\s)-(?:enc|encodedcommand)\s+\S+", event.command_line or "", re.I
        ):
            findings.append(Finding(
                make_deterministic_id(DETECTOR_VERSION, event.event_id),
                "encoded_powershell_command", Severity.MEDIUM,
                "Process creation record contains an encoded PowerShell argument; intent is unknown.",
                (event.event_id,),
            ))
    return findings
