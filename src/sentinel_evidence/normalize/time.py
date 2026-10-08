"""Timestamp parsing without fabricating timezone information."""

from datetime import datetime
from typing import Tuple, Optional


def parse_timestamp_text(ts_text: Optional[str]) -> Tuple[Optional[str], str]:
    """
    Parses original timestamp string safely.
    Never invents timezone info if absent.
    Returns (normalized_iso_string, timestamp_status).
    """
    if not ts_text:
        return None, "missing"

    ts_text_str = str(ts_text).strip()
    if not ts_text_str:
        return None, "missing"

    # Common Windows ISO / Sysmon formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_text_str, fmt)
            return dt.isoformat(), "parsed"
        except ValueError:
            continue

    return ts_text_str, "raw_unparsed"
