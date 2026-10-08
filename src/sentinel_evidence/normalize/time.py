"""Timestamp parsing without fabricating timezone information."""

from datetime import datetime, timezone
from typing import Tuple, Optional


def parse_timestamp_text(ts_text: Optional[str]) -> Tuple[Optional[datetime], str]:
    """
    Parses original timestamp string safely.
    Never invents timezone info if absent.
    Returns (datetime_obj, timestamp_status).
    """
    if not ts_text:
        return None, "missing"

    ts_text_str = str(ts_text).strip()
    if not ts_text_str:
        return None, "missing"

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
            if fmt.endswith("Z"):
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, "parsed"
        except ValueError:
            continue

    return None, "raw_unparsed"
