"""Streaming JSONL adapter for ingesting evidence logs."""

import json
from pathlib import Path
from typing import Generator, Tuple, Dict, Any
from sentinel_evidence.intake.limits import IntakeLimits, IntakeLimitError


def parse_jsonl_stream(file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    """
    Stream line-by-line JSONL evidence records.
    Yields (source_locator, raw_fields_dict).
    Handles malformed JSON safely and enforces line length limits.
    """
    line_number = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_number += 1
            if line_number > IntakeLimits.MAX_EVENT_COUNT:
                raise IntakeLimitError(f"Exceeded max event limit of {IntakeLimits.MAX_EVENT_COUNT}")

            if len(line.encode("utf-8")) > IntakeLimits.MAX_LINE_LENGTH_BYTES:
                raw_data = {"_parse_error": "Line length exceeds limit", "_raw_line_snippet": line[:100]}
                yield f"line:{line_number}", raw_data
                continue

            cleaned_line = line.strip()
            if not cleaned_line:
                continue

            try:
                data = json.loads(cleaned_line)
                if not isinstance(data, dict):
                    data = {"_raw_value": data, "_parse_error": "Top-level JSON is not an object"}
                yield f"line:{line_number}", data
            except json.JSONDecodeError as err:
                yield f"line:{line_number}", {
                    "_parse_error": f"Invalid JSON: {str(err)}",
                    "_raw_line": cleaned_line[:500]
                }
