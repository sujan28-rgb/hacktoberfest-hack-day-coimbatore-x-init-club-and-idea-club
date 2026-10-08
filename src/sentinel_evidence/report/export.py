"""Stable JSON shared by CLI, persistence, packets, and evaluation."""
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum


def default(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    raise TypeError(type(value).__name__)


def encode(value):
    return json.dumps(value, default=default, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def plain(value):
    return json.loads(encode(value))
