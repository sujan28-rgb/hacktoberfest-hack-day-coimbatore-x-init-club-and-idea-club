"""Source manifest and SHA-256 hashing."""

import hashlib
from pathlib import Path
from typing import Tuple, Optional
from sentinel_evidence.contracts import Source
from sentinel_evidence.intake.limits import IntakeLimits


def compute_file_hash(file_path: Path) -> Tuple[str, int]:
    """Compute SHA-256 hash and byte size of a file in a streaming fashion."""
    hasher = hashlib.sha256()
    byte_count = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            byte_count += len(chunk)

    return hasher.hexdigest(), byte_count


def create_source_manifest(file_path: Path, declared_host: Optional[str] = None) -> Source:
    """Validate file path and construct Source manifest with deterministic ID."""
    validated_path = IntakeLimits.validate_path(file_path)
    content_hash, byte_size = compute_file_hash(validated_path)

    return Source(
        file_hash=content_hash,
        file_path=str(validated_path),
        line_number=0,
        raw_hash=content_hash
    )
