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

    # Deterministic source ID based on SHA-256 content hash
    source_id = f"SRC-{content_hash[:16]}"

    return Source(
        source_id=source_id,
        content_hash=content_hash,
        declared_host=declared_host,
        byte_size=byte_size,
        original_source_mapping={"file_name": validated_path.name, "file_path": str(validated_path)}
    )
