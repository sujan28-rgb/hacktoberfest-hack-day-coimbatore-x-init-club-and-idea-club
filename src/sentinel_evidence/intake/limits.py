"""Resource, file path, and size limits enforcement for Intake."""

from pathlib import Path


class IntakeLimitError(ValueError):
    """Raised when file or path violates intake limits."""
    pass


class IntakeLimits:
    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
    MAX_LINE_LENGTH_BYTES = 10 * 1024 * 1024  # 10 MB per line
    MAX_EVENT_COUNT = 500_000
    ALLOWED_EXTENSIONS = {".jsonl", ".json"}

    @classmethod
    def validate_path(cls, file_path: Path) -> Path:
        """Validate path to prevent traversal, symlink exploitation, and check existence."""
        resolved = file_path.resolve(strict=True)

        if not resolved.is_file():
            raise IntakeLimitError(f"Path is not a regular file: {resolved}")

        if resolved.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
            raise IntakeLimitError(f"Extension '{resolved.suffix}' not allowed. Allowed: {cls.ALLOWED_EXTENSIONS}")

        file_size = resolved.stat().st_size
        if file_size > cls.MAX_FILE_SIZE_BYTES:
            raise IntakeLimitError(f"File size {file_size} exceeds limit of {cls.MAX_FILE_SIZE_BYTES} bytes")

        return resolved
