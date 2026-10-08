"""Replaceable local source boundary. No OS collector or recursive discovery."""
import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from sentinel_evidence.pipeline import MAX_BYTES


@dataclass(frozen=True)
class EvidenceSnapshot:
    name: str
    contents: bytes
    metadata: dict


@dataclass
class SourceBatch:
    snapshots: list[EvidenceSnapshot] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    discovered: int = 0
    ignored: int = 0


class EventSource(Protocol):
    """A real collector can supply immutable export snapshots through this interface."""
    key: str
    label: str

    def poll(self) -> SourceBatch: ...


class WorkspaceSource:
    def __init__(self, workspace):
        if os.name != "posix":
            raise ValueError("The workspace adapter requires macOS/Linux safe directory-relative file access")
        self.path = Path(workspace).expanduser().resolve(strict=True)
        info = self.path.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Configured evidence workspace is not a directory")
        self.identity = (info.st_dev, info.st_ino)
        self.key = hashlib.sha256(f"{self.path}:{self.identity}".encode()).hexdigest()
        self.label = self.path.name

    def poll(self):
        batch = SourceBatch()
        # Pin the authorized directory and open only direct children relative to it.
        root = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(root)
            if (info.st_dev, info.st_ino) != self.identity:
                raise ValueError("Evidence workspace was replaced; restart authorization in a new case")
            with os.scandir(root) as entries:
                names = []
                for index, entry in enumerate(entries):
                    if index >= 1000:
                        raise ValueError("Workspace exceeds 1000 direct entries")
                    if entry.name.lower().endswith(".jsonl"):
                        names.append(entry.name)
                    else:
                        batch.ignored += 1
            if len(names) > 100:
                raise ValueError("Workspace exceeds 100 JSONL files")
            total_bytes = 0
            for name in sorted(names):
                if total_bytes > MAX_BYTES:
                    raise ValueError("Workspace snapshots exceed 10 MiB")
                batch.discovered += 1
                try:
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
                    try:
                        before = os.fstat(descriptor)
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise ValueError("Only ordinary files without hard links are supported")
                        if before.st_size > MAX_BYTES:
                            raise ValueError("File exceeds 10 MiB")
                        chunks = []
                        size = 0
                        while size <= MAX_BYTES:
                            block = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
                            if not block:
                                break
                            chunks.append(block)
                            size += len(block)
                        after = os.fstat(descriptor)
                        current = os.stat(name, dir_fd=root, follow_symlinks=False)
                        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, current.st_ino):
                            raise ValueError("File is changing; waiting for a stable snapshot")
                        if size > MAX_BYTES:
                            raise ValueError("File exceeds 10 MiB")
                        total_bytes += size
                        if total_bytes > MAX_BYTES:
                            raise ValueError("Workspace snapshots exceed 10 MiB")
                        batch.snapshots.append(EvidenceSnapshot(name, b"".join(chunks), {
                            "collector": "authorized-workspace-jsonl-v1",
                            "workspace_key": self.key, "file_owner_uid": before.st_uid,
                        }))
                    finally:
                        os.close(descriptor)
                except (OSError, ValueError) as error:
                    batch.errors[name] = str(error) if isinstance(error, ValueError) else "Cannot safely read this file"
            if total_bytes > MAX_BYTES:
                raise ValueError("Workspace snapshots exceed 10 MiB")
            return batch
        finally:
            os.close(root)
