"""Small filesystem helpers shared by unprivileged Core state writers."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def _fsync_directory(path: Path) -> None:
    """Flush a directory entry update so an atomic replace survives a host crash."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: Path, payload: Any, *, mode: int = 0o660, default=None) -> None:
    """Atomically replace *path* with JSON using a unique sibling temp file.

    A unique mkstemp file avoids cross-worker collisions and prevents a
    pre-created predictable ``<name>.tmp`` symlink from being followed.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    tmp_path: Path | None = None
    try:
        fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        tmp_path = Path(raw_tmp)
        os.fchmod(fd, mode)
        data = json.dumps(payload, indent=2, sort_keys=True, default=default) + "\n"
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        _fsync_directory(path.parent)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
