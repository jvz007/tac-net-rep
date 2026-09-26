#!/usr/bin/env python3
"""Monotonic installer migration for the root-owned Tec-Tac trust policy.

The historic policy lived below /var/lib/tec-tac/policy and was writable by
Tactical-era policy management. Current releases move authority to
/etc/tec-tac/policy. During upgrade we may import a *stronger* valid legacy
floor, but a legacy value can never lower the current/default floor.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

LEVELS = ("unsigned", "signed_development", "signed_production", "secure_signed")
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}


class PolicyMigrationError(RuntimeError):
    pass


def _read_policy(path: Path, *, required: bool) -> dict | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise PolicyMigrationError(f"trust policy is missing: {path}")
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PolicyMigrationError(f"trust policy must be a regular non-symlink file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PolicyMigrationError(f"trust policy must be a regular file: {path}")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
            try:
                payload = json.load(handle)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise PolicyMigrationError(f"trust policy is unreadable: {path}: {exc}") from exc
    finally:
        os.close(fd)
    if not isinstance(payload, dict) or int(payload.get("schema", 0) or 0) != 1:
        raise PolicyMigrationError(f"trust policy schema is invalid: {path}")
    level = str(payload.get("minimum_level") or "").strip().lower()
    if level not in LEVEL_RANK:
        raise PolicyMigrationError(f"trust policy level is invalid: {path}")
    result = dict(payload)
    result["minimum_level"] = level
    return result


def _write_policy(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise PolicyMigrationError(f"trust policy directory must not be a symlink: {path.parent}")
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise PolicyMigrationError("short write while persisting trust policy")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def migrate(current: Path, legacy: Path, environment: str) -> dict:
    env = str(environment or "production").strip().lower()
    if env not in {"production", "development"}:
        raise PolicyMigrationError("environment must be production or development")
    default_level = "signed_development" if env == "development" else "signed_production"

    current_payload = _read_policy(current, required=False)
    legacy_payload = _read_policy(legacy, required=False)

    candidates: list[tuple[str, dict]] = [
        ("environment-default", {
            "schema": 1,
            "minimum_level": default_level,
            "updated_at": None,
            "updated_by": "installer",
        })
    ]
    if current_payload is not None:
        candidates.append(("current", current_payload))
    if legacy_payload is not None:
        candidates.append(("legacy", legacy_payload))

    source, winner = max(candidates, key=lambda item: LEVEL_RANK[item[1]["minimum_level"]])
    out = dict(winner)
    out["schema"] = 1
    if source == "legacy":
        previous = str(winner.get("updated_by") or "")[:120]
        out["updated_by"] = "installer-legacy-policy-migration" + (f":{previous}" if previous else "")
    elif source == "environment-default" and current_payload is not None:
        # Existing unsigned/otherwise weaker policy is raised to the secure
        # environment default, preserving the prior migration behavior.
        out["updated_by"] = "installer-security-migration"

    # Avoid rewriting a current policy whose effective content already wins.
    # This preserves administrator metadata/timestamps exactly when possible.
    if current_payload is None or current_payload != out:
        _write_policy(current, out)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True)
    parser.add_argument("--legacy", required=True)
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    try:
        result = migrate(Path(args.current), Path(args.legacy), args.environment)
    except PolicyMigrationError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps({"minimum_level": result["minimum_level"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
