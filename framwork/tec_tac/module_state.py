"""Persistent Tec-Tac module state and dependency/version helpers.

State is intentionally stored outside the Tactical source tree so upgrades do not
silently re-enable modules. Installed modules default to enabled when no explicit
state exists, preserving 1.3.x behaviour during upgrade. Corrupt state fails
closed for reads and can never be overwritten by a normal read/modify/write.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
STATE_FILE = STATE_ROOT / "module-state.json"
STATE_LOCK = STATE_ROOT / "module-state.lock"
logger = logging.getLogger("tec_tac.module_state")
_VERSION_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+.]([0-9A-Za-z.-]+))?\s*$")
_CONSTRAINT_RE = re.compile(r"^\s*(==|!=|>=|<=|>|<)?\s*([^\s,]+)\s*$")


class ModuleStateError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int
    suffix: str = ""

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = _VERSION_RE.match(str(value or ""))
        if not match:
            raise ModuleStateError(f"Invalid semantic version: {value!r}")
        major, minor, patch, suffix = match.groups()
        return cls(int(major), int(minor or 0), int(patch or 0), suffix or "")

    def core(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch


def _compare(left: Version, right: Version) -> int:
    if left.core() < right.core():
        return -1
    if left.core() > right.core():
        return 1
    if left.suffix == right.suffix:
        return 0
    if not left.suffix:
        return 1
    if not right.suffix:
        return -1
    return -1 if left.suffix < right.suffix else 1


def version_satisfies(version: str, constraint: str | None) -> bool:
    raw = str(constraint or "").strip()
    if not raw or raw == "*":
        return True
    current = Version.parse(version)
    for part in raw.split(","):
        match = _CONSTRAINT_RE.match(part)
        if not match:
            raise ModuleStateError(f"Invalid version constraint: {constraint!r}")
        operator, expected_raw = match.groups()
        operator = operator or "=="
        expected = Version.parse(expected_raw)
        cmp = _compare(current, expected)
        ok = {"==": cmp == 0, "!=": cmp != 0, ">": cmp > 0, ">=": cmp >= 0, "<": cmp < 0, "<=": cmp <= 0}[operator]
        if not ok:
            return False
    return True


def _default_state() -> dict:
    return {"schema": 1, "modules": {}}


def _corrupt_state(exc: Exception | str) -> dict:
    return {"schema": 1, "modules": {}, "_corrupt": True, "_error": str(exc)}


@contextmanager
def _state_lock(exclusive: bool):
    # The installer/recovery toolkit owns creation and permissions for this
    # cross-privilege lock. Django must never chmod or create a root-owned lock.
    # Shared readers only need O_RDONLY; privileged writers open read/write.
    mode = "r+" if exclusive else "r"
    try:
        handle = STATE_LOCK.open(mode)
    except FileNotFoundError as exc:
        if exclusive:
            raise ModuleStateError(
                f"Module state lock is unavailable at {STATE_LOCK}; run the Tec-Tac permission repair: {exc}"
            ) from exc
        # Bootstrap compatibility: upgrades from releases that predate the
        # shared lock can import Django settings before the installer has had a
        # chance to create it. Shared reads may proceed unlocked in this narrow
        # case; corrupt state still fails closed in _load_state_unlocked().
        logger.warning("Module state lock is missing at %s; reading state without a shared lock", STATE_LOCK)
        yield
        return
    except PermissionError:
        if not exclusive:
            # Root owns the mutation lock. Readers are safe without flock because
            # state is replaced atomically and a partial JSON file is never exposed.
            yield
            return
        raise
    except OSError as exc:
        raise ModuleStateError(
            f"Module state lock is unavailable at {STATE_LOCK}; run the Tec-Tac permission repair: {exc}"
        ) from exc
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _load_state_unlocked(*, mutation: bool = False) -> dict:
    if not STATE_FILE.is_file():
        return _default_state()
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if mutation:
            raise ModuleStateError(f"Module state is unreadable; refusing to overwrite it: {exc}") from exc
        return _corrupt_state(exc)
    if not isinstance(payload, dict) or not isinstance(payload.get("modules", {}), dict):
        if mutation:
            raise ModuleStateError("Module state has an invalid structure; refusing to overwrite it.")
        return _corrupt_state("Module state has an invalid structure.")
    payload.setdefault("schema", 1)
    payload.setdefault("modules", {})
    return payload


def load_state() -> dict:
    with _state_lock(False):
        return _load_state_unlocked()


def _save_state_unlocked(payload: dict) -> None:
    if payload.get("_corrupt"):
        raise ModuleStateError("Corrupt module state cannot be saved. Repair or restore module-state.json first.")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_name(STATE_FILE.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE_FILE)


def save_state(payload: dict) -> None:
    with _state_lock(True):
        _save_state_unlocked(payload)


def module_record(module_id: str, state: dict | None = None) -> dict:
    state = state or load_state()
    value = state.get("modules", {}).get(module_id)
    return dict(value) if isinstance(value, dict) else {}


def is_enabled(module_id: str, state: dict | None = None) -> bool:
    state = state or load_state()
    if state.get("_corrupt"):
        return False
    record = module_record(module_id, state)
    return bool(record.get("enabled", True))


def is_visible(module_id: str, state: dict | None = None, default: bool = True) -> bool:
    state = state or load_state()
    if state.get("_corrupt"):
        return False
    record = module_record(module_id, state)
    return bool(record["visible"]) if "visible" in record else bool(default)


def _mutate_record(module_id: str, mutate) -> dict:
    with _state_lock(True):
        state = _load_state_unlocked(mutation=True)
        record = dict(state["modules"].get(module_id) or {})
        mutate(record)
        state["modules"][module_id] = record
        _save_state_unlocked(state)
        return record


def set_enabled(module_id: str, enabled: bool) -> dict:
    return _mutate_record(module_id, lambda record: record.__setitem__("enabled", bool(enabled)))


def set_visible(module_id: str, visible: bool) -> dict:
    return _mutate_record(module_id, lambda record: record.__setitem__("visible", bool(visible)))


def remember_version(module_id: str, version: str) -> dict:
    def apply(record):
        record.setdefault("enabled", True)
        record["version"] = str(version)
    return _mutate_record(module_id, apply)


def forget_module(module_id: str) -> None:
    with _state_lock(True):
        state = _load_state_unlocked(mutation=True)
        if module_id in state["modules"]:
            del state["modules"][module_id]
            _save_state_unlocked(state)


def filter_enabled_plugins(plugins: Iterable) -> tuple:
    state = load_state()
    return tuple(plugin for plugin in plugins if getattr(plugin, "legacy", False) or is_enabled(getattr(plugin, "plugin_id", ""), state))
