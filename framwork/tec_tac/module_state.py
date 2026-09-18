"""Persistent Tec-Tac module state and dependency/version helpers.

State is intentionally stored outside the Tactical source tree so upgrades do not
silently re-enable modules. Installed modules default to enabled when no explicit
state exists, preserving 1.3.x behaviour during upgrade.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
STATE_FILE = STATE_ROOT / "module-state.json"
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
    # Stable versions sort after suffixed prerelease/build-like values.
    if left.suffix == right.suffix:
        return 0
    if not left.suffix:
        return 1
    if not right.suffix:
        return -1
    return -1 if left.suffix < right.suffix else 1


def version_satisfies(version: str, constraint: str | None) -> bool:
    """Return whether *version* satisfies a comma-separated constraint range.

    Supported operators: ==, !=, >, >=, <, <=. A bare version means ==.
    Empty or '*' means unconstrained.
    """
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
        ok = {
            "==": cmp == 0,
            "!=": cmp != 0,
            ">": cmp > 0,
            ">=": cmp >= 0,
            "<": cmp < 0,
            "<=": cmp <= 0,
        }[operator]
        if not ok:
            return False
    return True


def _default_state() -> dict:
    return {"schema": 1, "modules": {}}


def load_state() -> dict:
    if not STATE_FILE.is_file():
        return _default_state()
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleStateError(f"Module state is unreadable: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("modules", {}), dict):
        raise ModuleStateError("Module state has an invalid structure.")
    payload.setdefault("schema", 1)
    payload.setdefault("modules", {})
    return payload


def save_state(payload: dict) -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE_FILE)


def module_record(module_id: str, state: dict | None = None) -> dict:
    state = state or load_state()
    value = state.get("modules", {}).get(module_id)
    return dict(value) if isinstance(value, dict) else {}


def is_enabled(module_id: str, state: dict | None = None) -> bool:
    record = module_record(module_id, state)
    return bool(record.get("enabled", True))


def is_visible(module_id: str, state: dict | None = None, default: bool = True) -> bool:
    """Return whether an installed module should appear in Tec-Tac navigation.

    Visibility is independent from runtime enablement. Missing state defaults to
    visible so existing installations preserve their current navigation after
    upgrading the framework.
    """
    record = module_record(module_id, state)
    return bool(record["visible"]) if "visible" in record else bool(default)


def set_enabled(module_id: str, enabled: bool) -> dict:
    state = load_state()
    record = dict(state["modules"].get(module_id) or {})
    record["enabled"] = bool(enabled)
    state["modules"][module_id] = record
    save_state(state)
    return record


def set_visible(module_id: str, visible: bool) -> dict:
    state = load_state()
    record = dict(state["modules"].get(module_id) or {})
    record["visible"] = bool(visible)
    state["modules"][module_id] = record
    save_state(state)
    return record


def remember_version(module_id: str, version: str) -> dict:
    state = load_state()
    record = dict(state["modules"].get(module_id) or {})
    record.setdefault("enabled", True)
    record["version"] = str(version)
    state["modules"][module_id] = record
    save_state(state)
    return record


def forget_module(module_id: str) -> None:
    state = load_state()
    if module_id in state["modules"]:
        del state["modules"][module_id]
        save_state(state)


def filter_enabled_plugins(plugins: Iterable) -> tuple:
    state = load_state()
    return tuple(
        plugin for plugin in plugins
        if getattr(plugin, "legacy", False) or is_enabled(getattr(plugin, "plugin_id", ""), state)
    )
