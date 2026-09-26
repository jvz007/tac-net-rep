#!/usr/bin/python3
"""Regression: privileged job JSON publication must not follow Tactical symlinks."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPERS = {
    "system-update": ROOT / "scripts/system-update-helper.py",
    "server-backup": ROOT / "scripts/server-backup-helper.py",
    "module-v1": ROOT / "scripts/module-job-helper.py",
    "module-v2": ROOT / "scripts/module-v2-job-helper.py",
    "server-maintenance": ROOT / "scripts/server-maintenance-helper.py",
}


def load_module(label: str, path: Path):
    name = "tectac_h1_" + label.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"unable to load {label}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def exercise_atomic_writer(label: str, module) -> None:
    if not hasattr(module, "atomic_json"):
        raise AssertionError(f"{label}: atomic_json missing")
    with tempfile.TemporaryDirectory(prefix="tectac-h1-") as td:
        root = Path(td)
        victim_tmp = root / "victim-tmp"
        victim_target = root / "victim-target"
        victim_tmp.write_text("TMP-CANARY\n", encoding="utf-8")
        victim_target.write_text("TARGET-CANARY\n", encoding="utf-8")

        target = root / "00000000-0000-0000-0000-000000000001.json"
        legacy_tmp = target.with_name(target.name + ".tmp")
        legacy_tmp.symlink_to(victim_tmp)
        target.symlink_to(victim_target)

        kwargs = {}
        # All hardened writers accept mode; older call shapes remain compatible.
        try:
            module.atomic_json(target, {"id": "safe", "status": "dispatched"}, mode=0o640, **kwargs)
        except TypeError:
            module.atomic_json(target, {"id": "safe", "status": "dispatched"})

        if victim_tmp.read_text(encoding="utf-8") != "TMP-CANARY\n":
            raise AssertionError(f"{label}: fixed .tmp symlink canary was modified")
        if victim_target.read_text(encoding="utf-8") != "TARGET-CANARY\n":
            raise AssertionError(f"{label}: target symlink canary was modified")
        if target.is_symlink():
            raise AssertionError(f"{label}: published job remained a symlink")
        payload = json.loads(target.read_text(encoding="utf-8"))
        if payload.get("id") != "safe":
            raise AssertionError(f"{label}: published JSON mismatch")


def check_nofollow(label: str, path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "O_NOFOLLOW" not in text:
        raise AssertionError(f"{label}: privileged reads are missing O_NOFOLLOW")


def main() -> None:
    for label, path in HELPERS.items():
        module = load_module(label, path)
        exercise_atomic_writer(label, module)
        check_nofollow(label, path)

    system_text = HELPERS["system-update"].read_text(encoding="utf-8")
    if "shutil.copy2(path, HISTORY_ROOT / path.name)" in system_text:
        raise AssertionError("system-update: history still copies a mutable path")
    if "atomic_json(HISTORY_ROOT / path.name, job" not in system_text:
        raise AssertionError("system-update: history is not written from in-memory JSON")

    for label in ("system-update", "server-backup", "module-v1", "module-v2"):
        text = HELPERS[label].read_text(encoding="utf-8")
        if ".with_name(path.name + \".tmp\")" in text:
            raise AssertionError(f"{label}: fixed .tmp publication remains")

    print("PASS: privileged job-file symlink boundary")


if __name__ == "__main__":
    main()
