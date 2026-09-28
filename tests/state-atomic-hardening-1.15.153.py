#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK = ROOT / "framwork"
sys.path.insert(0, str(FRAMEWORK))

from tec_tac import module_state


def load_privileged_trust():
    spec = importlib.util.spec_from_file_location("privileged_trust_115153", ROOT / "scripts" / "privileged-trust.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_module_state_uses_unique_atomic_writer():
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        state_file = root / "module-state.json"
        lock_file = root / "module-state.lock"
        lock_file.write_text("", encoding="utf-8")
        old = (module_state.STATE_ROOT, module_state.STATE_FILE, module_state.STATE_LOCK)
        module_state.STATE_ROOT, module_state.STATE_FILE, module_state.STATE_LOCK = root, state_file, lock_file
        planted = root / "module-state.json.tmp.1234"
        victim = root / "victim"
        victim.write_text("safe", encoding="utf-8")
        planted.symlink_to(victim)
        try:
            module_state.save_state({"schema": 1, "modules": {"one": {"enabled": True}}})
            assert victim.read_text(encoding="utf-8") == "safe"
            assert json.loads(state_file.read_text(encoding="utf-8"))["modules"]["one"]["enabled"] is True
        finally:
            module_state.STATE_ROOT, module_state.STATE_FILE, module_state.STATE_LOCK = old


def test_privileged_policy_atomic_writer_ignores_predictable_tmp_and_concurrent_writes():
    mod = load_privileged_trust()
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        policy = root / "update-trust-policy.json"
        victim = root / "victim"
        victim.write_text("safe", encoding="utf-8")
        (root / "update-trust-policy.json.tmp").symlink_to(victim)
        old_root, old_file = mod.POLICY_ROOT, mod.POLICY_FILE
        old_fchown = mod.os.fchown
        mod.POLICY_ROOT, mod.POLICY_FILE = root, policy
        mod.os.fchown = lambda fd, uid, gid: None
        try:
            failures = []
            def writer(i):
                try:
                    mod.write_policy("signed_production" if i % 2 else "secure_signed", updated_by=f"worker-{i}")
                except Exception as exc:
                    failures.append(exc)
            threads = [threading.Thread(target=writer, args=(i,)) for i in range(12)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            assert not failures, failures
            payload = json.loads(policy.read_text(encoding="utf-8"))
            assert payload["minimum_level"] in {"signed_production", "secure_signed"}
            assert victim.read_text(encoding="utf-8") == "safe"
            assert list(root.glob(".update-trust-policy.json.*.tmp")) == []
        finally:
            mod.POLICY_ROOT, mod.POLICY_FILE = old_root, old_file
            mod.os.fchown = old_fchown


if __name__ == "__main__":
    test_module_state_uses_unique_atomic_writer()
    test_privileged_policy_atomic_writer_ignores_predictable_tmp_and_concurrent_writes()
    print("state atomic hardening 1.15.153: PASS")
