#!/usr/bin/env python3
"""D6a regression: invalid UTF-8 becomes startup-safe Core domain errors."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_ROOT = ROOT / "framwork" / "tec_tac"

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG_ROOT)]
sys.modules["tec_tac"] = pkg


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PKG_ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

registry = load("tec_tac.registry", "registry.py")
module_state = load("tec_tac.module_state", "module_state.py")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)

    plugin = root / "bad-plugin"
    plugin.mkdir()
    (plugin / registry.MANIFEST_NAME).write_bytes(b'{"id":"bad-plugin","version":"1.0","x":"\xff"}')
    try:
        registry._load_manifest("extension", plugin)
    except registry.RegistryError as exc:
        assert "Unable to read" in str(exc)
    else:
        raise AssertionError("invalid UTF-8 manifest escaped RegistryError")

    state_file = root / "module-state.json"
    state_file.write_bytes(b'{"schema":1,"modules":{"bad":"\xff"}}')
    module_state.STATE_ROOT = root
    module_state.STATE_FILE = state_file
    module_state.STATE_LOCK = root / "missing.lock"
    try:
        module_state.load_state()
    except module_state.ModuleStateError as exc:
        assert "valid UTF-8" in str(exc)
    else:
        raise AssertionError("invalid UTF-8 module state escaped ModuleStateError")

print("d6a-invalid-utf8: PASS")
