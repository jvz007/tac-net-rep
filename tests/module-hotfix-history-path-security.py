#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork/tec_tac/module_hotfix.py"

# Avoid importing the whole Django stack; the production file only needs these
# sibling modules to define the functions under test.
sys.path.insert(0, str(ROOT / "framwork"))

spec = importlib.util.spec_from_file_location("tec_tac.module_hotfix_history_security", MODULE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td)
    mod.HOTFIX_APPLIED_ROOT = base / "applied"
    valid_root = mod.HOTFIX_APPLIED_ROOT / "cybercns"
    valid_root.mkdir(parents=True)
    (valid_root / "HF001.json").write_text(json.dumps({"id": "HF001", "module_id": "cybercns", "applied_at": "2026-09-26T00:00:00Z"}))

    rows = mod.list_applied_hotfixes("cybercns")
    assert [row["id"] for row in rows] == ["HF001"]

    for value in ("../outside", "../../etc", "/etc", "cybercns/../other", "cybercns/test", "cybercns\\test", ".", "..", ""):
        try:
            mod.list_applied_hotfixes(value)
        except mod.ModuleHotfixError as exc:
            assert str(exc) == "Invalid module id."
        else:
            raise AssertionError(f"invalid module id accepted: {value!r}")

    # The all-modules administrative summary remains supported when no module
    # filter is supplied.
    all_rows = mod.list_applied_hotfixes(None)
    assert [row["id"] for row in all_rows] == ["HF001"]

source = MODULE.read_text(encoding="utf-8")
needle = 'if module_id is not None and not MODULE_RE.fullmatch(module_id or ""):'
assert needle in source
print("[TEST] PASS module hotfix history path security")
