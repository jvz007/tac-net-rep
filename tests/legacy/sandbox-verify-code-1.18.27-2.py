#!/usr/bin/env python3
"""1.18.27-2 regression: the installer's core.sandbox self-check (VERIFY_SANDBOX_CODE in install.sh) passes with the shipped kill switch.

Round 2 of the 1.18.27 review: the check expected not_owner, but with SANDBOX_ENABLED False start() raises sandbox_disabled first, so a fresh install
would have failed the verify step. Django-free. The body of VERIFY_SANDBOX_CODE is run as the installer runs it, against the REAL tec_tac.sandbox
module; only tec_tac.capabilities (Django-bound) is replaced by a stand-in that hands out the module's real provider.
"""
from __future__ import annotations

import importlib
import re
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


install = (ROOT / "install.sh").read_text(encoding="utf-8")
m = re.search(r'^VERIFY_SANDBOX_CODE="(.*)"$', install, re.MULTILINE)
must(m, "VERIFY_SANDBOX_CODE found")
code = m.group(1)  # bash keeps a backslash-n inside double quotes as it is, so Python sees the same text the installer passes

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules["tec_tac"] = pkg
sandbox = importlib.import_module("tec_tac.sandbox")
must(sandbox.SANDBOX_ENABLED is False, "the shipped constant is False")
caps = types.ModuleType("tec_tac.capabilities")
caps.capability_status = lambda *a, **k: {"available": True}
caps.get_capability = lambda *a, **k: sandbox._PROVIDER
sys.modules["tec_tac.capabilities"] = caps

import io
from contextlib import redirect_stdout

out = io.StringIO()
with redirect_stdout(out):
    exec(compile(code, "VERIFY_SANDBOX_CODE", "exec"), {})  # noqa: S102 - the installer's own check text, run as the installer runs it
must("TEC-TAC core.sandbox verification OK" in out.getvalue(), out.getvalue())

# the check follows the constant: the old fixed 'not_owner' expectation would fail with the switch off
must("SANDBOX_ENABLED" in code and "sandbox_disabled" in code and "not_owner" in code, "the check is tied to the constant")
old = code.replace("('not_owner' if SANDBOX_ENABLED else 'sandbox_disabled')", "'not_owner'")
must(old != code, "replaced")
try:
    with redirect_stdout(io.StringIO()):
        exec(compile(old, "old", "exec"), {})  # noqa: S102 - the installer's own check text with the old expectation
except AssertionError:
    pass
else:
    raise AssertionError("the 1.18.27-1 expectation must fail with the switch off")
print("[TEST] PASS sandbox verify code 1.18.27-2")
