#!/usr/bin/env python3
"""1.18.28 regression (from 1.18.27-2): the installer's core.sandbox self-check (VERIFY_SANDBOX_CODE in install.sh) passes with the shipped kill switch (True) and with it forced to False.

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
must(sandbox.SANDBOX_ENABLED is True, "the shipped constant is True (1.18.28)")
sandbox.SANDBOX_ENABLED = True  # the on path is proven with the constant set True
caps = types.ModuleType("tec_tac.capabilities")
caps.capability_status = lambda *a, **k: {"available": True}
caps.get_capability = lambda *a, **k: sandbox._PROVIDER
sys.modules["tec_tac.capabilities"] = caps

import io
from contextlib import redirect_stdout

out = io.StringIO()
with redirect_stdout(out):
    exec(compile(code, "VERIFY_SANDBOX_CODE", "exec"), {})  # noqa: S102 - the installer's own check text, run as the installer runs it
must("TEC-TAC core.sandbox verification OK" in out.getvalue() and "enabled=True" in out.getvalue(), out.getvalue())
must("ready=False" in out.getvalue(), "a server that is not ready (no selftest result here) still passes: start() with no caller is not_owner before any readiness refusal")

# the check follows the constant: the old fixed 'not_owner' expectation would fail with the switch off
must("SANDBOX_ENABLED" in code and "sandbox_disabled" in code and "not_owner" in code, "the check is tied to the constant")
old = code.replace("('not_owner' if SANDBOX_ENABLED else 'sandbox_disabled')", "'not_owner'")
must(old != code, "replaced")
# the old fixed 'not_owner' expectation is right for the shipped True value and would fail only with the switch forced off
with redirect_stdout(io.StringIO()):
    exec(compile(old, "old", "exec"), {})  # noqa: S102 - the installer's own check text with the fixed expectation, shipped value
sandbox.SANDBOX_ENABLED = False
try:
    with redirect_stdout(io.StringIO()):
        exec(compile(old, "old", "exec"), {})  # noqa: S102 - the same text with the constant forced off
except AssertionError:
    pass
else:
    raise AssertionError("the fixed not_owner expectation must fail with the switch forced off")
finally:
    sandbox.SANDBOX_ENABLED = True
# the real value is True: the check expects not_owner and starts no run (the Core caller is refused before the helper)
must("('not_owner' if SANDBOX_ENABLED else 'sandbox_disabled')" in code, "the check follows the constant")
# with the constant forced False the same text expects sandbox_disabled
sandbox.SANDBOX_ENABLED = False
try:
    out = io.StringIO()
    with redirect_stdout(out):
        exec(compile(code, "VERIFY_SANDBOX_CODE_OFF", "exec"), {})  # noqa: S102 - the installer's own check text with the constant forced off
    must("verification OK" in out.getvalue() and "enabled=False" in out.getvalue(), out.getvalue())
finally:
    sandbox.SANDBOX_ENABLED = True
print("[TEST] PASS sandbox verify code 1.18.28")
