#!/usr/bin/env python3
"""1.18.28 regression: the canary result is tied to the Core build and to the selftest run it belongs to (AD-65, held Low of the first 1.18.28 review).

Django-free. Covered:

* ``canary_record`` and ``run_canary_command`` write ``core_version`` (the installed VERSION text) and ``selftest_at`` (read before the canary ran)
  into canary.json, and the record stays free of secrets;
* the helper (``canary_record_state``, ``ready_status``, ``show_status``) and the Django side (``tec_tac.sandbox.status``) count a canary only
  when ok is True, core_version equals the installed VERSION text and selftest_at equals status.json's selftest_at;
* a canary of another Core version, another selftest run, missing keys, values that are not text, ok False, an unreadable VERSION file and an
  unreadable canary file all give canary_ok False, and the helper and Django agree on every case;
* the root-only canary launch (``ready_status(False)``) still skips the canary check, because it is what makes the canary.

The Django side runs against the real module with its file reader replaced by a plain reader (the trust checks of that reader are proven in
sandbox-switch-on-1.18.28.py). No socket is opened.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import json
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(ROOT, must, sh) = (H.ROOT, H.must, H.sh)
APP = ROOT / "framwork" / "tec_tac"

# ------------------------------------------------------------------------------------------------ the Django side, real module
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules["tec_tac"] = pkg
sandbox = importlib.import_module("tec_tac.sandbox")


def plain_reader(path, *, max_bytes):
    try:
        data = Path(path).read_bytes()
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            raise TypeError("not an object")
        return value
    except FileNotFoundError as exc:
        raise sandbox._Unreadable("selftest_not_run") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise sandbox._Unreadable("status_unreadable") from exc


sandbox._read_json_trusted = plain_reader
sandbox._registry_rows = list
sandbox.STATUS_FILE, sandbox.CANARY_FILE, sandbox.VERSION_FILE = sh.STATUS_FILE, sh.CANARY_FILE, sh.INSTALLED_VERSION_FILE

SELFTEST_AT = "2026-11-11T10:00:00Z"
GOOD = {"ok": True, "at": "2026-11-11T10:05:00Z", "counts": {}, "failing": [], "skipped": [], "core_version": "1.18.28", "selftest_at": SELFTEST_AT}


def put(canary, version="1.18.28\n", selftest_at=SELFTEST_AT):
    H.write_ready_status(canary=False, selftest_at=selftest_at)
    sh.CANARY_FILE.unlink(missing_ok=True)
    if canary is not None:
        sh.CANARY_FILE.write_text(canary if isinstance(canary, str) else json.dumps(canary), encoding="utf-8")
    if version is None:
        sh.INSTALLED_VERSION_FILE.unlink(missing_ok=True)
    else:
        sh.INSTALLED_VERSION_FILE.write_text(version, encoding="utf-8")


def helper_state():
    with contextlib.redirect_stdout(io.StringIO()) as out:
        sh.show_status()
    shown = json.loads(out.getvalue())["status"]
    try:
        sh.ready_status()
        gate = True
    except sh.Refusal as exc:
        must(exc.code == "sandbox_not_ready" and exc.message == "the sandbox canary has not passed on this server", exc.message)
        gate = False
    must(sh.canary_passed(sh.read_status()) is gate and shown["canary_ok"] is gate, "show_status, canary_passed and ready_status agree")
    return gate


def django_state():
    answer = sandbox.status()
    must(answer["active"] is answer["canary_ok"] and answer["enabled"] is True and answer["ready"] is True, answer)
    return answer["canary_ok"]


CASES = (
    ("matching", GOOD, "1.18.28\n", True),
    ("matching, no trailing newline in VERSION", GOOD, "1.18.28", True),
    ("other Core version", {**GOOD, "core_version": "1.18.27"}, "1.18.28\n", False),
    ("installed VERSION changed", GOOD, "1.18.29\n", False),
    ("rebuild label is not stripped", {**GOOD, "core_version": "1.18.28"}, "1.18.28" + "-2\n", False),  # built from pieces: the source tree carries no rebuild label
    ("other selftest run", {**GOOD, "selftest_at": "2026-11-11T09:59:59Z"}, "1.18.28\n", False),
    ("no core_version", {k: v for k, v in GOOD.items() if k != "core_version"}, "1.18.28\n", False),
    ("no selftest_at", {k: v for k, v in GOOD.items() if k != "selftest_at"}, "1.18.28\n", False),
    ("core_version not text", {**GOOD, "core_version": 1}, "1.18.28\n", False),
    ("core_version empty", {**GOOD, "core_version": ""}, "\n", False),
    ("selftest_at not text", {**GOOD, "selftest_at": 5}, "1.18.28\n", False),
    ("ok false", {**GOOD, "ok": False}, "1.18.28\n", False),
    ("ok not True", {**GOOD, "ok": "yes"}, "1.18.28\n", False),
    ("old record without the new keys", {"ok": True, "at": "2026-11-11T10:05:00Z"}, "1.18.28\n", False),
    ("canary not an object", "[1, 2]", "1.18.28\n", False),
    ("canary unreadable", "{nope", "1.18.28\n", False),
    ("canary missing", None, "1.18.28\n", False),
    ("VERSION unreadable", GOOD, None, False),
)
for label, canary, version, expected in CASES:
    put(canary, version)
    must(helper_state() is expected, ("helper", label))
    must(django_state() is expected, ("django", label))

# a canary whose selftest_at matches but the status.json has no selftest_at: never passed
put(GOOD)
status_text = json.loads(sh.STATUS_FILE.read_text(encoding="utf-8"))
status_text.pop("selftest_at")
sh.STATUS_FILE.write_text(json.dumps(status_text), encoding="utf-8")
must(helper_state() is False and django_state() is False, "no selftest_at in status.json")

# the canary's own launch needs ready only
put(None)
must(sh.ready_status(canary_required=False)["ready"] is True, "the canary launch path skips the canary check")

# ------------------------------------------------------------------------------------------------ the selftest writes the keys
rec = sh.canary_record([], True, {"OK": 0}, "1.18.28", SELFTEST_AT)
must(rec["core_version"] == "1.18.28" and rec["selftest_at"] == SELFTEST_AT and rec["ok"] is True, rec)
text = json.dumps(rec)
must("token" not in text and "marker" not in text and "secret" not in text.lower(), "no secret in the record")
must(sh.canary_record([], True, {}) ["core_version"] is None, "the new keys exist even when not given")

table = [{"wall": "w", "attack": "a", "expected": "e", "verdict": "OK", "actual": "x"}]
sh.run_canary = lambda: table
sh.canary_summary = lambda t: (True, {"OK": 1, "ATTACK SUCCEEDED": 0, "NOT RUN": 0, "SKIPPED": 0, "WARN": 0})
put(None, "1.18.28\n", "2026-11-11T10:00:00Z")
with contextlib.redirect_stdout(io.StringIO()) as out:
    must(sh.run_canary_command() == 0, "canary command passed")
saved = json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))
must(saved["core_version"] == "1.18.28" and saved["selftest_at"] == "2026-11-11T10:00:00Z" and saved["ok"] is True, saved)
must(helper_state() is True and django_state() is True, "the canary this command wrote counts for this build and selftest")
# a new selftest run makes the same record not count
H.write_ready_status(canary=False, selftest_at="2026-11-11T11:00:00Z")
must(helper_state() is False and django_state() is False, "a later selftest run needs a new canary")
# the selftest_at is read before the canary starts: a status.json that changes during the run does not move it
put(None, "1.18.28\n", "2026-11-11T10:00:00Z")


def run_and_change():
    H.write_ready_status(canary=False, selftest_at="2026-11-11T12:00:00Z")
    return table


sh.run_canary = run_and_change
with contextlib.redirect_stdout(io.StringIO()):
    sh.run_canary_command()
must(json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))["selftest_at"] == "2026-11-11T10:00:00Z", "the selftest run is the one read before the canary")
put(None, "1.18.28\n", "2026-11-11T10:00:00Z")
with contextlib.redirect_stdout(io.StringIO()):
    sh.run_canary_command()
must(json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))["selftest_at"] == "2026-11-11T10:00:00Z", "same")
sh.run_canary = lambda: table
# no status.json: the record carries None and never counts
sh.STATUS_FILE.unlink(missing_ok=True)
sh.INSTALLED_VERSION_FILE.write_text("1.18.28\n", encoding="utf-8")
with contextlib.redirect_stdout(io.StringIO()):
    sh.run_canary_command()
saved = json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))
must(saved["selftest_at"] is None and sh.canary_passed(sh.read_status()) is False, saved)
print("[TEST] PASS sandbox canary record 1.18.28")
