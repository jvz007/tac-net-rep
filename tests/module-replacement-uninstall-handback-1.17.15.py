#!/usr/bin/env python3
"""1.17.15 regression: an uninstall of an enabled replacement hands its replaced module back (Johan CQ43, 10 October 2026).

Two halves, both Django-free:
* Core: ``module_manager.queue_remove`` runs the real hand-back rules of ``module_manager_v2`` over a fixture model. It
  queues ``enable_modules`` when the replaced module can come back, refuses with HTTP 400 and the code
  ``replacement_hand_back_confirmation_required`` when it cannot and the request did not confirm, and records the job's
  hand-back list and the audit row. The view's mapping of that refusal is checked as text (Django is not installed here).
* Root helper: ``scripts/module-job-helper.py`` is loaded as a module (its shebang and main guard are not run). Its
  ``plan_remove_hand_back`` re-checks the rules from manifests before anything is removed, and ``set_module_enabled``
  writes the flag. The Linux-only parts (the bash path, the file owner) are stubbed; ``_trusted_stat`` is tested alone.

The on-server half (a real uninstall through sudo and the state file) is for the dev server.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
_stub("pwd", getpwnam=lambda name: None)  # the helper imports it; Linux only
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)
# Linux-only calls (file owner and mode) are no-ops here; the helper's owner check is tested on its own below.
if not hasattr(os, "fchmod"):
    os.fchmod = lambda *a, **k: None
if not hasattr(os, "chown"):
    os.chown = lambda *a, **k: None

from tec_tac import safe_files  # noqa: E402
from tec_tac import module_manager as mm  # noqa: E402
from tec_tac import module_manager_v2 as v2  # noqa: E402
from tec_tac import module_replacement as mr  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="tt-handback-"))
if os.name == "nt":  # Windows cannot open a directory to fsync it; Linux runs the real call.
    safe_files._fsync_directory = lambda path: None


# ------------------------------------------------------------------------------------------ fixtures
def module(mid, category="core", enabled=True, replaces="", dependencies=None, managed=True, **extra):
    return {"id": mid, "category": category, "enabled": enabled, "replaces": replaces, "managed": managed,
            "protected": False, "legacy": False, "dependencies": dependencies or {}, "runtime_requirements": [],
            "extension_version": "1.0.0", **extra}


def fixture(**overrides):
    """A core module ``patching`` and its enabled replacement ``adv-patching``. ``overrides`` replaces rows by id."""
    rows = {
        "patching": module("patching", "core", enabled=False),
        "adv-patching": module("adv-patching", "premium", enabled=True, replaces="patching"),
    }
    rows.update(overrides)
    return rows


STATE = {}


def install(rows):
    """Point the three Core seams at ``rows``: the catalogue, the live model and the job list. Nothing is read from disk."""
    STATE["rows"] = rows
    v2.installed_catalog_v2 = lambda: [dict(item) for item in rows.values()]
    mm.installed_catalog = lambda: [{"id": item["id"], "managed": item["managed"]} for item in rows.values()]
    mr.live_model = lambda *a, **k: {mid: mr.Node(id=mid, category=item["category"], enabled=item["enabled"],
                                                  replaces=item["replaces"]) for mid, item in rows.items()}
    v2._iter_jobs = lambda: []


AUDITS = []
mr.audit_switch_queued = lambda actor, subject, job_id, disabled=(), enabled=(), skipped=(): AUDITS.append(
    {"actor": actor, "subject": subject, "job": job_id, "enabled": list(enabled), "skipped": list(skipped)})
mm._dispatch = lambda job_id: None
mm.JOBS_ROOT = TMP / "jobs"
mm.LOGS_ROOT = TMP / "logs"


def queued_jobs():
    return sorted(mm.JOBS_ROOT.glob("*.json")) if mm.JOBS_ROOT.is_dir() else []


def remove(plugin_id="adv-patching", **kw):
    return mm.queue_remove(plugin_id, requested_by="alice", **kw)


# ------------------------------------------------------------------------------------------ Core: the hand-back
install(fixture())
AUDITS.clear()
job = remove(actor="ACTOR")
must(job["action"] == "remove" and job["plugin_id"] == "adv-patching", job)
must(job["requested_by"] == "alice", job)
stored = json.loads(next(p for p in queued_jobs()).read_text(encoding="utf-8"))
must(stored["enable_modules"] == ["patching"] and stored["hand_back_skipped"] == [], stored)
must(AUDITS == [{"actor": "ACTOR", "subject": "adv-patching", "job": stored["id"], "enabled": ["patching"], "skipped": []}], AUDITS)

# the replaced module cannot come back: a refusal, nothing queued, no audit
for f in queued_jobs():
    f.unlink()
AUDITS.clear()
blocked = fixture(patching=module("patching", "core", enabled=False, dependencies={"missing-lib": ">=1.0.0"}))
install(blocked)
try:
    remove()
    raise AssertionError("an unconfirmed uninstall must be refused")
except v2.ModuleReplacementHandBackConfirmationRequired as exc:
    payload = exc.as_payload()
must(payload["code"] == "replacement_hand_back_confirmation_required", payload)
must(payload["module"] == "adv-patching" and payload["will_enable"] == [], payload)
must([row["module"] for row in payload["hand_back_unavailable"]] == ["patching"], payload)
must("missing-lib" in payload["hand_back_unavailable"][0]["required_modules"], payload)
must(queued_jobs() == [] and AUDITS == [], "a refused uninstall queues nothing and writes no audit row")

# the same uninstall, confirmed: queued, the replaced module is left off and the job says so
confirmed = remove(confirm_without_hand_back=True, actor="ACTOR")
stored = json.loads(queued_jobs()[0].read_text(encoding="utf-8"))
must(stored["enable_modules"] == [] and stored["hand_back_skipped"] == ["patching"], stored)
must(AUDITS[-1]["enabled"] == [] and AUDITS[-1]["skipped"] == ["patching"], AUDITS)
must(confirmed["status"] == "queued", confirmed)

# a confirmation that is not true does not count
for f in queued_jobs():
    f.unlink()
try:
    remove(confirm_without_hand_back="yes")
    raise AssertionError("a confirmation that is not true must not count")
except v2.ModuleReplacementHandBackConfirmationRequired:
    pass

# nothing to hand back: a disabled replacement, a module that replaces nothing, a replaced module already enabled
for f in queued_jobs():
    f.unlink()
AUDITS.clear()
install(fixture(**{"adv-patching": module("adv-patching", "premium", enabled=False, replaces="patching")}))
remove()
stored = json.loads(queued_jobs()[0].read_text(encoding="utf-8"))
must(stored["enable_modules"] == [] and stored["hand_back_skipped"] == [] and AUDITS == [], "a disabled replacement hands back nothing")
for f in queued_jobs():
    f.unlink()
install(fixture(**{"adv-patching": module("adv-patching", "premium", enabled=True, replaces="")}))
remove()
stored = json.loads(queued_jobs()[0].read_text(encoding="utf-8"))
must(stored["enable_modules"] == [] and AUDITS == [], "a module that replaces nothing hands back nothing")
for f in queued_jobs():
    f.unlink()
install(fixture(patching=module("patching", "core", enabled=True)))
remove()
stored = json.loads(queued_jobs()[0].read_text(encoding="utf-8"))
must(stored["enable_modules"] == [] and stored["hand_back_skipped"] == [], "a replaced module that is on needs nothing")
for f in queued_jobs():
    f.unlink()

# a removed module that is not a replacement at all is queued as before
install(fixture(**{"other": module("other", "premium", enabled=True)}))
remove("other")
stored = json.loads(queued_jobs()[0].read_text(encoding="utf-8"))
must(stored["enable_modules"] == [] and stored["hand_back_skipped"] == [], stored)
for f in queued_jobs():
    f.unlink()

# the view maps the refusal to HTTP 400 with the code (checked as text: views.py needs Django)
views_src = (ROOT / "framwork" / "tec_tac" / "views.py").read_text(encoding="utf-8")
remove_view = re.search(r"class ModuleRemoveView.*?(?=\n@extend_schema_view|\Z)", views_src, re.S).group(0)
must("ModuleReplacementHandBackConfirmationRequired" in remove_view and "exc.as_payload(), status=400" in remove_view,
     "the remove view returns the hand-back refusal as HTTP 400")
must("confirm_without_hand_back=confirm" in remove_view and "_confirm_without_hand_back(request)" in remove_view,
     "the remove view reads confirm_without_hand_back")

# ------------------------------------------------------------------------------------------ root helper: the re-check
HELPER_PATH = ROOT / "scripts" / "module-job-helper.py"
source = HELPER_PATH.read_text(encoding="utf-8").replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"')
helper = types.ModuleType("module_job_helper_under_test")
helper.__file__ = str(HELPER_PATH)
exec(compile(source, str(HELPER_PATH), "exec"), helper.__dict__)  # the main guard keeps the worker from running

REAL_TRUSTED = helper._trusted_stat
# Linux-only pieces: the owner check is tested on its own below; the state write uses chown and fchmod.
helper._trusted_stat = lambda info: True

STATE_DIR = TMP / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
helper.STATE_ROOT = STATE_DIR
helper.STATE_FILE = STATE_DIR / "module-state.json"
helper.MODULE_STATE_LOCK = STATE_DIR / "module-state.lock"
helper.MODULE_STATE_LOCK.write_text("", encoding="utf-8")
REPO = TMP / "repo"


def manifest(mid, **fields):
    folder = REPO / "extensions" / mid
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps({"id": mid, **fields}), encoding="utf-8")


def set_state(modules):
    helper.STATE_FILE.write_text(json.dumps({"schema": 1, "modules": modules}), encoding="utf-8")


def reset_repo():
    extensions = REPO / "extensions"
    if extensions.is_dir():
        for folder in extensions.iterdir():
            for child in folder.iterdir():
                child.unlink()
            folder.rmdir()
    manifest("patching", category="core")
    manifest("adv-patching", category="premium", replaces="patching")


def plan(enable=("patching",), plugin="adv-patching"):
    return helper.plan_remove_hand_back(REPO, plugin, list(enable))


reset_repo()
set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}})
must(plan() == ["patching"], "a replaced module that is off comes back")
must(plan(enable=()) == [] and helper.plan_remove_hand_back(REPO, "adv-patching", None) == [], "nothing asked, nothing checked")

# every rule holds, or the job is refused before anything is removed
def refusal(label, setup, enable=("patching",), plugin="adv-patching"):
    reset_repo()
    setup()
    try:
        plan(enable=enable, plugin=plugin)
    except RuntimeError as exc:
        return str(exc)
    raise AssertionError(f"the helper must refuse: {label}")


text = refusal("the replaced module is on", lambda: set_state({"patching": {"enabled": True}, "adv-patching": {"enabled": True}}))
must("enabled already" in text, text)
text = refusal("the removed module is not enabled", lambda: set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": False}}))
must("not enabled" in text, text)
text = refusal("the target is not core or server", lambda: (manifest("patching", category="premium"),
                                                            set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}})))
must("not a core or server module" in text, text)
text = refusal("the removed module does not replace it", lambda: (manifest("adv-patching", category="premium", replaces="other"),
                                                                  set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}})))
must("does not replace it" in text, text)
text = refusal("another enabled replacement stays", lambda: (manifest("rival", category="premium", replaces="patching"),
                                                             set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}, "rival": {"enabled": True}})))
must("stays enabled" in text and "rival" in text, text)
text = refusal("the target has no trusted manifest", lambda: set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}}),
               enable=("ghost",))
must("cannot verify" in text, text)
text = refusal("the id is not valid", lambda: set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}}),
               enable=("../etc",))
must("invalid module id" in text, text)
text = refusal("the removed module has no manifest", lambda: set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}}),
               plugin="gone")
must("cannot verify the hand-back for gone" in text, text)

# a rival that is installed but off does not block
reset_repo()
manifest("rival", category="premium", replaces="patching")
set_state({"patching": {"enabled": False}, "adv-patching": {"enabled": True}, "rival": {"enabled": False}})
must(plan() == ["patching"], "a rival that is off does not block the hand-back")

# the state write: the replaced module comes back on, the rest of the file is kept
set_state({"patching": {"enabled": False, "version": "1.0.0"}, "adv-patching": {"enabled": True}, "other": {"enabled": True}})
helper.set_module_enabled(["patching"], True)
written = json.loads(helper.STATE_FILE.read_text(encoding="utf-8"))["modules"]
must(written["patching"] == {"enabled": True, "version": "1.0.0"} and written["other"] == {"enabled": True}, written)
must(written["adv-patching"] == {"enabled": True}, written)

# the record run_job works on keeps what Core queued; the root-side fields win for their own keys
status = {"id": "job-1", "status": "dispatched", "stage": "dispatched", "created_at": "2026-10-10T10:00:00+00:00",
          "requested_by": "alice", "enable_modules": ["patching"], "hand_back_skipped": [], "error": None}
immutable = {"id": "job-1", "action": "remove", "plugin_id": "adv-patching", "replace": False, "enable_modules": ["patching"]}
record = helper.run_job_record(status, immutable)
must(record["requested_by"] == "alice" and record["enable_modules"] == ["patching"] and record["status"] == "dispatched", record)
must(record["plugin_id"] == "adv-patching" and record["action"] == "remove" and record["stage"] == "dispatched", record)

# the owner and mode check, tested on its own: root-owned and not writable by group or others
must(REAL_TRUSTED(SimpleNamespace(st_uid=0, st_mode=0o100644)) is True, "root-owned, not writable by others: trusted")
must(REAL_TRUSTED(SimpleNamespace(st_uid=1000, st_mode=0o100644)) is False, "not root-owned: refused")
must(REAL_TRUSTED(SimpleNamespace(st_uid=0, st_mode=0o100666)) is False, "writable by others: refused")
must(REAL_TRUSTED(SimpleNamespace(st_uid=0, st_mode=0o100664)) is False, "writable by the group: refused")

# the helper stays LF-only (see root-script-crlf-1.17.15.sh)
must(b"\r" not in HELPER_PATH.read_bytes(), "the helper carries no carriage return")

print("[TEST] PASS module replacement uninstall hand-back 1.17.15")
