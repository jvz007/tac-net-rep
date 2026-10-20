#!/usr/bin/env python3
"""1.17.58 regression: the licensing enforcement mode (Johan, 19 October 2026: "okay lets stick to log-only").

Covered: the default is log-only with no stored value, with a read error and with a garbage value; what each mode does through the real
``_enforce_candidate_licensing`` (off skips the check and writes no row; log-only lets the module through, writes exactly one would-block
row and raises nothing; enforce refuses as in 1.17.57 and the 403 payload names the mode); a marker secret in a provider reason, a provider
detail dict or an exception message never reaches the row, the status, a log line or a result of log-only; a batch that gates one
candidate twice writes one row; an unexpected failure of the check is a would-block outside enforce and still raises in enforce; a failed
audit write never blocks; the PATCH of ``licensing_enforcement_mode`` (bad value 400, null resets, a non-superuser gets 403 and one deny
row before the value is checked, a mixed body is refused whole, one strict row per change, a failed audit write rolls the change back);
and a call-site pin: the gate is referenced only from stage and install code, so licensing cannot block sign-in, Tactical operations,
module rollback or a security update by construction.

Django, the real model and migration 0033 are dev-server work (tests/licensing-mode-runtime-1.17.58.py).
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
ml, v2, rs = H.ml, H.v2, H.rs
User, PermissionDenied = H.User, H.PermissionDenied
candidate = harness.candidate

MARKERS = ("MARKER-KEY-8841", "MARKER-TOKEN-8842", "MARKER-FINGERPRINT-8843", "MARKER-PRIVATE-8844", "MARKER-REASON-8845", "MARKER-EXC-8846", "MARKER-HEALTH-8847")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def everywhere(*extra):
    """Everything a leak could land in: the audit rows, the log lines and what the caller got back."""
    return json.dumps(H.audits, default=str) + "\n".join(H.log) + "\n".join(repr(item) for item in extra)


def no_marker(label, *extra):
    text = everywhere(*extra)
    for marker in MARKERS:
        must(marker not in text, (label, marker))


# ---- provider stubs: what the Licensing capability may say, with secrets in every free-text place
def cap_ok(*a, **k):
    return {"available": True, "capability_version": "1.3.0", "module_id": "licensing", "state": "available", "health": {"license_key": MARKERS[0]}}


def cap_unhealthy(*a, **k):
    return {"available": False, "capability_version": "1.3.0", "module_id": "licensing", "state": "unhealthy", "reason": MARKERS[4],
            "health": {"token": MARKERS[1], "fingerprint": MARKERS[2]}}


class Unlicensed:
    def check_entitlement(self, *, product, module_id, module_version):
        return {"licensed": False, "reason": MARKERS[4], "license_key": MARKERS[0], "private_key": MARKERS[3], "token": MARKERS[1], "fingerprint": MARKERS[2]}


class Licensed:
    def check_entitlement(self, *, product, module_id, module_version):
        return {"licensed": True, "license_key": MARKERS[0]}


class Raises:
    def check_entitlement(self, *, product, module_id, module_version):
        raise RuntimeError(MARKERS[5])


def scenario(status=cap_ok, provider=None):
    provider = provider or Unlicensed()
    v2.capability_status = status
    v2.get_capability = lambda *a, **k: provider


def set_mode(value):
    H.config.licensing_enforcement_mode = value


REAL_CHECK = v2.check_licensing_requirement


# ======================================================================================================= 1. the default and the getter
H.reset()
must(ml.DEFAULT_LICENSING_MODE == "log-only" and ml.LICENSING_MODES == ("off", "log-only", "enforce"), "default and choices")
must(ml.get_licensing_enforcement_mode() == "log-only" and ml.read_mode() == ("log-only", "default"), "no stored value")
for garbage in ("Enforce", "ENFORCE", " enforce", "on", "true", 5, True, None, [], {}, "log_only"):
    set_mode(garbage)
    must(ml.get_licensing_enforcement_mode() == "log-only" and ml.read_mode()[1] == "default", ("garbage", garbage))
H.current_fails.on = True
must(ml.get_licensing_enforcement_mode() == "log-only", "a read error fails open")
H.current_fails.on = False
for good in ml.LICENSING_MODES:
    set_mode(good)
    must(ml.get_licensing_enforcement_mode() == good and ml.read_mode() == (good, "set"), good)
set_mode("")
must(ml.serialize_mode("") == {"value": "log-only", "source": "default", "choices": ["off", "log-only", "enforce"], "default": "log-only"}, "serialize blank")
must(ml.serialize_mode("enforce")["source"] == "set" and ml.serialize_mode("enforce")["value"] == "enforce", "serialize set")
must(ml.serialize_mode("junk")["source"] == "default", "serialize junk")
# one constant moves the default, and an explicit choice still wins
original = ml.DEFAULT_LICENSING_MODE
ml.DEFAULT_LICENSING_MODE = "enforce"
set_mode("")
must(ml.get_licensing_enforcement_mode() == "enforce", "a blank value follows the default constant")
set_mode("off")
must(ml.get_licensing_enforcement_mode() == "off", "an explicit choice persists when the default moves")
ml.DEFAULT_LICENSING_MODE = original
print("       the default is log-only with no value, a read error or a garbage value; an explicit choice wins over a moved default")

# ======================================================================================================= 2. the gate, mode by mode
calls = []
real_status = v2.capability_status


def counting_status(*a, **k):
    calls.append("status")
    return cap_ok()


# off: no check, no row
H.reset()
set_mode("off")
v2.capability_status = counting_status
v2.get_capability = lambda *a, **k: Unlicensed()
cand = candidate()
status = v2._enforce_candidate_licensing(cand)
must(not calls and not H.audits, "off checks nothing and writes nothing")
must(status["state"] == "not-checked" and status["licensed"] is None and status["required"] is True and status["enforcement_mode"] == "off" and cand["licensing_status"] is status, status)
must(v2._enforce_candidate_licensing(candidate(required=False))["state"] == "not-required", "a module with no licence need is as before in off")
print("       off: the check is skipped, no row, state not-checked")

# log-only: through, one row, nothing raised
for label, status_fn, provider in (("unlicensed", cap_ok, Unlicensed()), ("capability unhealthy", cap_unhealthy, Licensed()), ("provider error", cap_ok, Raises())):
    H.reset()
    set_mode("")  # the default
    scenario(status_fn, provider)
    cand = candidate()
    status = v2._enforce_candidate_licensing(cand)
    must(cand["licensing_status"] is status and status["would_block"] is True and status["licensed"] is False, (label, status))
    must(status["enforcement_mode"] == "log-only" and status["audited"] is True, (label, status))
    must(len(H.audits) == 1, (label, [a["action"] for a in H.audits]))
    row = H.audits[0]
    must(row["action"] == "custom:licence-would-block" and row["module_id"] == "core" and row["object_type"] == "module" and row["object_id"] == "reportmanager", row)
    must(row["strict"] is False, "best effort")
    must(row["actor"].kind == "service" and (row["actor"].module_id, row["actor"].service, row["actor"].identity) == ("core", "licensing", "gate"), row["actor"])
    must(set(row["metadata"]) == {"module", "version", "state", "reason", "mode"} and row["metadata"]["mode"] == "log-only", row["metadata"])
    must(row["metadata"]["module"] == "reportmanager" and row["metadata"]["version"] == "1.0.0", row["metadata"])
    must(len(row["metadata"]["reason"]) <= ml.REASON_CAP, "capped reason")
    must(set(status) <= {"required", "module", "module_version", "product", "capability", "required_capability_version", "capability_version",
                          "provider_module", "state", "licensed", "reason", "enforcement_mode", "would_block", "audited"}, set(status))
    no_marker(label, status)
print("       log-only (the default): the module goes through, one would-block row, no provider text anywhere")
must(status["state"] == "provider-error" and status["reason"] == "The licensing entitlement check failed.", status)

# the states map to Core's own sentences, and an unknown state is 'unknown'
for state, sentence in (("unlicensed", "Product 'reportmanager' is not licensed."), ("unhealthy", "The licensing provider reports that it is not healthy."),
                        ("disabled", "The licensing provider module is disabled."), ("made-up", "The licence check did not pass.")):
    summary = ml.refusal_summary({"state": state, "reason": MARKERS[4], "product": "reportmanager", "details": {"k": MARKERS[0]}}, "log-only")
    must(summary["reason"] == sentence and MARKERS[4] not in json.dumps(summary) and MARKERS[0] not in json.dumps(summary), (state, summary))
must(ml.refusal_summary({"state": "made-up"}, "log-only")["state"] == "unknown", "unknown state")
print("       refusal states read as Core's own sentences; provider reasons and detail dicts are never copied")

# enforce: refuses as before
H.reset()
set_mode("enforce")
scenario(cap_ok, Unlicensed())
try:
    v2._enforce_candidate_licensing(candidate())
    raise AssertionError("enforce did not refuse")
except v2.LicensingRequirementError as exc:
    payload = exc.as_payload()
    must(payload["code"] == "licensing_requirement_failed" and payload["licensing"]["state"] == "unlicensed", payload)
    must(payload["licensing"]["enforcement_mode"] == "enforce", payload["licensing"])
    must(payload["licensing"]["reason"] == MARKERS[4], "enforce keeps the 1.17.57 refusal text")
must(not H.audits, "a refusal in enforce writes no gate row")
for status_fn, provider, state in ((cap_unhealthy, Licensed(), "unhealthy"), (cap_ok, Raises(), "provider-error")):
    scenario(status_fn, provider)
    try:
        v2._enforce_candidate_licensing(candidate())
        raise AssertionError("enforce did not refuse")
    except v2.LicensingRequirementError as exc:
        must(exc.result["state"] == state, exc.result)
scenario(cap_ok, Licensed())
ok = v2._enforce_candidate_licensing(candidate())
must(ok["licensed"] is True and ok["state"] == "licensed" and "enforcement_mode" not in ok and not H.audits, ok)
print("       enforce: refuses exactly as 1.17.57, the 403 payload gains enforcement_mode")

# a licensed module and a module with no licence need are the same in every mode
for mode in ("off", "log-only", "enforce"):
    H.reset()
    set_mode(mode)
    scenario(cap_ok, Licensed())
    must(v2._enforce_candidate_licensing(candidate(required=False))["state"] == "not-required" and not H.audits, mode)
    if mode != "off":
        must(v2._enforce_candidate_licensing(candidate())["state"] == "licensed" and not H.audits, mode)
print("       a free module and a licensed module read the same in every mode")

# a batch gates one candidate twice in one request: one row
H.reset()
scenario(cap_ok, Unlicensed())
cand = candidate()
v2._enforce_candidate_licensing(cand)
v2._enforce_candidate_licensing(cand)
must(len(H.audits) == 1, [a["action"] for a in H.audits])
v2._enforce_candidate_licensing(candidate())  # a fresh candidate of the same module is a new request: a new row
must(len(H.audits) == 2, "no cross-request dedupe")
print("       one candidate gated twice writes one row; separate requests write their own")

# an unexpected failure of the check is a would-block outside enforce, and still an error in enforce
def boom(candidate_):
    raise KeyError(MARKERS[5])


v2.check_licensing_requirement = boom
try:
    for mode in ("log-only", ""):
        H.reset()
        set_mode(mode)
        status = v2._enforce_candidate_licensing(candidate())
        must(status["state"] == "check-error" and status["would_block"] is True and len(H.audits) == 1, status)
        no_marker("unexpected failure", status)
    H.reset()
    set_mode("enforce")
    try:
        v2._enforce_candidate_licensing(candidate())
        raise AssertionError("enforce swallowed an unexpected failure")
    except KeyError:
        pass
finally:
    v2.check_licensing_requirement = REAL_CHECK
print("       an unexpected failure of the check is a would-block in log-only and an error in enforce, as before")

# a failed audit write never blocks log-only
H.reset()
set_mode("log-only")
scenario(cap_ok, Unlicensed())
H.audit_fail.on = True
cand = candidate()
status = v2._enforce_candidate_licensing(cand)
must(status["would_block"] is True and status["audited"] is False and not H.audits, status)
must(any("would-block audit row" in line for line in H.log), "the failed write is logged")
no_marker("failed audit write", status)
H.audit_fail.on = False
v2._enforce_candidate_licensing(cand)  # a later gate call on the same candidate tries again
must(len(H.audits) == 1, "the retry wrote the row")
print("       a failed would-block write is logged and ignored; licensing never blocks")

# ======================================================================================================= 3. the setting over PATCH and GET
view = rs.RuntimeSettingsView()
SETTING = "licensing_enforcement_mode"
admin = User("root", superuser=True)
manager = User("manager", runtime=True)
nobody = User("nobody")


def patch(user, body):
    return view.patch(SimpleNamespace(user=user, data=body))


def denied(user, body):
    try:
        patch(user, body)
    except PermissionDenied as exc:
        return str(exc)
    raise AssertionError("not refused")


H.reset()
got = view.get(SimpleNamespace(user=nobody)).data
must(got[SETTING] == {"value": "log-only", "source": "default", "choices": ["off", "log-only", "enforce"], "default": "log-only"}, got[SETTING])
must(SETTING in rs.RUNTIME_SETTING_NAMES and rs.RUNTIME_SETTING_NAMES[:3] == ("module_register_timeout_seconds", "tactical_operation_upload_max_mib", "system_name"), rs.RUNTIME_SETTING_NAMES)

# a person with no right at all is refused first; a manager who is not a superuser gets 403 and a deny row, before the value is checked
denied(nobody, {SETTING: "enforce"})
must(not H.audits, "no right, no row")
for value in ("enforce", "bogus", 5, True, None, ""):
    H.reset()
    must(rs.LICENSING_MODE_DENIED in denied(manager, {SETTING: value}), value)
    must(H.config.licensing_enforcement_mode == "", "nothing saved")
    rows = [a for a in H.audits if a["action"] == "deny"]
    must(len(rows) == 1 and rows[0]["object_id"] == SETTING and rows[0]["object_type"] == "runtime_settings" and rows[0]["strict"] is False, H.audits)
    must(rows[0]["metadata"] == {"reason": "superuser_required"} and rows[0].get("before") is None and rows[0].get("after") is None, "no value in the deny row")
    if isinstance(value, str) and value:
        must(value not in json.dumps(rows, default=str).replace("licensing_enforcement_mode", ""), "the value is not copied into the row")
# a mixed body is refused whole: the other setting is not saved either
H.reset()
denied(manager, {"module_register_timeout_seconds": 60, SETTING: "enforce"})
must(H.config.module_register_timeout_seconds == 30 and H.config.licensing_enforcement_mode == "", "mixed body refused whole")
print("       a manager who is not a superuser: 403 and a deny row before the value is looked at, a mixed body refused whole")

# a superuser: bad values are 400 and change nothing
H.reset()
for bad in ("Enforce", "ENFORCE", " enforce", "on", "true", 1, True, False, 1.5, [], {}, "", "log_only"):
    response = patch(admin, {SETTING: bad})
    must(response.status_code == 400 and SETTING in response.data["detail"], (bad, response.data))
must(H.config.licensing_enforcement_mode == "" and not H.audits, "bad values change and audit nothing")

# a good value: stored, one strict row with effective before and after and where each came from
response = patch(admin, {SETTING: "enforce"})
must(response.status_code == 200 and H.config.licensing_enforcement_mode == "enforce", response.data)
must(response.data[SETTING] == {"value": "enforce", "source": "set", "choices": ["off", "log-only", "enforce"], "default": "log-only"}, response.data)
must(len(H.audits) == 1, H.audits)
row = H.audits[0]
must(row["action"] == "modify" and row["object_type"] == "runtime_settings" and row["object_id"] == SETTING and row["strict"] is True and row["module_id"] == "core", row)
must(row["before"] == {SETTING: "log-only"} and row["after"] == {SETTING: "enforce"} and row["actor"] is admin, row)
must(row["metadata"] == {"source_before": "default", "source_after": "set"}, row["metadata"])
must(ml.get_licensing_enforcement_mode() == "enforce", "the gate reads the new value at once")
H.audits.clear()
# the same value again is no change
patch(admin, {SETTING: "enforce"})
must(not H.audits, "no row for the current value")
# another value
patch(admin, {SETTING: "off"})
must(H.audits[-1]["before"] == {SETTING: "enforce"} and H.audits[-1]["after"] == {SETTING: "off"} and H.audits[-1]["metadata"] == {"source_before": "set", "source_after": "set"}, H.audits[-1])
H.audits.clear()
# null resets to the default: stored blank
response = patch(admin, {SETTING: None})
must(H.config.licensing_enforcement_mode == "" and response.data[SETTING]["source"] == "default" and response.data[SETTING]["value"] == "log-only", response.data)
must(H.audits[-1]["before"] == {SETTING: "off"} and H.audits[-1]["after"] == {SETTING: "log-only"} and H.audits[-1]["metadata"] == {"source_before": "set", "source_after": "default"}, H.audits[-1])
H.audits.clear()
patch(admin, {SETTING: None})
must(not H.audits, "resetting a default is no change")
# choosing log-only while the default is log-only pins it: a change of source, so a row
patch(admin, {SETTING: "log-only"})
must(len(H.audits) == 1 and H.audits[0]["before"] == H.audits[0]["after"] == {SETTING: "log-only"}, H.audits)
must(H.audits[0]["metadata"] == {"source_before": "default", "source_after": "set"} and H.config.licensing_enforcement_mode == "log-only", H.audits[0])
# one strict row per changed setting, in one transaction
H.reset()
H.config.module_register_timeout_seconds = 30
response = patch(admin, {"module_register_timeout_seconds": 60, SETTING: "enforce"})
must(response.status_code == 200 and [a["object_id"] for a in H.audits] == ["module_register_timeout_seconds", SETTING] and all(a["strict"] for a in H.audits), H.audits)
H.config.module_register_timeout_seconds = 30
# a failed audit write rolls the change back (the write raises inside the transaction)
H.reset()
H.audit_fail.on = True
H.audit_fail.only_strict = True
errors = H.AtomicCtx.exited_with_error
try:
    patch(admin, {SETTING: "enforce"})
    raise AssertionError("a failed audit write was swallowed")
except RuntimeError:
    pass
must(H.AtomicCtx.exited_with_error == errors + 1, "the change and its row share one transaction")
H.audit_fail.on = False
# a stored invalid value is read as the default, never as a number
H.reset()
H.config.licensing_enforcement_mode = "junk"
response = patch(admin, {SETTING: "off"})
must(response.status_code == 200 and H.audits[-1]["before"] == {SETTING: "log-only"} and H.audits[-1]["metadata"]["source_before"] == "default", H.audits)
# the 400 texts
H.reset()
must(SETTING in patch(admin, {}).data["detail"] and patch(admin, {"nope": 1}).status_code == 400, "400 texts")
print("       PATCH: bad value 400, null resets, one strict row per change, a failed audit write rolls the change back")

# ======================================================================================================= 4. call-site pin
APP = H.root / "framwork" / "tec_tac"
sources = {path.name: path.read_text(encoding="utf-8") for path in APP.rglob("*.py")}
def references_gate(text):
    """True when the code (not a comment or a docstring) names the gate: a call, an attribute or an import."""
    for node in ast.walk(ast.parse(text)):
        if (isinstance(node, ast.Name) and node.id == "_enforce_candidate_licensing") or (isinstance(node, ast.Attribute) and node.attr == "_enforce_candidate_licensing")                 or (isinstance(node, ast.alias) and node.name == "_enforce_candidate_licensing"):
            return True
    return False


gate_users = sorted(name for name, text in sources.items() if references_gate(text))
must(gate_users == ["module_manager_v2.py", "views.py"], gate_users)
# views.py: only the two v1 module package views call the gate
tree = ast.parse(sources["views.py"])
holders = sorted(node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and "_enforce_candidate_licensing" in (ast.get_source_segment(sources["views.py"], node) or ""))
must(holders == ["ModulePackageInspectView", "ModulePackageInstallView"], holders)
# module_manager_v2.py: only stage and install functions call the gate
tree = ast.parse(sources["module_manager_v2.py"])
callers = sorted({fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef) and fn.name != "_enforce_candidate_licensing"
                  and any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_enforce_candidate_licensing" for c in ast.walk(fn))})
must(callers and all(re.search(r"(stage|install|inspect)", name) for name in callers), callers)
must(not any(re.search(r"(rollback|restore|sign|login|session|context|operation|update|helper)", name) for name in callers), callers)
# nothing that signs in, builds the UI context, runs a Tactical operation, rolls back or updates the system reaches the check or the mode
def reaches_licensing(text):
    """True when the code imports module_licensing or names the check or the mode getter (comments and strings do not count)."""
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.ImportFrom) and ((node.module or "").split(".")[-1] == "module_licensing" or any(alias.name == "module_licensing" for alias in node.names)):
            return True
        if isinstance(node, ast.Import) and any(alias.name.split(".")[-1] == "module_licensing" for alias in node.names):
            return True
        if (isinstance(node, ast.Name) and node.id in ("check_licensing_requirement", "get_licensing_enforcement_mode")) or (
                isinstance(node, ast.Attribute) and node.attr in ("check_licensing_requirement", "get_licensing_enforcement_mode")):
            return True
    return False


ALLOWED = ["module_licensing.py", "module_licensing_views.py", "module_manager_v2.py", "module_repository_views.py", "module_v2_views.py", "runtime_settings.py"]
reached = sorted(name for name, text in sources.items() if reaches_licensing(text))
must(reached == ALLOWED, reached)
must(not reaches_licensing(sources["views.py"]), "views.py (sign-in, UI context, system update) does not reach module_licensing")
for helper in sorted((H.root / "scripts").glob("*.py")):
    must("module_licensing" not in helper.read_text(encoding="utf-8") and "_enforce_candidate_licensing" not in helper.read_text(encoding="utf-8"), f"{helper.name} reaches the gate")
for guarded in ("tactical_operations.py", "audit.py", "rbac.py", "session_security.py", "module_replacement.py"):
    if guarded in sources:
        must(not reaches_licensing(sources[guarded]), f"{guarded} reaches the licensing gate")
print("       call sites: the gate is referenced only from module stage and install code; sign-in, the UI context, Tactical operations, rollback and system updates never reach it")

# the migration and the model agree
migration = (APP / "migrations" / "0033_runtime_licensing_mode.py").read_text(encoding="utf-8")
must('("tec_tac", "0032_event_jobs")' in migration and 'name="licensing_enforcement_mode"' in migration, "migration 0033 names its parent and the column")
must('field=models.CharField(blank=True, default="", max_length=16)' in migration, "migration field")
must('licensing_enforcement_mode = models.CharField(max_length=16, blank=True, default="")' in sources["models.py"], "model field")
print("[TEST] PASS licensing enforcement mode 1.17.58")
