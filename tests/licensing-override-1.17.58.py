#!/usr/bin/env python3
"""1.17.58 regression: the audited emergency override of the licence refusal (Johan, 19 October 2026; flagged for human review: commercial).

The rule: a superuser may let one refused module through a stage or install when the mode is enforce, with a reason of 1 to 500 characters,
and Core writes one STRICT audit row first. It skips nothing but this licence refusal. It does not carry from stage to install.

Covered through the real views and the real gate (staging itself is stubbed; the stubs call the gate the way the real staging does): a
non-superuser who sends the field gets 403 and one deny row before any package work, in every mode, on the v2 inspect, the v2 install and
the repository stage routes; a superuser's empty, over-long, control-character or non-text reason is a 400; enforce plus a refusal plus a
valid override continues and writes exactly one strict row with the reason and the superuser as actor; a failed strict write keeps the
refusal; log-only and off write no override row; the scope is cleared after success, after an exception and is not seen by another thread;
the override does not carry to a second call; nothing but the reason text is free text in the row; a source pin shows the override is used
only inside the licence gate (trust, signature, compatibility, dependency and replacement checks cannot see it), and that the v1 routes take none.
"""
from __future__ import annotations

import ast
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
ml, v2, v2views, repoviews = H.ml, H.v2, H.v2views, H.repoviews
User = H.User
candidate = harness.candidate
MARKERS = ("MARKER-KEY-7701", "MARKER-TOKEN-7702", "MARKER-REASON-7703")
FIELD = "licence_override_reason"
ROOT = H.root


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class Unlicensed:
    def check_entitlement(self, *, product, module_id, module_version):
        return {"licensed": False, "reason": MARKERS[2], "license_key": MARKERS[0], "token": MARKERS[1]}


def world(mode):
    H.reset()
    H.config.licensing_enforcement_mode = mode
    v2.capability_status = lambda *a, **k: {"available": True, "capability_version": "1.3.0", "module_id": "licensing", "state": "available"}
    v2.get_capability = lambda *a, **k: Unlicensed()


# ---- the staging stubs: they run the gate exactly where the real functions do, and note what the gate could see
WORK = []  # one entry per call that did package work
SEEN = []  # active_override() at the moment of the gate


def gate(cand):
    status = v2._enforce_candidate_licensing(cand)
    SEEN.append(ml.active_override())
    return status


def fake_stage(*args, **kwargs):
    WORK.append("stage")
    cand = candidate()
    gate(cand)
    return {"upload_id": "u1", "preview": {"licensing": cand["licensing_status"]}}


def fake_install(upload_id, requested_order=None, requested_by=None, disable_replaced=None, actor=None):
    WORK.append("install")
    cand = candidate()
    gate(cand)
    gate(cand)  # a batch gates one candidate twice
    return {"job_id": "j1", "licensing": cand["licensing_status"]}


def fake_repo_stage(repository_id, module_id, version, allow_source_change=False):
    WORK.append("repo-stage")
    cand = candidate()
    gate(cand)
    return {"upload_id": "u2", "preview": {"licensing": cand["licensing_status"]}}


v2views.stage_multiple_packages = lambda uploads, signatures, metadata_files: fake_stage()
v2views.stage_uploaded_artifact = lambda *a, **k: fake_stage()
v2views.queue_v2_install = fake_install
v2views.queue_batch_install = fake_install
repoviews.stage_repository_package = fake_repo_stage


class Files:
    def getlist(self, name):
        return [SimpleNamespace(name="p.zip")] if name == "packages" else []

    def get(self, name):
        return None


def call(route, user, data=None):
    del WORK[:]
    del SEEN[:]
    body = dict(data or {})
    if route == "inspect":
        return v2views.ModuleV2InspectView().post(SimpleNamespace(user=user, data=body, FILES=Files()))
    if route == "install":
        return v2views.ModuleV2InstallView().post(SimpleNamespace(user=user, data=body), "11111111-1111-1111-1111-111111111111")
    body.update(repository_id="repo", module_id="reportmanager")
    return repoviews.ModuleOnlineStageView().post(SimpleNamespace(user=user, data=body))


ROUTES = ("inspect", "install", "repo")
ADMIN = User("root", superuser=True)
MANAGER = User("manager", runtime=True)
OK_STATUS = {"inspect": 201, "install": 202, "repo": 201}

# ======================================================================================================= 1. a non-superuser: 403, a deny row, no work
for mode in ("off", "log-only", "enforce"):
    for route in ROUTES:
        for value in ("a good reason", "", "   ", None, 5, "x" * 600):
            world(mode)
            response = call(route, MANAGER, {FIELD: value})
            must(response.status_code == 403 and response.data["code"] == "licence_override_superuser_required", (mode, route, value, response.data))
            must(not WORK, (mode, route, "no package work before the check"))
            rows = [a for a in H.audits if a["action"] == "deny"]
            must(len(rows) == 1 and rows[0]["object_id"] == "licence_override" and rows[0]["object_type"] == "module" and rows[0]["strict"] is False, H.audits)
            must(rows[0]["metadata"] == {"reason": "superuser_required"}, rows[0]["metadata"])
            dumped = json.dumps(rows, default=str)
            must("a good reason" not in dumped and "xxxxx" not in dumped, "the reason text is never in the deny row")
print("       a non-superuser who sends the field: 403 and one deny row, before any work, in every mode, on all three routes")

# ======================================================================================================= 2. a superuser's bad reason: 400
for mode in ("off", "log-only", "enforce"):
    for route in ROUTES:
        for bad in ("", "   ", "\t\n", "x" * 501, "bad\x00reason", "bad\x07reason", "zero\u200bwidth", None, 5, True, ["reason"], {"reason": "x"}):
            world(mode)
            response = call(route, ADMIN, {FIELD: bad})
            must(response.status_code == 400 and response.data["code"] == "invalid_licence_override_reason" and FIELD in response.data["detail"], (mode, route, bad, response.data))
            must(not WORK and not H.audits, (mode, route, bad, "refused before work, no row"))
print("       a superuser's empty, over-long, control-character or non-text reason is a 400, never silently ignored")
for good, expected in (("x", "x"), ("x" * 500, "x" * 500), ("  needs a reason  ", "needs a reason"), ("Café – stuck on a licence call", "Café – stuck on a licence call")):
    must(ml.clean_override_reason(good) == expected, good)

# ======================================================================================================= 3. enforce: refusal plus override continues, one strict row
for route in ROUTES:
    world("enforce")
    refused = call(route, ADMIN, {})
    must(refused.status_code == 403 and refused.data["code"] == "licensing_requirement_failed" and refused.data["licensing"]["enforcement_mode"] == "enforce", (route, refused.data))
    must(not H.audits, "a refusal writes no gate row in enforce")
    world("enforce")
    response = call(route, ADMIN, {FIELD: "  Licensing server is down; customer is waiting  "})
    must(response.status_code == OK_STATUS[route], (route, response.status_code, response.data))
    status = response.data["licensing"] if route == "install" else response.data["preview"]["licensing"]
    must(status["overridden"] is True and status["would_block"] is False and status["enforcement_mode"] == "enforce" and status["licensed"] is False, status)
    rows = [a for a in H.audits if a["action"] == "custom:licence-override"]
    must(len(rows) == 1 and len(H.audits) == 1, (route, [a["action"] for a in H.audits]))  # the batch gate ran twice: one row
    row = rows[0]
    must(row["strict"] is True and row["actor"] is ADMIN and row["module_id"] == "core" and row["object_type"] == "module" and row["object_id"] == "reportmanager", row)
    must(row["metadata"] == {"module": "reportmanager", "version": "1.0.0", "state": "unlicensed", "mode": "enforce",
                             "override_reason": "Licensing server is down; customer is waiting"}, row["metadata"])
    dumped = json.dumps(H.audits, default=str) + json.dumps(response.data, default=str) + "\n".join(H.log)
    for marker in MARKERS:
        must(marker not in dumped, (route, "the reason text is the only free text", marker))
    must(SEEN and all(item is not None and item[0] is ADMIN for item in SEEN), "the gate saw the override")
    must(ml.active_override() is None, "cleared after the call")
print("       enforce plus a refusal plus a valid override: the stage or install continues, one strict row with the reason and the superuser")

# ======================================================================================================= 4. a failed strict write keeps the refusal
for route in ROUTES:
    world("enforce")
    H.audit_fail.on = True
    H.audit_fail.only_strict = True
    response = call(route, ADMIN, {FIELD: "emergency"})
    must(response.status_code == 403 and response.data["code"] == "licensing_requirement_failed", (route, response.data))
    must(not H.audits and ml.active_override() is None, "no row, no override")
    H.audit_fail.on = False
print("       if the strict row cannot be written the original refusal stands (fail closed)")

# ======================================================================================================= 5. log-only and off: nothing blocks, so no override row
for mode, rows_expected in (("log-only", ["custom:licence-would-block"]), ("", ["custom:licence-would-block"]), ("off", [])):
    for route in ROUTES:
        world(mode)
        response = call(route, ADMIN, {FIELD: "just in case"})
        must(response.status_code == OK_STATUS[route], (mode, route, response.data))
        must([a["action"] for a in H.audits] == rows_expected, (mode, route, [a["action"] for a in H.audits]))
        must(not [a for a in H.audits if a["action"] == "custom:licence-override"], "no override row where nothing blocks")
print("       log-only writes its would-block row and off writes nothing: no override row where nothing blocks")

# ======================================================================================================= 6. the scope is cleared, and is local to the thread
world("enforce")
with ml.override_scope(ADMIN, "reason"):
    must(ml.active_override() == (ADMIN, "reason"), "set inside")
    other = []
    worker = threading.Thread(target=lambda: other.append(ml.active_override()))
    worker.start()
    worker.join(5)
    must(other == [None], "another thread does not see it")
must(ml.active_override() is None, "cleared on success")
try:
    with ml.override_scope(ADMIN, "reason"):
        raise RuntimeError("boom")
except RuntimeError:
    pass
must(ml.active_override() is None, "cleared after an exception")
with ml.override_scope(ADMIN, None):
    must(ml.active_override() is None, "no reason, no scope")
# nested scopes restore the outer one
with ml.override_scope(ADMIN, "outer"):
    with ml.override_scope(ADMIN, "inner"):
        must(ml.active_override()[1] == "inner", "inner")
    must(ml.active_override()[1] == "outer", "outer restored")
must(ml.active_override() is None, "nothing left")
# a view whose work raises still clears it
v2views.queue_v2_install = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("queue failed"))
try:
    call("install", ADMIN, {FIELD: "reason"})
except RuntimeError:
    pass
must(ml.active_override() is None, "cleared when the view's work raised")
v2views.queue_v2_install = fake_install
print("       the scope is cleared after success and after an exception, restored when nested, and not seen by another thread")

# ======================================================================================================= 7. it does not carry from stage to install
world("enforce")
call("inspect", ADMIN, {FIELD: "stage anyway"})
must(len([a for a in H.audits if a["action"] == "custom:licence-override"]) == 1, "the stage wrote its row")
second = call("install", ADMIN, {})
must(second.status_code == 403 and second.data["code"] == "licensing_requirement_failed", "the install needs its own reason")
must(len([a for a in H.audits if a["action"] == "custom:licence-override"]) == 1, "no second row without a reason")
call("install", ADMIN, {FIELD: "install anyway"})
rows = [a for a in H.audits if a["action"] == "custom:licence-override"]
must(len(rows) == 2 and rows[1]["metadata"]["override_reason"] == "install anyway", [r["metadata"] for r in rows])
# and an ordinary request in the same thread afterwards is not overridden
must(call("repo", ADMIN, {}).status_code == 403, "the next request has no override")
print("       the override does not carry from stage to install, nor to the next request")

# ======================================================================================================= 8. a licensed module and a free module are untouched
world("enforce")
v2.get_capability = lambda *a, **k: SimpleNamespace(check_entitlement=lambda **kw: {"licensed": True})
response = call("install", ADMIN, {FIELD: "not needed"})
must(response.status_code == 202 and not H.audits, "an override that is not needed writes no row")
must(response.data["licensing"].get("overridden") is None, response.data)
print("       an override that is not needed is not recorded")

# ======================================================================================================= 9. source pins: the override lives in one function
APP = ROOT / "framwork" / "tec_tac"
sources = {path.name: path.read_text(encoding="utf-8") for path in APP.rglob("*.py")}


def names_in(text, wanted):
    return sorted({node.attr if isinstance(node, ast.Attribute) else node.id for node in ast.walk(ast.parse(text))
                   if (isinstance(node, ast.Attribute) and node.attr in wanted) or (isinstance(node, ast.Name) and node.id in wanted)})


users = sorted(name for name, text in sources.items() if names_in(text, {"active_override", "audit_override"}))
must(users == ["module_manager_v2.py"], users)  # module_licensing.py defines them; only the gate calls them
tree = ast.parse(sources["module_manager_v2.py"])
holders = sorted(fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef) and names_in(ast.get_source_segment(sources["module_manager_v2.py"], fn), {"active_override", "audit_override"}))
must(holders == ["_enforce_candidate_licensing"], holders)
# the trust, signature, compatibility, dependency and replacement checks never see the override
for name in ("module_manager.py", "module_replacement.py", "trusted_publishers.py", "trust_policy.py", "module_state.py", "registry.py"):
    must(name in sources and not any(token in sources[name] for token in ("active_override", "override_scope", "audit_override", "licence_override", "module_licensing")), f"{name} must not know the licence override")
v2_text = sources["module_manager_v2.py"]
enforce = ast.get_source_segment(v2_text, next(fn for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef) and fn.name == "_enforce_candidate_licensing"))
must(enforce.count("MODE_ENFORCE") >= 2 and "active_override() if mode == module_licensing.MODE_ENFORCE else None" in enforce, "the override applies in enforce only")
must("_verify_stage_trust" not in enforce and "version_satisfies" not in enforce and "resolve_install_plan" not in enforce, "the gate function does only the licence")
# only the three v2 views set a scope, and the v1 routes take none
scope_users = sorted(name for name, text in sources.items() if names_in(text, {"override_scope", "read_override"}))
must(scope_users == ["module_repository_views.py", "module_v2_views.py"], scope_users)
must("licence_override" not in sources["views.py"] and "override_scope" not in sources["views.py"], "the v1 routes take no override")
print("       source pin: the override is used only inside the licence gate; the v1 routes take none")
print("[TEST] PASS licensing override 1.17.58")
