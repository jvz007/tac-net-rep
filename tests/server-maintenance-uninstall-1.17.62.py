#!/usr/bin/env python3
"""1.17.62 regression (R-23, held Medium from the 1.17.18 review): the root helper keeps no runnable path for a surviving hand registration
after its module is uninstalled.

``--unregister-module`` deleted the module's own executable but left an administrator's hand registration (and the protected Tactical
Updater actions) as it was: enabled, with no hash. A later package under the same module id could then put a file at that path and the
registration would run it, without the administrator opting in again. Now a surviving hand registration is kept on disk but marked
``enabled: false`` with ``disabled_reason: module removed`` (plus the module and a time). Dispatch and run refuse it with that sentence, and
it is never runnable again until the administrator registers it again knowingly.

Uses the harness of tests/server-maintenance-module-actions-1.17.17.py (the helper runs against a fake file ownership layer; the root
helper, systemd and sudo cannot run on this PC; the real thing is tests/server-maintenance-uninstall-runtime-1.17.62.sh on the dev server).
Covered: a hand registration owned by the module, one whose executable lies under the module's folder (owner or not), and a protected one
are disabled and flagged and nothing else about them changes; a registration that belongs to nobody (an ownerless one with its own
executable) and another module's are untouched; manifest registrations are removed as before; load_action (the one door of dispatch and run)
refuses the flagged registration with the sentence, even though its executable is gone, and even after a later package puts a file at the
same path; a second unregister changes nothing; an administrator's own disabled registration is left as it is; registering again knowingly
makes it runnable; the audit row carries the action and the module only; the manifest has no allow-list of keys added; the install path
and register-module are unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE_TEST = Path(__file__).resolve().parent / "server-maintenance-module-actions-1.17.17.py"
source = BASE_TEST.read_text(encoding="utf-8")
cut = source.index("\ntry:\n    # ---- the owner and mode rule on its own")
H = {"__name__": "sm_harness", "__file__": str(BASE_TEST)}
exec(compile(source[:cut], str(BASE_TEST), "exec"), H)  # noqa: S102 - the shared test harness, not user input
sm, must, ROOT = H["sm"], H["must"], H["ROOT"]
REG, ACT, EXT = H["REG"], H["ACT"], H["EXT"]
action, manifest, put_module, reg_file, reg_json, fails = (H[k] for k in ("action", "manifest", "put_module", "reg_file", "reg_json", "fails"))
audit_events = H["audit_events"]
import json

real_chown = H["_real"]["chown"]
REASON = "module removed"


def hand(action_id, executable, **over):
    """An administrator's registration: no registered_by, no hash."""
    payload = {"id": action_id, "revision": "1", "executable": str(executable), "argv": [], "parameters": {}, "timeout_seconds": 5,
               "success_exit_codes": [0], "enabled": True, "permission": "vendor.rotate"}
    payload.update(over)
    reg_file(action_id).write_text(json.dumps(payload), encoding="utf-8")
    return payload


def flagged(action_id, original, module="vendor"):
    got = dict(reg_json(action_id))
    stamp = got.pop("disabled_at", None)
    want = {**original, "enabled": False, "disabled_reason": REASON, "disabled_module": module}
    return got == want and isinstance(stamp, str) and stamp


try:
    OTHER_EXE = ACT / "somebody-elses-program"
    OTHER_EXE.write_bytes(b"#!/bin/sh\n")

    # ---- a module with its own actions and four kinds of hand registration
    put_module("vendor", manifest([action(), action("vendor.other", "sub/other.sh", permission="vendor.other")]), files=("rotate.sh", "sub/other.sh"))
    sm.register_module("vendor")
    must(reg_json("vendor.rotate")["registered_by"] == "module-manifest", "the module's own action")
    under = ACT / "vendor" / "hand-copy"  # a hand registration that points into the module's own folder (as the protected Tactical Updater ones do)
    under.write_bytes(b"#!/bin/sh\n")
    owned_elsewhere = hand("vendor.owned", OTHER_EXE, owner_module="vendor")
    under_owned = hand("vendor.under", under, owner_module="vendor")
    under_ownerless = hand("vendor.protected", under, permission="vendor.danger")  # no owner_module at all, but it runs a file under the module's folder
    ownerless_own_exe = hand("vendor.ownerless", OTHER_EXE)  # an administrator's own program, nothing to do with the module
    other_module = hand("other.manual", OTHER_EXE, owner_module="other")
    for action_id in ("vendor.owned", "vendor.under", "vendor.protected", "vendor.ownerless", "other.manual"):
        must(sm.load_action(action_id)["id"] == action_id, f"{action_id} runs before the uninstall")

    # ---- uninstall
    sm.unregister_module("vendor")
    must(not reg_file("vendor.rotate").exists() and not reg_file("vendor.other").exists() and not (ACT / "vendor").exists(), "manifest registrations and the folder are removed as before")
    must(flagged("vendor.owned", owned_elsewhere), reg_json("vendor.owned"))
    must(flagged("vendor.under", under_owned), reg_json("vendor.under"))
    must(flagged("vendor.protected", under_ownerless), reg_json("vendor.protected"))
    must(reg_json("vendor.ownerless") == ownerless_own_exe and reg_json("other.manual") == other_module, "an administrator's own program and another module's registration are untouched")
    must(OTHER_EXE.is_file(), "the administrator's own executable is never touched")
    print("       the module's own actions are removed; a hand registration owned by the module, or running a file under its folder, is kept but disabled and flagged")

    # ---- dispatch and run read the registration through load_action: refused with the sentence, even though the path is gone
    for action_id in ("vendor.owned", "vendor.under", "vendor.protected"):
        fails(lambda a=action_id: sm.load_action(a), "module removed")
    fails(lambda: sm.load_action("vendor.under"), "has to register it again")
    must(sm.load_action("vendor.ownerless")["id"] == "vendor.ownerless" and sm.load_action("other.manual")["id"] == "other.manual", "the untouched ones still run")
    print("       load_action, the one door of dispatch and run, refuses a flagged registration with 'module removed', although its executable is gone")

    # ---- a later package under the same module id cannot fill the path and run it
    put_module("vendor", manifest([action("vendor.fresh", "rotate.sh")]), files=("rotate.sh", "hand-copy"))  # even a package that ships a file of that name
    sm.register_module("vendor")
    must((ACT / "vendor" / "rotate.sh").is_file() and reg_json("vendor.fresh")["registered_by"] == "module-manifest", "the new package registers its own action")
    (ACT / "vendor" / "hand-copy").write_bytes(b"#!/bin/sh\necho from-the-new-package\n")  # the path of the old hand registration is filled again
    for action_id in ("vendor.under", "vendor.protected", "vendor.owned"):
        fails(lambda a=action_id: sm.load_action(a), "module removed")
    must(flagged("vendor.under", under_owned) and flagged("vendor.protected", under_ownerless), "and the registrations are still flagged after the new install")
    print("       a later package under the same module id cannot fill the path and run the old registration")

    # ---- an upgrade (register-module) does not flag anything; only an uninstall does
    put_module("vendor", manifest([action("vendor.fresh", "rotate.sh")], version="1.3.0"), files=("rotate.sh",))
    sm.register_module("vendor")
    must(flagged("vendor.under", under_owned), "the flag stays through an upgrade (it never lifts by itself)")

    # ---- a second uninstall changes nothing (the time stamp is not rewritten)
    before = {a: reg_json(a) for a in ("vendor.owned", "vendor.under", "vendor.protected")}
    sm.unregister_module("vendor")
    sm.unregister_module("vendor")
    must(not reg_file("vendor.fresh").exists(), "the second package's own action is removed")
    must({a: reg_json(a) for a in before} == before, "flagging is idempotent: the file and its time stamp do not change")
    audit = [e for e in audit_events() if e["event"] == "action.disabled_module_removed"]
    must(sorted(e["detail"]["action"] for e in audit) == ["vendor.owned", "vendor.protected", "vendor.under"], audit)
    must(all(set(e["detail"]) == {"action", "module"} and e["detail"]["module"] == "vendor" for e in audit), "the row carries the action and the module only")
    last = [e for e in audit_events() if e["event"] == "module.actions_unregistered"][-1]
    must(last["detail"]["module"] == "vendor" and set(last["detail"]) == {"module", "actions", "disabled"}, last)
    print("       a second uninstall flags nothing again; one audit row per flagged registration, naming the action and the module only")

    # ---- a registration the administrator disabled already is left as it is
    admin_off = hand("vendor.adminoff", OTHER_EXE, owner_module="vendor", enabled=False)
    sm.unregister_module("vendor")
    must(reg_json("vendor.adminoff") == admin_off, "an administrator's own disabled registration is not rewritten")
    fails(lambda: sm.load_action("vendor.adminoff"), "registered action is disabled")
    try:
        sm.load_action("vendor.adminoff")
    except RuntimeError as exc:
        must("module removed" not in str(exc), "and its message does not claim a reason it does not have")

    # ---- registering again knowingly makes it runnable (a fresh file replaces the flagged one)
    manifest_file = H["BASE"] / "reregister.json"
    manifest_file.write_text(json.dumps(under_owned | {"executable": str(OTHER_EXE)}), encoding="utf-8")
    sm.register_manifest(manifest_file)
    again = reg_json("vendor.under")
    must(again["enabled"] is True and "disabled_reason" not in again and "disabled_at" not in again, again)
    must(sm.load_action("vendor.under")["id"] == "vendor.under", "an administrator who registers it again knowingly can run it")
    print("       an administrator's own disabled registration is not rewritten; registering again knowingly replaces the flagged file and runs")

    # ---- a registry file that is a symlink is never read or rewritten
    link_target = hand("vendor.linked", OTHER_EXE, owner_module="vendor")
    linked_text = reg_file("vendor.linked").read_text(encoding="utf-8")
    real_is_symlink = Path.is_symlink
    Path.is_symlink = lambda self: self.name == "vendor.linked.json" or real_is_symlink(self)
    try:
        sm.unregister_module("vendor")
    finally:
        Path.is_symlink = real_is_symlink
    must(reg_file("vendor.linked").read_text(encoding="utf-8") == linked_text, "a symlinked registry file is left alone")
    must(link_target["enabled"] is True, "and it is not flagged through the link")
    print("       a registry file that is a symlink is never read or rewritten")

    # ---- another module's flow is not touched, and a module with nothing to flag is a plain uninstall
    put_module("clean", manifest([action("clean.run", "run.sh", permission="clean.run")], id="clean", permission_groups={"Clean": ["clean.run"]}), files=("run.sh",))
    sm.register_module("clean")
    sm.unregister_module("clean")
    must(not reg_file("clean.run").exists() and reg_json("other.manual") == other_module and reg_json("vendor.ownerless") == ownerless_own_exe, "nothing else moved")
finally:
    if real_chown is not None:
        H["os"].chown = real_chown
    H["os"].chmod = H["_real"]["chmod"]

# ---- the source: what the code does, and what it does not add
helper = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
body = helper.split("def _disable_surviving_hand_registrations", 1)[1].split("\ndef unregister_module", 1)[0]
for needle in ('payload.get("registered_by") == "module-manifest"', 'payload["enabled"] = False', 'payload["disabled_reason"] = MODULE_REMOVED_REASON',
               "_write_root_file(path", 'append_audit("action.disabled_module_removed"', "_under_module_folder(payload.get(\"executable\"), module_id)"):
    must(needle in body, needle)
must("unlink" not in body and "rmtree" not in body, "flagging deletes nothing")
load = helper.split("def load_action", 1)[1].split("\ndef ", 1)[0]
must(load.index("_disabled_message(payload)") < load.index("validate_manifest(payload)"), "the disabled check runs before the executable is looked at")
must("verify_registered_executable_hash(manifest)" in load, "the SHA-256 recheck at dispatch and run stays")
dispatch_run = helper.split("def dispatch(", 1)[1] + helper.split("def run_job(", 1)[1]
must(dispatch_run.count("load_action(") >= 2, "dispatch and run both go through load_action")
must('MODULE_ACTION_KEYS = frozenset({"id", "description", "permission", "executable", "argv", "parameters", "timeout_seconds", "success_exit_codes", "revision", "protected"})' in helper,
     "no manifest key was added")
for name in ("module-job-helper.py", "module-v2-job-helper.py"):
    text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    must("disabled_reason" not in text and "module removed" not in text and "action_allow" not in text, f"{name} keeps no allow-list and needs no change")
must("ALLOWED_MANIFEST_KEYS" not in helper and "allow_list" not in helper.lower(), "the root helper keeps no allow-list of manifest keys")
sm_core = (ROOT / "framwork" / "tec_tac" / "server_maintenance.py").read_text(encoding="utf-8")
must("its module was removed. An administrator has to register it again." in sm_core and '"disabled_reason": MODULE_REMOVED_REASON' in sm_core, "Core says why in start() and list_actions()")
docs = (ROOT / "docs" / "server-maintenance-capability.md").read_text(encoding="utf-8")
for needle in ("Since 1.17.62 (R-23)", "module removed", "register-protected-actions.sh", "never runnable again until the administrator registers it again knowingly"):
    must(needle in docs, needle)
print("       the code deletes nothing, checks the flag before the executable and keeps the SHA-256 recheck; no allow-list, no new manifest key; Core and the docs say what an administrator sees")

print("[TEST] PASS server maintenance uninstall 1.17.62")
