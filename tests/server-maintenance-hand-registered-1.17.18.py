#!/usr/bin/env python3
"""1.17.18 regression (held Medium from the 1.17.17 review; CQ54): removing a module's server-maintenance actions never deletes an
administrator's hand registration.

``--unregister-module`` and the stale-action sweep of ``--register-module`` used to delete every registry file whose ``owner_module`` was
the module, which also removed an action an administrator registered by hand with that owner (a protected one included). Now only files
the helper itself wrote (``registered_by`` is ``module-manifest``) are removed. Also checks the held Low: the text about a hotfix
agrees with the code (a hotfix does not change the registered copy; the copy keeps running until the module is installed again).

Uses the harness of tests/server-maintenance-module-actions-1.17.17.py (the helper runs against fake file ownership; the root helper,
systemd and sudo cannot run on this PC).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE_TEST = Path(__file__).resolve().parent / "server-maintenance-module-actions-1.17.17.py"
source = BASE_TEST.read_text(encoding="utf-8")
cut = source.index("\ntry:\n    # ---- the owner and mode rule on its own")
H = {"__name__": "sm_harness", "__file__": str(BASE_TEST)}
exec(compile(source[:cut], str(BASE_TEST), "exec"), H)
sm, must, ROOT = H["sm"], H["must"], H["ROOT"]
REG, ACT, EXT = H["REG"], H["ACT"], H["EXT"]
action, manifest, put_module, reg_file, reg_json, norm = (H[k] for k in ("action", "manifest", "put_module", "reg_file", "reg_json", "norm"))
audit_events = H["audit_events"]
import json  # noqa: E402

real_chown = H["_real"]["chown"]
try:
    HAND_EXE = ACT / "hand-made"
    HAND_EXE.write_bytes(b"#!/bin/sh\n")

    def hand(action_id, **over):
        """An administrator's registration: an owner_module, no registered_by, no hash."""
        payload = {"id": action_id, "revision": "1", "executable": str(HAND_EXE), "argv": [], "parameters": {}, "timeout_seconds": 5,
                   "success_exit_codes": [0], "enabled": True, "owner_module": "vendor", "permission": "vendor.rotate"}
        payload.update(over)
        reg_file(action_id).write_text(json.dumps(payload), encoding="utf-8")
        return payload

    # ---- the module registers its own actions; an administrator also registered two by hand with the same owner
    put_module("vendor", manifest([action(), action("vendor.other", "sub/other.sh", permission="vendor.other")]), files=("rotate.sh", "sub/other.sh"))
    sm.register_module("vendor")
    must(reg_json("vendor.rotate")["registered_by"] == "module-manifest", "the module's own action")
    keep_plain = hand("vendor.manual", permission="vendor.rotate")
    keep_protected = hand("vendor.danger", permission="vendor.danger")  # a protected action, registered by hand
    # a hand registration whose payload names no owner is never the module's
    hand("vendor.ownerless", owner_module=None)

    # ---- a re-register that no longer lists anything removes only the module's own
    put_module("vendor", manifest([action()], version="1.3.0"), files=("rotate.sh",))
    sm.register_module("vendor")
    must(not reg_file("vendor.other").exists(), "the manifest-registered action the manifest dropped is removed")
    must(reg_json("vendor.manual") == keep_plain and reg_json("vendor.danger") == keep_protected, "hand registrations survive a re-register")
    put_module("vendor", manifest(None, server_maintenance_actions=None), files=("rotate.sh",))
    sm.register_module("vendor")
    must(not reg_file("vendor.rotate").exists(), "with no actions declared the module's own are gone")
    must(reg_json("vendor.manual") == keep_plain and reg_json("vendor.danger") == keep_protected, "and the hand registrations still stay")

    # ---- --unregister-module removes the module's own, never a hand registration (protected ones included)
    put_module("vendor", manifest(), files=("rotate.sh",))
    sm.register_module("vendor")
    must(reg_file("vendor.rotate").is_file() and (ACT / "vendor" / "rotate.sh").is_file(), "registered again")
    sm.unregister_module("vendor")
    must(not reg_file("vendor.rotate").exists() and not (ACT / "vendor").exists(), "a module-manifest action and its folder are removed")
    must(reg_json("vendor.manual") == keep_plain, "a hand registration with owner_module survives --unregister-module")
    must(reg_json("vendor.danger") == keep_protected, "a protected hand registration survives --unregister-module")
    must(reg_file("vendor.ownerless").is_file() and HAND_EXE.is_file(), "an ownerless hand registration and its executable survive")
    events = audit_events()
    removed = [e["detail"]["action"] for e in events if e["event"] == "action.unregistered"]
    must("vendor.manual" not in removed and "vendor.danger" not in removed, removed)
    last = [e for e in events if e["event"] == "module.actions_unregistered"][-1]
    must(last["detail"]["actions"] == ["vendor.rotate"], last)
    # nothing to remove, a second call: harmless
    sm.unregister_module("vendor")
    must(reg_json("vendor.manual") == keep_plain, "still there")

    # ---- a hand registration that is later re-registered by the module becomes the module's (the migration path is unchanged)
    put_module("vendor", manifest([action("vendor.manual", permission="vendor.rotate")]), files=("rotate.sh",))
    sm.register_module("vendor")
    must(reg_json("vendor.manual")["registered_by"] == "module-manifest", "replaced by the module's registration")
    sm.unregister_module("vendor")
    must(not reg_file("vendor.manual").exists(), "and then it is the module's to remove")
    must(reg_json("vendor.danger") == keep_protected, "the protected hand registration is still untouched")

    # ---- a protected manifest entry: an earlier module-registered file is dropped, a hand one stays (unchanged from 1.17.17)
    put_module("vendor", manifest([action(), action("vendor.late", "danger.sh", permission="vendor.danger")]), files=("rotate.sh", "danger.sh"))
    sm.register_module("vendor")
    must(reg_json("vendor.late")["registered_by"] == "module-manifest", "registered")
    put_module("vendor", manifest([action(), action("vendor.late", "danger.sh", permission="vendor.danger", protected=True)]), files=("rotate.sh", "danger.sh"))
    sm.register_module("vendor")
    must(not reg_file("vendor.late").exists(), "now protected: the module's earlier registration is dropped")
    sm.unregister_module("vendor")

    # ---- another module's actions are untouched, as before
    put_module("other", manifest([action("other.run", "run.sh", permission="other.run")], id="other", permission_groups={"Other": ["other.run"]}), files=("run.sh",))
    sm.register_module("other")
    hand("other.manual", owner_module="other")
    sm.unregister_module("other")
    must(not reg_file("other.run").exists() and reg_file("other.manual").is_file(), "the same rule for every module")
finally:
    if real_chown is not None:
        H["os"].chown = real_chown
    H["os"].chmod = H["_real"]["chmod"]

# ---- the source: the sweep checks registered_by, and the text says what the code does
helper = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
body = helper.split("def _remove_owned_actions", 1)[1].split("def register_module", 1)[0]
must('payload.get("registered_by") != "module-manifest"' in body, "the sweep skips anything the module did not register")
docs = (ROOT / "docs" / "server-maintenance-capability.md").read_text(encoding="utf-8")
must("hand registration" in docs and "registered_by" in docs and "never removes" in docs, "docs state the rule")
# held Low (core-1.17.17-1): a hotfix does not change the registered copy, and the text no longer says the action stops
contracts = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for name, text in (("contracts.py", contracts), ("docs", docs), ("helper docstring", helper)):
    must("the action stops until the module is installed again" not in text and "so the hash fails and the action stops" not in text, f"{name}: the stale claim is gone")
    must("keeps running" in text, f"{name}: says the registered copy keeps running")
must("A hotfix does not change the registered copy" in contracts and "A hotfix does not change the registered copy" in docs, "same wording in the contract and the docs")
# the code agrees: the hash is of the root-owned copy, and the hotfix helper never re-registers
must('_sha256_nofollow(Path(manifest["executable"]))' in helper, "the hash check reads the registered (root-owned) copy")
hotfix = (ROOT / "scripts" / "module-hotfix-job-helper.py").read_text(encoding="utf-8")
must("server-maintenance" not in hotfix and "register_module" not in hotfix and "register-module" not in hotfix, "a hotfix never re-registers")

print("[TEST] PASS server maintenance hand registrations 1.17.18")
