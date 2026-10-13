#!/usr/bin/env python3
"""1.17.24 regression: only an effective superuser may change the system name (held Low of the 1.17.23 review).

Django is not installed on the development PC, so the real runtime_settings.py is loaded against the stubs of
tests/update-source-1.17.2.py. Covered: a holder of core.runtime_settings.manage is refused for a new name, for null and for a
mixed body; nothing is saved; one deny row (no value); the same person still changes the register timeout alone; a superuser
changes and resets the name with one strict row each; the upload-limit refusal writes one deny row too; GET stays open;
a failed deny write never turns the 403 into a 500.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "update-source-1.17.2.py"
source = HARNESS.read_text(encoding="utf-8")
marker = 'rs = load("runtime_settings")'
H = {"__file__": str(HARNESS), "__name__": "update_source_harness"}
exec(compile(source[: source.index(marker)], "update-source-1.17.2.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse of the 1.17.x harness
must, mods, load = H["must"], H["mods"], H["load"]
AUDITS, Config, CONFIG = H["AUDITS"], H["Config"], H["CONFIG"]
PermissionDenied = H["PermissionDenied"]

mods["tec_tac.rbac"].is_effective_superuser = lambda user: bool(getattr(user, "superuser", False))
mods["tec_tac.rbac"].can_manage_runtime_settings = lambda user: bool(
    getattr(user, "superuser", False) or getattr(user, "manage", False) or getattr(user, "privileged", False)
)
rs = load("runtime_settings")
CONFIG.system_name = "Tec-Tac"
CONFIG.tactical_operation_upload_max_mib = 10


def person(**rights):
    return types.SimpleNamespace(**{"username": "u", "superuser": False, "manage": False, "privileged": False, **rights})


def patch(body, who):
    return rs.RuntimeSettingsView().patch(types.SimpleNamespace(user=who, data=body))


def refused(body, who, message):
    saves = len(Config.saved)
    AUDITS.clear()
    try:
        patch(body, who)
    except PermissionDenied as exc:
        must(str(exc) == message, exc)
    else:
        raise AssertionError(f"{body!r} must be refused")
    must(len(Config.saved) == saves, "nothing saved")
    return list(AUDITS)


must(rs.SYSTEM_NAME_DENIED == "Only a Tec-Tac superuser may change the system name.", rs.SYSTEM_NAME_DENIED)
manager = person(manage=True)

# (1) a manager is refused for a name, for null and for a mixed body; config unchanged; one deny row, no value
for body in ({"system_name": "X"}, {"system_name": None}, {"system_name": "X", rs.SETTING_MODULE_REGISTER_TIMEOUT: 90}):
    rows = refused(body, manager, rs.SYSTEM_NAME_DENIED)
    must(CONFIG.system_name == "Tec-Tac" and CONFIG.module_register_timeout_seconds == 30, "config unchanged")
    must(len(rows) == 1, rows)
    row = rows[0]
    must(row["module_id"] == "core" and row["action"] == "deny" and row["object_type"] == "runtime_settings", row)
    must(row["object_id"] == "system_name" and row["metadata"] == {"reason": "superuser_required"} and row["strict"] is False, row)
    must("X" not in str(row.get("before")) and "X" not in str(row.get("after")) and not row.get("before") and not row.get("after"), row)

# (2) the same person still changes the register timeout alone
AUDITS.clear()
resp = patch({rs.SETTING_MODULE_REGISTER_TIMEOUT: 60}, manager)
must(resp.status_code == 200 and CONFIG.module_register_timeout_seconds == 60, resp.data)
must([r["object_id"] for r in AUDITS] == [rs.SETTING_MODULE_REGISTER_TIMEOUT] and AUDITS[0]["action"] == "modify", AUDITS)

# (3) a superuser changes and resets the name, one strict row each
for body, expected in (({"system_name": "Acme IT"}, "Acme IT"), ({"system_name": None}, "Tec-Tac")):
    AUDITS.clear()
    resp = patch(body, person(superuser=True))
    must(resp.status_code == 200 and CONFIG.system_name == expected, resp.data)
    must(len(AUDITS) == 1 and AUDITS[0]["action"] == "modify" and AUDITS[0]["strict"] is True and AUDITS[0]["object_id"] == "system_name", AUDITS)

# (4) the upload-limit refusal now writes one deny row and still raises UPLOAD_LIMIT_DENIED
rows = refused({rs.SETTING_TACTICAL_UPLOAD_MAX_MIB: 12}, manager, rs.UPLOAD_LIMIT_DENIED)
must(len(rows) == 1 and rows[0]["action"] == "deny" and rows[0]["object_id"] == rs.SETTING_TACTICAL_UPLOAD_MAX_MIB, rows)
must(CONFIG.tactical_operation_upload_max_mib == 10, "upload limit unchanged")
# both superuser-only keys: the upload refusal comes first, still one row
rows = refused({"system_name": "Z", rs.SETTING_TACTICAL_UPLOAD_MAX_MIB: 12}, manager, rs.UPLOAD_LIMIT_DENIED)
must(len(rows) == 1, rows)

# (5) a person with no right at all still gets the old message and no new row
rows = refused({"system_name": "X"}, person(), rs.RUNTIME_SETTINGS_DENIED)
must(rows == [], rows)

# (6) GET stays open for the non-superuser
resp = rs.RuntimeSettingsView().get(types.SimpleNamespace(user=manager))
must(resp.status_code == 200 and resp.data["system_name"]["value"] == "Tec-Tac", resp.data)

# (7) a failed deny write never turns the 403 into a 500
H["AUDIT_FAIL"]["on"] = True
try:
    patch({"system_name": "X"}, manager)
except PermissionDenied as exc:
    must(str(exc) == rs.SYSTEM_NAME_DENIED, exc)
else:
    raise AssertionError("must still be refused")
finally:
    H["AUDIT_FAIL"]["on"] = False

print("system name superuser 1.17.24: ok")
