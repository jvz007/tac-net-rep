#!/usr/bin/env python3
"""1.17.26 regression: the private mail relay setting (AD-30). Superuser only, strict bool, audited, fail-closed reader.

Django is not installed on the development PC, so the real runtime_settings.py is loaded against the stubs of
tests/update-source-1.17.2.py. Covered: a manager is refused with one deny row (no value) and nothing is saved; a mixed body is refused
whole; a person with no right at all gets the old message and no row; a superuser turns it on and off with one strict row each; the
same value writes no row; a number, text, null and a list are 400 and write nothing; GET shape {value, default, warning}; a failed audit
write raises (the row is written inside the transaction); a failed deny write never turns the 403 into a 500; the reader fails closed;
the reader is not in the public contract; the other settings are unchanged.
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
CONFIG.priority_mail_private_relay = False
KEY = "priority_mail_private_relay"


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


must(rs.PRIORITY_MAIL_PRIVATE_RELAY_DENIED == "Only a Tec-Tac superuser may change the private mail relay setting.", rs.PRIORITY_MAIL_PRIVATE_RELAY_DENIED)
must(KEY in rs.RUNTIME_SETTING_NAMES and rs.SETTING_PRIORITY_MAIL_PRIVATE_RELAY == KEY, "the key is a runtime setting")
manager = person(manage=True)

# (1) a manager is refused for true, false, null and a mixed body: one deny row, no value, nothing saved
for body in ({KEY: True}, {KEY: False}, {KEY: None}, {KEY: True, rs.SETTING_MODULE_REGISTER_TIMEOUT: 90}, {KEY: 1}):
    rows = refused(body, manager, rs.PRIORITY_MAIL_PRIVATE_RELAY_DENIED)  # checked before the value: even a bad value is 403, not 400
    must(CONFIG.priority_mail_private_relay is False and CONFIG.module_register_timeout_seconds == 30, "config unchanged")
    must(len(rows) == 1, rows)
    row = rows[0]
    must(row["module_id"] == "core" and row["action"] == "deny" and row["object_type"] == "runtime_settings", row)
    must(row["object_id"] == KEY and row["metadata"] == {"reason": "superuser_required"} and row["strict"] is False, row)
    must(not row.get("before") and not row.get("after"), "no value in the deny row")

# (2) no right at all: the old message, no row
must(refused({KEY: True}, person(), rs.RUNTIME_SETTINGS_DENIED) == [], "no row for a person with no right")

# (3) a superuser turns it on and off, one strict row each, before and after a bool
for value, before in ((True, False), (False, True)):
    AUDITS.clear()
    resp = patch({KEY: value}, person(superuser=True))
    must(resp.status_code == 200 and CONFIG.priority_mail_private_relay is value, resp.data)
    must(len(AUDITS) == 1, AUDITS)
    row = AUDITS[0]
    must(row["action"] == "modify" and row["strict"] is True and row["object_id"] == KEY and row["object_type"] == "runtime_settings", row)
    must(row["before"] == {KEY: before} and row["after"] == {KEY: value}, row)
    must(resp.data[KEY]["value"] is value, resp.data)

# (4) the same value writes no row and no save
saves = len(Config.saved)
AUDITS.clear()
resp = patch({KEY: False}, person(superuser=True))
must(resp.status_code == 200 and AUDITS == [] and len(Config.saved) == saves, (AUDITS, Config.saved))

# (5) not a bool: 400 and nothing written (the superuser passes the 403 gate first)
for bad in (1, 0, "true", "false", None, [True], {"a": 1}, 1.0):
    saves = len(Config.saved)
    AUDITS.clear()
    resp = patch({KEY: bad}, person(superuser=True))
    must(resp.status_code == 400 and "true or false" in resp.data["detail"], (bad, resp.data))
    must(AUDITS == [] and len(Config.saved) == saves and CONFIG.priority_mail_private_relay is False, bad)

# (6) GET shape, open to every signed-in user
resp = rs.RuntimeSettingsView().get(types.SimpleNamespace(user=manager))
entry = resp.data[KEY]
must(set(entry) == {"value", "default", "warning"} and entry["value"] is False and entry["default"] is False, entry)
must("private network" in entry["warning"] and "Priority 1" in entry["warning"], entry["warning"])
must(entry["warning"].isascii(), "plain text")

# (7) a failed strict audit write raises; the source writes the row inside the transaction, after the save
H["AUDIT_FAIL"]["on"] = True
try:
    try:
        patch({KEY: True}, person(superuser=True))
    except Exception:
        pass
    else:
        raise AssertionError("a failed strict audit write must raise")
finally:
    H["AUDIT_FAIL"]["on"] = False
src = Path(rs.__file__).read_text(encoding="utf-8")
must("with transaction.atomic():" in src and src.index("_audit_change(request.user, before, value, setting)") > src.index("config.save("), "audit inside the transaction")
CONFIG.priority_mail_private_relay = False

# (8) a failed deny write never turns the 403 into a 500
H["AUDIT_FAIL"]["on"] = True
try:
    patch({KEY: True}, manager)
except PermissionDenied as exc:
    must(str(exc) == rs.PRIORITY_MAIL_PRIVATE_RELAY_DENIED, exc)
else:
    raise AssertionError("must still be refused")
finally:
    H["AUDIT_FAIL"]["on"] = False

# (9) the reader fails closed
CONFIG.priority_mail_private_relay = True
must(rs.get_priority_mail_private_relay() is True, "on reads on")
for odd in (1, "true", None, [True], 0, "yes"):
    CONFIG.priority_mail_private_relay = odd
    must(rs.get_priority_mail_private_relay() is False, ("an odd stored value reads off", odd))
CONFIG.priority_mail_private_relay = True
H["CURRENT_FAILS"]["on"] = True
try:
    must(rs.get_priority_mail_private_relay() is False, "a database error reads off")
finally:
    H["CURRENT_FAILS"]["on"] = False
CONFIG.priority_mail_private_relay = False

# (10) the other settings still work and the reader is not a public Python contract row
resp = patch({rs.SETTING_MODULE_REGISTER_TIMEOUT: 45}, manager)
must(resp.status_code == 200 and CONFIG.module_register_timeout_seconds == 45, resp.data)
contracts = (Path(rs.__file__).parent / "contracts.py").read_text(encoding="utf-8")
must('"name": "get_priority_mail_private_relay"' not in contracts, "the reader is not a contract row")

print("[TEST] PASS runtime settings private relay 1.17.26")
