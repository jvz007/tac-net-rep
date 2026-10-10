#!/usr/bin/env python3
"""1.17.14 regression: the upload ceiling as a runtime setting (Johan CQ40, 9 October 2026). Validator, getter, serializer and PATCH.

``tactical_operation_upload_max_mib``: whole MiB, 1 to 25, default 10, on ``TecTacRuntimeConfig`` (migration 0026). GET returns
{value, minimum, maximum, default, bytes}. PATCH takes the module register timeout, the new key, or both. A body with only the old
key behaves as before. An empty body or an unknown key is a 400. The upload key is superuser only (the same rule as the update source,
CQ12), the timeout keeps core.runtime_settings.manage. Each changed setting writes its own strict audit row, object_id the setting
name. Same stub harness as tests/runtime-settings-permission-1.17.2.py (executed from it, so the two cannot drift).
"""
from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "runtime-settings-permission-1.17.2.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("GRANTS[1] = {NEW}")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
rs, rbac, CONFIG, GRANTS, User, PermissionDenied, must = (G[k] for k in ("rs", "rbac", "CONFIG", "GRANTS", "User", "PermissionDenied", "must"))
APP = G["APP"]
MIB = 2**20
UP = "tactical_operation_upload_max_mib"
TO = "module_register_timeout_seconds"

AUDIT = []
sys.modules["tec_tac.audit"].record = lambda **kw: AUDIT.append(kw)
SAVES = []
type(CONFIG).save = lambda self, update_fields=None: SAVES.append(list(update_fields or []))
CONFIG.tactical_operation_upload_max_mib = 10

GRANTS[1] = {"core.runtime_settings.manage"}
GRANTS[2] = {"core.privileged_operations"}
users = {
    "superuser": User(superuser=True),
    "role superuser": User(role_id=9, role_superuser=True),
    "manage": User(role_id=1),
    "privileged": User(role_id=2),
    "nobody": User(role_id=3),
}


def reset():
    CONFIG.module_register_timeout_seconds = 30
    CONFIG.tactical_operation_upload_max_mib = 10
    del AUDIT[:], SAVES[:]


def patch(who, data):
    return rs.RuntimeSettingsView().patch(types.SimpleNamespace(user=users[who], data=data))


def denied(who, data):
    try:
        patch(who, data)
    except PermissionDenied as exc:
        return str(exc)
    raise AssertionError(f"{who} was not refused: {data}")


# ------------------------------------------------------------------------------------------------ validator
must(rs.DEFAULT_TACTICAL_UPLOAD_MAX_MIB == 10 and rs.MIN_TACTICAL_UPLOAD_MAX_MIB == 1 and rs.MAX_TACTICAL_UPLOAD_MAX_MIB == 25, "constants")
must(rs.SETTING_TACTICAL_UPLOAD_MAX_MIB == UP, "the key")
for good in (1, 2, 10, 15, 24, 25):
    must(rs.validate_tactical_upload_max_mib(good) == good, good)
for bad in (True, False, 10.0, 10.5, "10", "", None, 0, -1, 26, 100, [10], {"v": 10}):
    try:
        rs.validate_tactical_upload_max_mib(bad)
    except rs.RuntimeSettingsError as exc:
        must(UP in str(exc), (bad, str(exc)))
    else:
        raise AssertionError(f"accepted {bad!r}")

# ------------------------------------------------------------------------------------------------ getter: never raises, falls back to 10 MiB
reset()
must(rs.get_tactical_upload_max_bytes() == 10 * MIB, "default")
CONFIG.tactical_operation_upload_max_mib = 15
must(rs.get_tactical_upload_max_bytes() == 15 * MIB, "stored 15")
for odd in (0, 26, 10**9, None, "x"):
    CONFIG.tactical_operation_upload_max_mib = odd
    must(rs.get_tactical_upload_max_bytes() == 10 * MIB, f"a stored {odd!r} reads as the default")
CONFIG.tactical_operation_upload_max_mib = 10
saved = rs.TecTacRuntimeConfig.current
rs.TecTacRuntimeConfig.current = classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("db down")))
must(rs.get_tactical_upload_max_bytes() == 10 * MIB, "a database error reads as the default")
rs.TecTacRuntimeConfig.current = saved
# an existing row that predates the column reads as 10 (the model default, migration 0026)
del CONFIG.tactical_operation_upload_max_mib
must(rs.get_tactical_upload_max_bytes() == 10 * MIB, "a row with no value reads as 10")
CONFIG.tactical_operation_upload_max_mib = 10

# ------------------------------------------------------------------------------------------------ GET
reset()
view = rs.RuntimeSettingsView()
body = view.get(types.SimpleNamespace(user=users["nobody"])).data
must(body[UP] == {"value": 10, "minimum": 1, "maximum": 25, "default": 10, "bytes": 10 * MIB}, body[UP])
must(body[TO]["value"] == 30 and body[TO]["default"] == 30, "the old key is unchanged")
CONFIG.tactical_operation_upload_max_mib = 15
must(view.get(types.SimpleNamespace(user=users["nobody"])).data[UP]["bytes"] == 15 * MIB, "bytes follow the value")
CONFIG.tactical_operation_upload_max_mib = 99  # a bad stored value is shown as what the executor uses
must(view.get(types.SimpleNamespace(user=users["nobody"])).data[UP]["value"] == 10, "out of range reads as the default")

# ------------------------------------------------------------------------------------------------ PATCH: the old key, exactly as before
reset()
for who in ("superuser", "role superuser", "manage", "privileged"):
    reset()
    answer = patch(who, {TO: 60})
    must(answer.status_code == 200 and CONFIG.module_register_timeout_seconds == 60 and CONFIG.tactical_operation_upload_max_mib == 10, who)
    must(len(AUDIT) == 1 and AUDIT[0]["object_id"] == TO and AUDIT[0]["before"] == {TO: 30} and AUDIT[0]["after"] == {TO: 60} and AUDIT[0]["strict"] is True, AUDIT)
    must(answer.data[UP]["value"] == 10, "the answer carries both settings")
reset()
denied("nobody", {TO: 60})
must(CONFIG.module_register_timeout_seconds == 30 and not AUDIT, "refused: nothing changed")
for bad in (True, 60.5, "60", None, 4, 301):
    answer = patch("manage", {TO: bad})
    must(answer.status_code == 400 and TO in answer.data["detail"] and not AUDIT and CONFIG.module_register_timeout_seconds == 30, (bad, answer.data))
reset()
patch("manage", {TO: 30})
must(not AUDIT and not SAVES, "no change, no audit row, no save")

# ------------------------------------------------------------------------------------------------ PATCH: the upload key
reset()
for who in ("superuser", "role superuser"):
    reset()
    answer = patch(who, {UP: 20})
    must(answer.status_code == 200 and CONFIG.tactical_operation_upload_max_mib == 20 and CONFIG.module_register_timeout_seconds == 30, who)
    must(answer.data[UP] == {"value": 20, "minimum": 1, "maximum": 25, "default": 10, "bytes": 20 * MIB}, answer.data[UP])
    must(len(AUDIT) == 1 and AUDIT[0]["object_id"] == UP and AUDIT[0]["before"] == {UP: 10} and AUDIT[0]["after"] == {UP: 20}
         and AUDIT[0]["module_id"] == "core" and AUDIT[0]["object_type"] == "runtime_settings" and AUDIT[0]["strict"] is True, AUDIT)
    must(SAVES == [[UP, "updated_by", "updated_at"]], SAVES)
# the permission split: manage, privileged and nobody are refused for the upload key, and nothing changes
for who in ("manage", "privileged", "nobody"):
    reset()
    message = denied(who, {UP: 20})
    must("superuser" in message and "upload" in message if who != "nobody" else "core.runtime_settings.manage" in message, message)
    must(CONFIG.tactical_operation_upload_max_mib == 10 and not AUDIT and not SAVES, who)
    # sending both keys is refused as a whole: the timeout is not changed either
    denied(who, {TO: 90, UP: 20})
    must(CONFIG.module_register_timeout_seconds == 30 and CONFIG.tactical_operation_upload_max_mib == 10 and not AUDIT, who)
# a non-superuser gets 403 and never 400, even for a bad value
reset()
denied("manage", {UP: "lots"})
denied("manage", {UP: 99})
# a superuser with a bad value gets 400 and nothing changes
for bad in (True, 10.5, "20", None, 0, 26, -3, [20]):
    reset()
    answer = patch("superuser", {UP: bad})
    must(answer.status_code == 400 and UP in answer.data["detail"] and CONFIG.tactical_operation_upload_max_mib == 10 and not AUDIT, (bad, answer.data))
# both keys at once: each changed setting writes its own audit row, in one save
reset()
answer = patch("superuser", {TO: 90, UP: 25})
must(answer.status_code == 200 and CONFIG.module_register_timeout_seconds == 90 and CONFIG.tactical_operation_upload_max_mib == 25, answer.data)
must(sorted(row["object_id"] for row in AUDIT) == sorted([TO, UP]) and len(AUDIT) == 2, AUDIT)
must(len(SAVES) == 1 and set(SAVES[0]) == {TO, UP, "updated_by", "updated_at"}, SAVES)
# one key changed and one not: one row
reset()
CONFIG.module_register_timeout_seconds = 90
patch("superuser", {TO: 90, UP: 12})
must([row["object_id"] for row in AUDIT] == [UP], AUDIT)
# a bad value in one key changes neither
reset()
answer = patch("superuser", {TO: 90, UP: 99})
must(answer.status_code == 400 and CONFIG.module_register_timeout_seconds == 30 and CONFIG.tactical_operation_upload_max_mib == 10 and not AUDIT, answer.data)
answer = patch("superuser", {TO: "soon", UP: 12})
must(answer.status_code == 400 and CONFIG.tactical_operation_upload_max_mib == 10 and not AUDIT, answer.data)
# the same value as now: no audit row
reset()
patch("superuser", {UP: 10})
must(not AUDIT and not SAVES, "no change")
# an empty body and an unknown key are 400
for data in ({}, {"nope": 1}, {UP: 12, "nope": 1}, {TO: 60, "extra": True}):
    reset()
    answer = patch("superuser", data)
    must(answer.status_code == 400 and not AUDIT and CONFIG.tactical_operation_upload_max_mib == 10, (data, answer.data))
must("Unknown runtime setting" in patch("superuser", {"nope": 1}).data["detail"], "unknown key text")
must(TO in patch("superuser", {}).data["detail"] and UP in patch("superuser", {}).data["detail"], "an empty body names both settings")
must(patch("superuser", ["list"]).status_code == 400 and patch("superuser", "x").status_code == 400, "not an object")

# ------------------------------------------------------------------------------------------------ the model, the migration, the text
models_src = (APP / "models.py").read_text(encoding="utf-8")
must("tactical_operation_upload_max_mib = models.PositiveIntegerField(default=10)" in models_src, "model field")
migration = APP / "migrations" / "0026_runtime_upload_limit.py"
tree = ast.parse(migration.read_text(encoding="utf-8"))
text = migration.read_text(encoding="utf-8")
must('("tec_tac", "0025_runtime_update_sources")' in text and 'name="tactical_operation_upload_max_mib"' in text and "default=10" in text, "migration 0026 follows 0025, adds the column with default 10")
must(sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree)) == 1, "one migration class")
must(not any(p.name.startswith("0027") for p in (APP / "migrations").iterdir()), "no later migration yet")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for needle in (UP, "superuser", "1.17.14"):
    must(needle in contracts, f"the runtime-settings contract entry lacks {needle!r}")

print("[TEST] PASS runtime settings upload 1.17.14")
