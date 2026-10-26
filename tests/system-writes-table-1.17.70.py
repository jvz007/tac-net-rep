#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203, AD-45): the fixed function table gains one WRITE row, winupdate.set_action, and a module can only name its key.

The real system_actions.py and system_writes.py on the stub harness. Covered: the row exists with kind write, replacement_only, owner patching, the
single minimum flag can_manage_winupdates and the parameter schema allowed_actions; every earlier row keeps kind task and replacement_only False (the new
fields are defaulted, so no earlier row or module changes); a module cannot name a callable, a dotted path or an unknown key; a write row registered with
dangerous False is refused; a write row registered with delegable_to is refused; the parameter schema accepts a non-empty subset of approve, ignore and
nothing and refuses inherit, an unknown word, a duplicate, an empty list, a text instead of a list and any extra key; the audit and confirmation line of the
row name the decisions; the row's Tactical callable is the serializer the PUT uses (pinned excerpt of v1.5.2).
"""
from __future__ import annotations

from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

table = sa.SYSTEM_FUNCTIONS
row = table["winupdate.set_action"]
must(row.kind == "write" and row.replacement_only is True and row.owner_module == "patching", row)
must(tuple(row.min_flags) == ("can_manage_winupdates",) and row.takes_username is False and row.reapproves_by_policy is False, row)
must(tuple(row.parameters) == ("allowed_actions",) and row.accepts == "update_actions", row)
must((row.module_path, row.function_name) == ("winupdate.serializers", "WinUpdateSerializer"), "the row names the serializer Tactical's PUT uses (v1.5.2 winupdate/views.py EditWindowsUpdates.put)")
must("done" not in row.result_text.lower().split(), "an honest result text")
for key in ("winupdate.scan", "winupdate.install", "scripts.run"):
    must(table[key].kind == "task" and table[key].replacement_only is False and table[key].confirmation_line is None, key)
must(set(table) == {"winupdate.scan", "winupdate.install", "scripts.run", "winupdate.set_action", "agent.command"}, sorted(table))
must(sa.KIND_TASK == "task" and sa.KIND_WRITE == "write" and sa.WRITE_ACTIONS == ("approve", "ignore", "nothing"), "the kinds and the decisions")
print("       the row exists: write, replacement only, owner patching, one flag, allowed_actions; every earlier row stays a task")

# ---- a module names only the key
fresh(0)
for bad in ("winupdate.tasks.bulk_check_for_updates_task", "winupdate.serializers.WinUpdateSerializer", "winupdate.set_action ", "winupdate.setaction", "", None, 7, ["winupdate.set_action"]):
    try:
        sa.register_system_action("patchmanagement.other", "patchmanagement", "x", bad, WRITE_FLAGS, dangerous=True)
    except sa.SystemActionRegistrationError:
        continue
    raise AssertionError(f"accepted function {bad!r}")
must(not [a for a in sa.registered_system_actions() if a["id"] == "patchmanagement.other"], "nothing registered")
print("       a module cannot name a callable, a dotted path, an unknown key or a near miss")

# ---- dangerous and delegable_to
fresh(0)
sa._clear_for_tests()
for kw, why in ((dict(dangerous=False), "dangerous false"), (dict(), "dangerous default"), (dict(dangerous=True, delegable_to=["maintenance"]), "delegable_to set")):
    try:
        sa.register_system_action(WRITE, "patchmanagement", "x", "winupdate.set_action", WRITE_FLAGS, **kw)
    except sa.SystemActionRegistrationError:
        continue
    raise AssertionError(f"accepted: {why}")
must(sa.get_system_action(WRITE) is None, "nothing registered")
ok = sa.register_system_action(WRITE, "patchmanagement", "x", "winupdate.set_action", WRITE_FLAGS, dangerous=True, delegable_to=())
must(ok is not None and ok.dangerous is True and ok.delegable_to == () and ok.via_replacement is True, ok)
described = sa.get_system_action(WRITE)
must(described["kind"] == "write" and described["replacement_only"] is True and described["function"] == "winupdate.set_action" and described["warning"] is None, described)
must(sa.get_system_action("patching.scan") is None or sa.get_system_action("patching.scan")["kind"] == "task", "a task row describes as a task")
print("       a write row needs dangerous=True and an empty delegable_to")

# ---- the parameter schema
good = row.validate_parameters({"allowed_actions": ["ignore", "approve"]})
must(good == {"allowed_actions": ["approve", "ignore"]}, "canonical order")
must(row.validate_parameters({"allowed_actions": ["nothing"]}) == {"allowed_actions": ["nothing"]}, "one decision is fine")
must(row.validate_parameters({"allowed_actions": ("approve", "ignore", "nothing")}) == {"allowed_actions": ["approve", "ignore", "nothing"]}, "all three")
for value in (None, {}, [], "approve", {"allowed_actions": []}, {"allowed_actions": "approve"}, {"allowed_actions": ["inherit"]}, {"allowed_actions": ["approve", "inherit"]},
              {"allowed_actions": ["approve", "approve"]}, {"allowed_actions": ["Approve"]}, {"allowed_actions": [1]}, {"allowed_actions": ["approve"], "installed": True},
              {"allowed_actions": ["approve"], "extra": 1}, {"allowed_actions": ["approve", "ignore", "nothing", "approve"]}, {"allowed_actions": {"approve": 1}}):
    try:
        row.validate_parameters(value)
    except ValueError:
        continue
    raise AssertionError(f"accepted parameters {value!r}")
must(row.audit_extra(good) == {"allowed_actions": ["approve", "ignore"]}, "the audit extra names the decisions")
line = row.confirmation_line(good)
must("approve or ignore" in line and "Tactical keeps the decisions" in line and "audit log" in line and "changed in Tactical in the meantime" in line, line)
must("do nothing" in row.confirmation_line({"allowed_actions": ["approve", "ignore", "nothing"]}) and "approve, ignore or do nothing" in row.confirmation_line({"allowed_actions": ["approve", "ignore", "nothing"]}), "plain words")
print("       the schema takes a non-empty subset of approve, ignore and nothing and refuses inherit, extras and every bad shape; the line names the decisions")

# ---- the pinned excerpt of Tactical v1.5.2: PUT winupdate/<pk>/ saves through WinUpdateSerializer(partial=True), and the action column holds these four choices
excerpt = ROOT / ".." / ".." / "reference" / "tacticalrmm" / "api" / "tacticalrmm" / "winupdate"
if (excerpt / "views.py").is_file():
    views_src = (excerpt / "views.py").read_text(encoding="utf-8")
    must("class EditWindowsUpdates" in views_src and "WinUpdateSerializer(" in views_src and "partial=True" in views_src, "Tactical's PUT")
    models_src = (excerpt / "models.py").read_text(encoding="utf-8")
    must(all(f'("{c}"' in models_src for c in ("inherit", "approve", "ignore", "nothing")), "the four choices")
    print("       Tactical v1.5.2: PUT winupdate/<pk>/ saves through WinUpdateSerializer(partial=True); the four choices are inherit, approve, ignore and nothing")
else:
    print("       reference/tacticalrmm is not beside this folder: the v1.5.2 excerpt check is NOT RUN here")
print("PASS system writes table 1.17.70")
