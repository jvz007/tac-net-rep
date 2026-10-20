#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (CQ179 b): an administrator can list schedules by creator and confirmer, and that adds no right.

Django and DRF are not installed on the development PC, so the filter functions of scheduler_views.py are compiled out of the real file (ast)
and run against the real ``schedule_creator_names``; the view's wiring, the serializer, create and edit are read as source. Covered: the
filter matches the stored creator or confirmer name exactly and without regard to case; an unknown name matches nothing; a row made before
migration 0036 matches by the creator row's user name; no filter keeps every row; the filter runs inside the list loop before the permission
and scope test and only ever removes a row; no permission code or role helper was added (the scheduler has no code in rbac, and the count of
permission calls in scheduler_views.py is the 1.17.62 count); the serialized schedule keeps every earlier key and adds the two names; create
stores the signed-in person as creator and confirmer, edit sets the editor as confirmer after the unchanged permission and scope checks.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

VIEWS = (APP / "scheduler_views.py").read_text(encoding="utf-8")
tree = ast.parse(VIEWS)
wanted = {"_name_filter", "_name_filters_match", "_person_name"}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
must({n.name for n in nodes} == wanted, [n.name for n in nodes])
ns = {"schedule_creator_names": sched.schedule_creator_names, "MAX_NAME_FILTER": 150}
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)
exec(compile(module, "scheduler_views.py", "exec"), ns)  # noqa: S102 - the real functions of the real file
match_ = ns["_name_filters_match"]


def row(creator="", confirmed="", user=None):
    return SimpleNamespace(created_by_username=creator, confirmed_by_username=confirmed, created_by=SimpleNamespace(username=user) if user else None)


alice_row, bob_row, old_row, none_row = row("alice", "bob"), row("bob", "bob"), row("", "", user="Carol"), row("", "")
ALL = [alice_row, bob_row, old_row, none_row]


def listed(created=None, confirmed=None):
    return [r for r in ALL if match_(r, created, confirmed)]


must(listed() == ALL, "no filter: every row")
must(listed("alice") == [alice_row] and listed("bob") == [bob_row], "the stored creator name, exactly")
must(listed("ALICE") == [alice_row] and listed("Alice") == [alice_row], "case-insensitive")
must(listed("al") == [] and listed("alice ") == [] and listed("alic") == [], "exact, never a prefix")
must(listed("carol") == [old_row], "a row made before 0036 matches by the creator row's user name")
must(listed("nobody") == [], "an unknown name returns an empty list")
must(listed(confirmed="bob") == [alice_row, bob_row] and listed(confirmed="BOB") == [alice_row, bob_row], "the confirmer name")
must(listed("alice", "bob") == [alice_row] and listed("bob", "alice") == [], "both filters together narrow further")
must(listed(confirmed="carol") == [], "a row with no confirmer matches no confirmer name")
request = SimpleNamespace(query_params={"created_by": "  Alice  ", "confirmed_by": ""})
must(ns["_name_filter"](request, "created_by") == "Alice" and ns["_name_filter"](request, "confirmed_by") is None and ns["_name_filter"](request, "missing") is None, "trimmed; blank is no filter")
must(ns["_person_name"](SimpleNamespace(username="x" * 200)) == "x" * 150 and ns["_person_name"](None) == "", "the stored name is at most 150 characters")
print("       the filter matches the stored creator or confirmer exactly and case-insensitively, falls back to the creator row, and an unknown name matches nothing")

# ---- the wiring: the filter only removes rows and runs before the unchanged permission and scope test
get_src = VIEWS.split("class SchedulerListView(APIView):", 1)[1].split("    def post(self, request):", 1)[0]
must('_name_filter(request, "created_by")' in get_src and '_name_filter(request, "confirmed_by")' in get_src, "both query parameters are read")
loop = get_src.split("for schedule in qs:", 1)[1]
must(loop.index("_name_filters_match(schedule, created_by, confirmed_by)") < loop.index("_can_access_target_scope(request.user, schedule.targets)"), "the filter runs first")
must("continue" in loop.split("_name_filters_match", 1)[1].split("try:", 1)[0], "a non-match is skipped, never added")
must("(_native_scheduler_manager(request.user) or (action and _can_use_action(request.user, action))) and _can_access_target_scope(request.user, schedule.targets)" in loop, "the permission and scope test is exactly as in 1.17.62")
must(VIEWS.count("has_extension_permission(") + VIEWS.count("has_tactical_permission(") + VIEWS.count("_native_scheduler_manager(") == 18, "no new permission call (1.17.62 had 18)")
rbac = (APP / "rbac.py").read_text(encoding="utf-8")
must(not re.search(r"[\"'](core\.)?scheduler[.:]", rbac), "no scheduler permission code exists in rbac, and none was added")
print("       the filter runs inside the list loop before the unchanged permission and scope test and only removes rows; no permission was added")

# ---- the serializer keeps every earlier key and adds the two names
ser = (APP / "scheduler.py").read_text(encoding="utf-8").split("def serialize_schedule", 1)[1]
old_keys = ["id", "name", "module_id", "action_id", "action_label", "action_available", "target_mode", "targets", "target_state", "target_state_detail", "parameters",
            "schedule_type", "timezone", "run_at", "run_time", "weekdays", "day_of_month", "interval_seconds", "interval_anchor_at", "owner_type", "owner_module", "owner_key",
            "owner_label", "managed_by_module", "enabled", "missed_policy", "missed_grace_minutes", "concurrency_policy", "retry_count", "retry_delay_seconds", "last_run_at",
            "next_run_at", "last_status", "created_by", "updated_by", "created_at", "updated_at"]
for key in old_keys:
    must(f'"{key}":' in ser, f"the serialized key {key} is still there")
must('"created_by_username":' in ser and '"confirmed_by_username":' in ser, "the two names are added")
must(ser.index('"updated_by":') < ser.index('"created_by_username":') < ser.index('"created_at":'), "added next to the author keys; nothing moved")
print("       the serialized schedule keeps every earlier key and adds created_by_username and confirmed_by_username")

# ---- create and edit store the person
post_src = VIEWS.split("def post(self, request):", 1)[1].split("class SchedulerDetailView", 1)[0]
must("created_by_username=_person_name(request.user), confirmed_by_username=_person_name(request.user)" in post_src, "create stores the signed-in person")
must(post_src.index("_require_action(request.user") < post_src.index("_require_target_scope(request.user, data.get(\"targets\"), payload=True)") < post_src.index("created_by_username="), "the permission and scope checks come first")
patch_src = VIEWS.split("def patch(self, request, schedule_id):", 1)[1].split("def delete(self, request, schedule_id):", 1)[0]
must("schedule.confirmed_by_username = _person_name(request.user)" in patch_src and "schedule.created_by_username = _person_name(schedule.created_by)" in patch_src, "edit confirms the editor and fills a missing creator name")
must(patch_src.index("_require_target_scope(request.user, data.get(\"targets\"), payload=True)") < patch_src.index("confirmed_by_username"), "the checks come before the confirmation")
must(patch_src.index("_require_user_managed(schedule)") < patch_src.index("confirmed_by_username") and "_require_schedule_owner_or_manager(request.user, schedule)" in patch_src, "the owner-or-manager check is unchanged")
print("       create stores the creator and confirmer; edit sets the editor as confirmer after the unchanged permission and scope checks")
print("PASS scheduler creator filter 1.17.63")
