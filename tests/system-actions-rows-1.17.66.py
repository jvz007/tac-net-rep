#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 regression (CQ175, CQ173): the scripts.run row, parameters read from the confirmed record only, and install for the honoured replacement.

The real system_actions.py, scheduler.py, scheduler_run_context.py, caller_identity.py and tasks.py on the stub harness; ``scripts.tasks`` and
``winupdate.tasks`` are stubs that record ``.delay``. Covered: Script Execution (and no other module) registers scripts.run, with both minimum
flags; the task is called with keywords only and the creator's stored name (first 50 characters) as the username; the parameters come only from
the run's confirmed record, and a caller argument that differs from it is refused as parameters_changed; bad shapes of every parameter are refused;
a module that is disabled, a replacement that is not honoured, an action not in the signed manifest, a wrong calling module and a target outside
the snapshot are refused with one deny row and nothing sent; the audit rows carry script_pk and counts and never an argument or an environment
value; the honoured replacement registers and runs winupdate.install and the audit row carries the plain warning; Windows Patching keeps it.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

MARKER = "SECRET-MARKER-9c41"
PATCH_FLAGS = ("can_manage_winupdates", "can_run_bulk")
SCRIPT_FLAGS = ("can_run_bulk", "can_run_scripts")
IDS = [987654311, 987654312, 987654313]
RUN_ID = "scriptexecution.run"
CFG = {"action_id": RUN_ID, "agents": IDS, "parameters": None}
GOOD = {"script_pk": 7, "args": ["-Quiet", MARKER], "env_vars": [f"TOKEN={MARKER}"], "timeout": 120, "run_as_user": True}
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]]}  # noqa: E731
alice = User("alice")
long_name = User("a" * 60)
roots = {}


def install_scripts_stub():
    mod("scripts")
    sys.modules["scripts"].__path__ = []
    mod("scripts.tasks", bulk_script_task=FakeTacticalTask("script"))


HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'], parameters=CFG.get('parameters'))\n"
)


def fresh():
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    install_scripts_stub()
    roots["scriptexecution"] = plugin("scriptexecution", system_actions=[RUN_ID])
    roots["patching"] = plugin("patching", system_actions=["patching.install"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.install"])
    roots["checks"] = plugin("checks", system_actions=[])
    HONOURED["patchmanagement"] = "patching"
    for who in ("alice", "a" * 60):
        FLAGS[who] = set(PATCH_FLAGS) | set(SCRIPT_FLAGS)
        SCOPE[who] = set(IDS)
    CFG.update(action_id=RUN_ID, agents=list(IDS), parameters=None)
    names = dict(sa=sa, CFG=CFG)
    for module in ("scriptexecution", "patching", "patchmanagement", "checks"):
        ns = compile_as(roots[module] / "handlers.py", HANDLER_SRC, **names)
        aid = f"{module}.handler"
        if aid not in sched._ACTIONS:
            sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=ns["handler"], target_types=("none",), timeout_seconds=600)
    sa.register_system_action(RUN_ID, "scriptexecution", "Scheduled script run", "scripts.run", SCRIPT_FLAGS)
    sa.register_system_action("patching.install", "patching", "Scheduled install", "winupdate.install", PATCH_FLAGS)


def start(handler="scriptexecution.handler", user=alice, confirmed=None, manual=True):
    run = make_run(handler, handler.split(".")[0], user=user, owner="user", manual=manual)
    if confirmed is not None:
        run.parameters_snapshot = {"system_action_parameters": confirmed}
    return run, go(run)


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def reason_of(run, out):
    if isinstance(out, sa.SystemActionRefused):
        return out.reason
    rows = deny_rows()
    return rows[0]["metadata"]["reason"] if len(rows) == 1 else None


def refused(run, out, reason):
    must(reason_of(run, out) == reason, (reason, out, AUDITS))
    must(not TASK_CALLS and len(deny_rows()) == 1 and not [a for a in AUDITS if a["action"] == "run"], (reason, TASK_CALLS, AUDITS))
    must(MARKER not in repr(AUDITS) and MARKER not in repr(run.error), f"{reason}: no argument value anywhere")


# ---- registration: only Script Execution, with both flags
fresh()
for kw, why in (
    (dict(module="patching", flags=SCRIPT_FLAGS), "another module"),
    (dict(module="checks", flags=SCRIPT_FLAGS), "another module"),
    (dict(module="scriptexecution", flags=("can_run_bulk",)), "can_run_scripts missing"),
    (dict(module="scriptexecution", flags=("can_run_scripts",)), "can_run_bulk missing"),
):
    sa._clear_for_tests()
    try:
        sa.register_system_action(f"{kw['module']}.run", kw["module"], "x", "scripts.run", kw["flags"])
        raise AssertionError(f"accepted: {why}")
    except sa.SystemActionRegistrationError:
        pass
sa._clear_for_tests()
definition = sa.register_system_action(RUN_ID, "scriptexecution", "Scheduled script run", "scripts.run", SCRIPT_FLAGS + ("can_reboot_agents",))
must(definition.permissions == tuple(sorted(set(SCRIPT_FLAGS) | {"can_reboot_agents"})) and definition.username_param is None, definition)
fresh()
row = sa.get_system_action(RUN_ID)
must(row["owner_module"] == "scriptexecution" and row["min_flags"] == ["can_run_bulk", "can_run_scripts"] and row["parameters"][0] == "script_pk" and row["warning"] is None, row)
must(sa.get_system_action("patching.install")["warning"] == sa.REAPPROVE_WARNING, "install carries the warning in its description")
print("       only Script Execution registers scripts.run, with can_run_bulk and can_run_scripts (stricter than Tactical's bulk route)")

# ---- the happy path: keywords only, the creator's stored name, nothing from the caller
fresh()
run, out = start(confirmed=GOOD)
must(out["outcome"] == "queued" and out["groups"]["sent"] == 1 and len(TASK_CALLS) == 1, (out, TASK_CALLS))
name, args, kwargs = TASK_CALLS[0]
must(name == "script" and args == () and set(kwargs) == {"script_pk", "agent_pks", "args", "timeout", "username", "run_as_user", "env_vars", "custom_field_pk", "collector_all_output", "save_to_agent_note"}, (args, kwargs))
must(kwargs["script_pk"] == 7 and kwargs["agent_pks"] == IDS and kwargs["args"] == GOOD["args"] and kwargs["env_vars"] == GOOD["env_vars"] and kwargs["timeout"] == 120, kwargs)
must(kwargs["username"] == "alice" and kwargs["run_as_user"] is True and kwargs["collector_all_output"] is False and kwargs["save_to_agent_note"] is False and kwargs["custom_field_pk"] is None, kwargs)
rows = [a for a in AUDITS if a["action"] == "run"]
must(len(rows) == 1 and rows[0]["metadata"]["script_pk"] == 7 and rows[0]["metadata"]["args_count"] == 2 and rows[0]["metadata"]["env_vars_count"] == 1 and rows[0]["strict"] is True, rows)
must(MARKER not in repr(AUDITS) and MARKER not in repr(run.__dict__.get("result")) and MARKER not in repr(out), "no argument or environment value in any audit row or result")
fresh()
CFG["parameters"] = GOOD  # the caller may repeat the confirmed record
run, out = start(confirmed=GOOD)
must(out["outcome"] == "queued", out)
fresh()
CFG["parameters"] = {}
run, out = start(confirmed={"script_pk": 9})
must(out["outcome"] == "queued" and TASK_CALLS[0][2]["timeout"] == 90 and TASK_CALLS[0][2]["args"] == [] and TASK_CALLS[0][2]["env_vars"] == [], TASK_CALLS)
print("       the task is called with keywords only; arguments and environment values are read from the confirmed record and never reach an audit row")

# ---- the username is the creator's stored name, first 50 characters, never the caller's
fresh()
run, out = start(user=long_name, confirmed=GOOD)
must(out["outcome"] == "queued" and TASK_CALLS[0][2]["username"] == ("a" * 60)[:50], TASK_CALLS)
fresh()
CFG["parameters"] = {**GOOD, "username": "root"}
run, out = start(confirmed=GOOD)
refused(run, out, "parameters_changed")
print("       the username is the creator's stored name cut to 50 characters; a name from the caller is refused")

# ---- parameters: the caller's argument must be None, {} or equal to the confirmed record
for caller in ({**GOOD, "timeout": 121}, {"script_pk": 8}, {"x": 1}, GOOD | {"args": ["-Other"]}):
    fresh()
    CFG["parameters"] = caller
    run, out = start(confirmed=GOOD)
    refused(run, out, "parameters_changed")
fresh()
CFG["parameters"] = GOOD  # a caller with a record the person never confirmed
run, out = start(confirmed=None)
refused(run, out, "parameters_changed")
fresh()
CFG["parameters"] = {"script_pk": 7}
run, out = start(confirmed=None)
refused(run, out, "parameters_changed")
fresh()
run, out = start(confirmed=None)  # nothing confirmed and nothing passed: script_pk is missing
refused(run, out, "bad_parameters")
print("       a caller argument that differs from what the person confirmed is parameters_changed; nothing confirmed is bad_parameters")

# ---- bad shapes
BAD = [
    {"script_pk": "7"}, {"script_pk": True}, {"script_pk": 0}, {"script_pk": -1}, {"script_pk": 2 ** 63}, {"script_pk": 7.0},
    {"script_pk": 7, "args": "-Quiet"}, {"script_pk": 7, "args": [1]}, {"script_pk": 7, "args": ["x"] * 51}, {"script_pk": 7, "args": ["x" * 1001]}, {"script_pk": 7, "args": ["a\nb"]},
    {"script_pk": 7, "env_vars": {"A": "b"}}, {"script_pk": 7, "env_vars": [None]},
    {"script_pk": 7, "timeout": 0}, {"script_pk": 7, "timeout": 86401}, {"script_pk": 7, "timeout": True}, {"script_pk": 7, "timeout": "90"},
    {"script_pk": 7, "run_as_user": "yes"}, {"script_pk": 7, "collector_all_output": 1}, {"script_pk": 7, "save_to_agent_note": None},
    {"script_pk": 7, "custom_field_pk": 3}, {"script_pk": 7, "username": "root"}, {"script_pk": 7, "command": "rm -rf /"},
]
for confirmed in BAD:
    fresh()
    run, out = start(confirmed=confirmed)
    refused(run, out, "bad_parameters")
fresh()
run, out = start(confirmed="not an object")
refused(run, out, "bad_parameters")
fresh()
run, out = start(confirmed={"script_pk": 7, "args": ["x"] * 50, "timeout": 86400, "env_vars": ["A=" + "b" * 998]})
must(out["outcome"] == "queued", "the limits themselves are allowed")
print("       a script_pk, args, env_vars, timeout, flag or extra key of the wrong shape is bad_parameters; the limits themselves are allowed")

# ---- the guards that every row keeps
fresh()
ENABLED["scriptexecution"] = False
run, out = start(confirmed=GOOD)
must(isinstance(out, sa.SystemActionRefused) and out.reason == "caller_unverified" and not TASK_CALLS, out)  # a disabled module is not even a verified caller
fresh()
real_enabled = sa._enabled_now
sa._enabled_now = lambda module_id: False  # disabled between the caller check and the module check
run, out = start(confirmed=GOOD)
sa._enabled_now = real_enabled
refused(run, out, "module_disabled")
fresh()
PLUGINS["scriptexecution"].system_actions = ()  # the signed manifest no longer lists it
run, out = start(confirmed=GOOD)
refused(run, out, "action_not_declared")
fresh()
CFG["action_id"] = RUN_ID
run, out = start("checks.handler", confirmed=GOOD)  # another module's handler calls Script Execution's action
refused(run, out, "wrong_module")
fresh()
run = make_run("scriptexecution.handler", "scriptexecution", user=alice, owner="user", manual=True, targets={"type": "endpoint", "ids": [str(IDS[0])]})
run.parameters_snapshot = {"system_action_parameters": GOOD}
out = go(run)
refused(run, out, "outside_targets")
fresh()
FLAGS["alice"].discard("can_run_scripts")  # a person-started run keeps the re-read of every flag, including the scripts flag
run, out = start(confirmed=GOOD)
refused(run, out, "permission_lost")
fresh()
FLAGS["alice"].discard("can_run_scripts")  # 1.17.65: a scheduled run is not re-read; the right was checked at creation
run, out = start(confirmed=GOOD, manual=False)
must(out["outcome"] == "queued" and len(TASK_CALLS) == 1, out)
fresh()
SCOPE["alice"] = {IDS[0]}
run, out = start(confirmed=GOOD)
refused(run, out, "out_of_scope")
fresh()
DELAY_FAIL["raise"] = True
run, out = start(confirmed=GOOD)
must(run.status == "failed" and run.error_type == "OutcomeUnknown" and MARKER not in repr(AUDITS) + repr(run.error), (run.__dict__, AUDITS))
DELAY_FAIL["raise"] = False
print("       module disabled, not declared, wrong module, outside the targets, scope and flag losses are refused with one deny row; a failed send is never repeated")

# ---- CQ173: install for the honoured replacement, with the warning
fresh()
sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", PATCH_FLAGS)
CFG["action_id"] = "patchmanagement.install"
run, out = start("patchmanagement.handler")
must(out["outcome"] == "queued" and TASK_CALLS == [("install", (IDS,), {})], (out, TASK_CALLS))
sent = [a for a in AUDITS if a["action"] == "run"]
must(len(sent) == 1 and sent[0]["metadata"]["warning"] == "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere.", sent)
fresh()
CFG["action_id"] = "patching.install"
run, out = start("patching.handler")
must(out["outcome"] == "queued" and [a for a in AUDITS if a["action"] == "run"][0]["metadata"]["warning"] == sa.REAPPROVE_WARNING, "Windows Patching keeps install, with the same warning")
fresh()
sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", PATCH_FLAGS)
HONOURED.clear()  # the replacement stops being honoured
CFG["action_id"] = "patchmanagement.install"
run, out = start("patchmanagement.handler")
refused(run, out, "replacement_not_honoured")
fresh()
HONOURED.clear()
must(sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", PATCH_FLAGS) is None, "not honoured: nothing is registered")
fresh()
CFG["action_id"] = "patching.install"
CFG["parameters"] = {"x": MARKER}
run, out = start("patching.handler")
refused(run, out, "bad_parameters")
print("       the honoured replacement registers and runs install; the audit row carries the plain warning; an install still takes no parameters")

# ---- the source: no free-form command, one import, the call shape comes from the row
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("bulk_command_task" not in src and "rawcmd" not in src and "subprocess" not in src, "no free-form command path")
must("entry.build_call(group, cleaned, username)" in src and "snapshot.get(PARAMETERS_KEY)" in src, "the call shape is the row's and the parameters are the snapshot's")
must("reapproves_by_policy" not in src.split("def _run(", 1)[1].split("# ----", 1)[0].replace("entry.reapproves_by_policy", "").replace('"reapproves_by_policy"', ""), "no run-time refusal for reapproves_by_policy")
print("PASS system actions rows 1.17.66")
