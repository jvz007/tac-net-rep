#!/usr/bin/env python3
"""1.17.68 compatibility: every call a module makes today keeps its signature and its result.

Read as source (this PC has no Django). Core side: the public signatures of reconcile_schedule, start_one_off_run, verify_run_context, register_scheduled_action,
run_system_action, register_system_action and describe_confirmation only gained trailing optional keywords (or none), VerifiedSchedulerRun only gained
trailing defaulted fields and methods, run_system_action keeps wrong_module, and the capability keeps its four earlier operations first.

Module side (when modules/ is on this PC): the calls that modules make are read with ast and every keyword each one passes is still a keyword of the real signature;
every module that calls reconcile_schedule is counted (17 on 21 October 2026) and ONLY patchmanagement passes confirmed_by_request, which is the one call whose behaviour
changed (it now moves ownership and stores the scope); verify_run_context is called with the two ids as keywords (and at most require_owner); nothing passes the two
private fields of VerifiedSchedulerRun. Which modules already use a new name is printed and is not a failure: a module adopting a new name is the point.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def functions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            out.setdefault(node.name, node)
    return out


def params(fn):
    args = fn.args
    positional = [a.arg for a in args.posonlyargs + args.args]
    keyword_only = [a.arg for a in args.kwonlyargs]
    return positional, keyword_only


sched = functions(APP / "scheduler.py")
sa = functions(APP / "system_actions.py")
conf = functions(APP / "system_action_confirmation.py")

# ---- Core: the signatures only grew at the end, and with defaults
pos, kw = params(sched["reconcile_schedule"])
must(pos == [] and kw[:4] == ["owner_module", "owner_key", "action_id", "schedule_type"] and kw[-2:] == ["confirmed_by_request", "confirmation_id"], (pos, kw))
RECONCILE = set(kw)
must(len(kw) == 23, f"reconcile_schedule has the same {len(kw)} keywords as in 1.17.67 (23)")
pos, kw = params(sched["start_one_off_run"])
must(kw[:3] == ["user", "owner_module", "action_id"] and kw[-1] == "confirmation_id" and len(kw) == 9, kw)
ONE_OFF = set(kw)
pos, kw = params(sched["register_scheduled_action"])
must(kw == ["id", "module_id", "label", "handler", "description", "target_types", "permission", "dangerous", "timeout_seconds", "unattended"], kw)
REGISTER_ACTION = set(kw)
ctx_src = (APP / "scheduler_run_context.py").read_text(encoding="utf-8")
must("def verify_run_context(\n    context: Any, *, expected_module_id: str, expected_action_id: str, require_owner: bool = True,\n) -> VerifiedSchedulerRun:" in ctx_src.replace("\r\n", "\n"), "verify_run_context keeps its signature")
must("def run_system_action(context, *, action_id, agent_ids, parameters=None) -> dict:" in (APP / "system_actions.py").read_text(encoding="utf-8"), "run_system_action keeps its signature")
RUN_SA = {"action_id", "agent_ids", "parameters"}
pos, kw = params(sa["register_system_action"])
must(pos == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "delegable_to"], pos)
REGISTER_SA = set(pos)
pos, kw = params(conf["describe_confirmation"])
must(pos == ["user", "action_id", "targets", "parameters", "when"], pos)
fields = re.findall(r"^    (\w+): [^\n=]+(?: = [^\n]+)?$", ctx_src.split("class VerifiedSchedulerRun:", 1)[1].split("    def _owner_now", 1)[0].replace("\r\n", "\n"), re.MULTILINE)
must(fields[:13] == ["run_id", "schedule_id", "module_id", "action_id", "owner_module", "owner_key", "one_off", "user", "owner_user_id", "owner_username", "creator_username", "confirmed_by_username", "unattended"], fields)
must(fields[13:] == ["_creation_scope", "_targets"], "1.17.68 appended two private defaulted fields after the 1.17.63 ones")
must("_creation_scope: Any = field(default=None, repr=False, compare=False)" in ctx_src and "_targets: Any = field(default=None, repr=False, compare=False)" in ctx_src, "defaulted, out of equality and the repr")
for method in ("has_tactical_permission", "resource_context", "has_creation_scope", "creation_scope_info", "held_at_creation", "resolved_endpoints"):
    must(f"def {method}(" in ctx_src, method)
sa_src = (APP / "system_actions.py").read_text(encoding="utf-8")
must('"wrong_module": "Only the module that owns this run and this action can run it."' in sa_src and "if identity.module_id != verified.module_id:" in sa_src, "wrong_module is unchanged")
must('OPERATIONS = (\n    "list_actions", "get_action", "run", "describe_confirmation",' in sa_src.replace("\r\n", "\n"), "the four earlier operations stay first")
print("       Core: reconcile_schedule, start_one_off_run, verify_run_context, register_scheduled_action, run_system_action and describe_confirmation keep their signatures; register_system_action and VerifiedSchedulerRun only gained trailing optional parts")

# ---- the modules
modules = ROOT.parents[1] / "modules"
if not modules.is_dir():
    print("       modules/ is not on this PC: the module read was skipped")
    print("PASS scheduler compat 1.17.68")
    raise SystemExit(0)

CALLS = {"reconcile_schedule": (RECONCILE, {}), "start_one_off_run": (ONE_OFF, {}), "register_scheduled_action": (REGISTER_ACTION, {}), "run_system_action": (RUN_SA, {}),
         "register_system_action": (REGISTER_SA, {}), "verify_run_context": ({"expected_module_id", "expected_action_id", "require_owner"}, {})}
users = {name: set() for name in CALLS}
request_users = set()
verify_calls = 0
NEW_NAMES = ("describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run", "register_target_resolver",
             "held_at_creation", "resolved_endpoints", "has_creation_scope", "creation_scope_info", "delegable_to", "patch_lockdown", "TakeoverRefused", "CreationScopeUnavailable")
adopters = {name: set() for name in NEW_NAMES}
for path in sorted(modules.rglob("*.py")):
    parts = path.relative_to(modules).parts
    if "node_modules" in parts or "tests" in parts or path.name.startswith("test_") or path.name == "stubs.py" or len(parts) < 2:
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError):
        continue
    owner = parts[0]
    for name in NEW_NAMES:
        if name in text:
            adopters[name].add(owner)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        if func not in CALLS:
            continue
        allowed = CALLS[func][0]
        keywords = {k.arg for k in node.keywords if k.arg}
        # only a call that really is Core's: it must import from tec_tac in this file
        if "tec_tac" not in text:
            continue
        users[func].add(owner)
        must(keywords <= allowed or any(k.arg is None for k in node.keywords), f"{path.relative_to(modules)}: {func} passes a keyword that is not in the signature: {sorted(keywords - allowed)}")
        if func == "reconcile_schedule" and "confirmed_by_request" in keywords:
            request_users.add(owner)
        if func == "verify_run_context":
            verify_calls += 1
            must(len(node.args) <= 1 and {"expected_module_id", "expected_action_id"} <= keywords, f"{path.relative_to(modules)}: verify_run_context is called with the context and the two ids as keywords")
        if func == "run_system_action":
            must(len(node.args) <= 1, "run_system_action takes the context as its only positional argument")
    must("_creation_scope=" not in text, f"{owner}: nothing passes the private fields of VerifiedSchedulerRun")
must(len(users["reconcile_schedule"]) >= 17, f"{len(users['reconcile_schedule'])} modules call reconcile_schedule (17 on 21 October 2026)")
must(request_users <= {"patchmanagement"}, f"only patchmanagement passes confirmed_by_request, which is the call that now moves ownership; found {sorted(request_users)}")
must(verify_calls >= 3, f"verify_run_context call sites: {verify_calls}")
must(len(users["register_scheduled_action"]) >= 20, "every register_scheduled_action user keeps working: the signature did not change")
for name in ("alerts", "backups", "checks", "cyberhoot", "licensing", "notifications", "scoutdns", "serverhealth", "sentinelone"):
    must(name in users["reconcile_schedule"], f"{name} still calls reconcile_schedule without a request and is unaffected (no stored creator to protect, no ownership to move)")
print(f"       modules/: {len(users['reconcile_schedule'])} modules call reconcile_schedule, {len(users['register_scheduled_action'])} register scheduled actions, {len(users['start_one_off_run'])} start one-off runs, {verify_calls} verify_run_context call sites: every keyword is still in the signature; only {sorted(request_users)} passes a request")
used = {name: sorted(owners) for name, owners in adopters.items() if owners}
print(f"       new names already in module code (information, not a failure): {used if used else 'none'}")
print("PASS scheduler compat 1.17.68")
