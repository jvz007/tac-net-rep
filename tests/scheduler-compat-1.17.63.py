#!/usr/bin/env python3
"""1.17.63 compatibility: every module that uses the Scheduler, one-off runs, reconcile_schedule, run contexts and system actions still binds.

Reads Core and every module under modules/ as source (ast), like tests/server-job-hook-compat-1.17.62.py. Covered: every call in modules/ of
register_scheduled_action, reconcile_schedule, start_one_off_run, get_one_off_run, get_owned_schedule, disable_owned_schedule, remove_owned_schedule,
verify_run_context, complete_pending_run, run_system_action, register_system_action and register_event_job binds to the 1.17.63 signature (the
new parameters are optional and the dataclass fields are last with defaults); no module passes ``unattended`` or ``confirmed_by_request``; no
module registers an event job or a hook under a mixed-case module id; no module uses system actions yet, so the behaviour change reaches none of
them until patchmanagement or patching adopt it in their own releases; the new refusal reason, the migration and the version are in place.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
MODULES = ROOT.parents[1] / "modules"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def defs(path, names):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names}


FILES = {
    "register_scheduled_action": APP / "scheduler.py", "reconcile_schedule": APP / "scheduler.py", "start_one_off_run": APP / "scheduler.py",
    "get_one_off_run": APP / "scheduler.py", "get_owned_schedule": APP / "scheduler.py", "disable_owned_schedule": APP / "scheduler.py",
    "remove_owned_schedule": APP / "scheduler.py", "verify_run_context": APP / "scheduler_run_context.py",
    "complete_pending_run": APP / "scheduler_completion.py", "run_system_action": APP / "system_actions.py",
    "register_system_action": APP / "system_actions.py", "register_event_job": APP / "event_jobs.py",
}
SIGS = {}
for name, path in FILES.items():
    SIGS[name] = defs(path, {name})[name].args


def params(args):
    """(positional names, keyword-only names, required names)"""
    positional = [a.arg for a in args.posonlyargs + args.args]
    kwonly = [a.arg for a in args.kwonlyargs]
    required = positional[: len(positional) - len(args.defaults)] + [a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True) if d is None]
    return positional, kwonly, required


def binds(call: ast.Call, args: ast.arguments) -> str | None:
    positional, kwonly, required = params(args)
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None  # a splat cannot be bound by reading; nothing to prove
    if len(call.args) > len(positional):
        return "too many positional arguments"
    given = set(positional[: len(call.args)])
    for keyword in call.keywords:
        if keyword.arg not in positional + kwonly:
            return f"unknown keyword {keyword.arg}"
        if keyword.arg in given:
            return f"{keyword.arg} given twice"
        given.add(keyword.arg)
    missing = [name for name in required if name not in given]
    return f"missing {missing}" if missing else None


# ---- (1) the signatures: the new parameters are optional, new fields are last with defaults
sched_src = (APP / "scheduler.py").read_text(encoding="utf-8")
reg = defs(APP / "scheduler.py", {"register_scheduled_action", "reconcile_schedule"})
for name, new in (("register_scheduled_action", "unattended"), ("reconcile_schedule", "confirmed_by_request")):
    args = reg[name].args
    kwonly = [a.arg for a in args.kwonlyargs]
    # 1.17.66 added one optional keyword after confirmed_by_request (confirmation_id), so the 1.17.63 keyword is last but one for reconcile_schedule
    position = -2 if name == "reconcile_schedule" else -1
    must(kwonly[position] == new and args.kw_defaults[position] is not None and args.kw_defaults[-1] is not None, f"{name}: {new} is where it was and has a default")
    must(not args.args and not args.posonlyargs, f"{name} stays keyword-only")
must(ast.unparse(reg["register_scheduled_action"].args.kw_defaults[-1]) == "False" and ast.unparse(reg["reconcile_schedule"].args.kw_defaults[-2]) == "None"
     and [a.arg for a in reg["reconcile_schedule"].args.kwonlyargs][-1] == "confirmation_id" and ast.unparse(reg["reconcile_schedule"].args.kw_defaults[-1]) == "None", "defaults")
vr = ast.parse((APP / "scheduler_run_context.py").read_text(encoding="utf-8"))
verified = next(n for n in vr.body if isinstance(n, ast.ClassDef) and n.name == "VerifiedSchedulerRun")
fields = [(n.target.id, n.value is not None) for n in verified.body if isinstance(n, ast.AnnAssign)]
must([f for f, _d in fields][-5:] == ["creator_username", "confirmed_by_username", "unattended", "_creation_scope", "_targets"] and all(d for _f, d in fields[-5:]) and not any(d for _f, d in fields[:-5]), fields)  # 1.17.68 appended the two private fields
must(ast.unparse(defs(APP / "scheduler_run_context.py", {"verify_run_context"})["verify_run_context"].args) == "context: Any, *, expected_module_id: str, expected_action_id: str, require_owner: bool=True", "verify_run_context")
sa_tree = ast.parse((APP / "system_actions.py").read_text(encoding="utf-8"))
must(ast.unparse(defs(APP / "system_actions.py", {"run_system_action"})["run_system_action"].args) == "context, *, action_id, agent_ids, parameters=None", "run_system_action")
must(ast.unparse(defs(APP / "scheduler.py", {"start_one_off_run"})["start_one_off_run"].args) == "*, user, owner_module: str, action_id: str, targets: dict | None=None, parameters: dict | None=None, name: str | None=None, retry_count: int=0, retry_delay_seconds: int=DEFAULT_RETRY_DELAY_SECONDS, confirmation_id: str | None=None", "start_one_off_run")  # 1.17.66: one optional last keyword
print("       unattended and confirmed_by_request are the one new, last, optional keyword of their functions; VerifiedSchedulerRun adds three defaulted fields last")

# ---- (2) every call in modules/ still binds, and none uses the new names
if not MODULES.is_dir():
    print("       modules/ is not on this PC: the module search was skipped")
else:
    calls = {name: [] for name in SIGS}
    users = {name: set() for name in SIGS}
    new_names = []
    mixed_event_ids = []
    scanned = 0
    for path in sorted(MODULES.rglob("*.py")):
        parts = path.relative_to(MODULES).parts
        if len(parts) < 2 or any(p in {"node_modules", "__pycache__", "tests"} for p in parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        scanned += 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                called = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
                if called in SIGS:
                    problem = binds(node, SIGS[called])
                    must(problem is None, f"{path.relative_to(MODULES)}:{node.lineno}: {called}() does not bind to 1.17.63: {problem}")
                    calls[called].append((parts[0], node.lineno))
                    users[called].add(parts[0])
                    for keyword in node.keywords:
                        if keyword.arg in ("unattended", "confirmed_by_request"):
                            new_names.append(f"{path.relative_to(MODULES)}:{node.lineno}")
        for literal in re.findall(r"""["']([A-Za-z0-9_-]*[A-Z][A-Za-z0-9_-]*)\.server_job_finished["']""", source):
            mixed_event_ids.append((parts[0], literal))
    must(not new_names, f"modules that already pass a new keyword: {new_names}")
    must(not mixed_event_ids, f"modules that already name a mixed-case hook: {mixed_event_ids}")
    must(len(users["register_scheduled_action"]) >= 20, f"expected the Scheduler users to be found: {sorted(users['register_scheduled_action'])}")
    for name in ("run_system_action", "register_system_action", "complete_pending_run", "verify_run_context"):
        print(f"       {name}: {len(calls[name])} call(s) in modules/ {sorted(users[name])}")
    must(not calls["run_system_action"] and not calls["register_system_action"], "no module uses system actions yet: the behaviour change reaches none of them")
    manifest_hits = [p.parts[-2] for p in MODULES.rglob("tec_tac.json") if '"system_actions"' in p.read_text(encoding="utf-8", errors="replace")]
    must(not manifest_hits, f"no module manifest lists system_actions yet: {manifest_hits}")
    # every event job a module registers with a literal id still passes Core's check, with the module id spelled as the module's own
    policy_text = (APP / "event_jobs_policy.py").read_text(encoding="utf-8")
    new_re = re.compile(re.search(r'JOB_ID_RE = re\.compile\(r"(.+?)"\)', policy_text).group(1))
    old_re = re.compile(r"^([a-z0-9][a-z0-9_-]{0,63})\.([a-z0-9][a-z0-9._-]{0,79})$")
    event_ids = []
    for path in sorted(MODULES.rglob("*.py")):
        parts = path.relative_to(MODULES).parts
        if len(parts) < 2 or any(p in {"node_modules", "__pycache__", "tests"} for p in parts):
            continue
        for literal in re.findall(r"""register_event_job\(\s*id\s*=\s*["']([^"']+)["']""", path.read_text(encoding="utf-8", errors="replace")):
            event_ids.append((parts[0], literal))
            must((old_re.fullmatch(literal) is None) or (new_re.fullmatch(literal) is not None), f"{literal} registered before and must still")
    print(f"       {scanned} module files read; {sum(len(v) for v in calls.values())} calls bind to the 1.17.63 signatures; {len(event_ids)} literal event job ids still register")
    for name in ("register_scheduled_action", "reconcile_schedule", "start_one_off_run", "get_owned_schedule"):
        print(f"       {name}: {len(calls[name])} call(s) in {sorted(users[name])}")

# ---- (3) the release pieces
sa_text = (APP / "system_actions.py").read_text(encoding="utf-8")
must('"action_not_declared"' in sa_text, "the new refusal reason")
migrations = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must(migrations[-2] == "0036_schedule_creator_name.py" and migrations[-3] == "0035_server_job_hook.py" and migrations[-1] == "0037_creation_scope_and_delegation.py", migrations[-3:])  # 1.17.68 added 0037
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(tuple(int(x) for x in re.sub(r"-\d+$", "", version).split(".")) >= (1, 17, 63) and f'"version": "{version}"' in (ROOT / "tec_tac_package.json").read_text(encoding="utf-8"), version)  # 1.17.65: 1.17.63 or later
notes = ROOT / f"RELEASE_NOTES_{version}.md"
must(notes.is_file() and "## Module-facing" in notes.read_text(encoding="utf-8"), "release notes with a module-facing heading")
print("PASS scheduler compat 1.17.63")
