#!/usr/bin/env python3
"""1.17.67 compatibility: the fail-closed creation gate and the plan mark touch only a declared system action and only an action that calls
run_system_action. Every other module keeps working as in 1.17.66.

Read as source (this PC has no Django): scheduler.py keeps _action_declared_as_system_action as it was (a failed read still answers False, the
run-time exemption), the new system_action_state is the only caller of the two reads in the creation gate, reconcile_schedule and
start_one_off_run keep their signatures, and the capability keeps its operations and its version. When modules/ is on this PC: no module calls
run_system_action, register_system_action, describe_confirmation, system_action_state, the three new log routes or the system update audit
step; the modules that call reconcile_schedule or start_one_off_run are counted (their ordinary actions are covered by
tests/system-actions-creation-failclosed-1.17.67.py).
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


sched_src = (APP / "scheduler.py").read_text(encoding="utf-8")
tree = ast.parse(sched_src)
funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
declared = ast.get_source_segment(sched_src, funcs["_action_declared_as_system_action"])
must("except Exception:  # noqa: BLE001 - any failure to read means the exemption does not apply" in declared and "return False" in declared, "the run-time exemption still swallows to False")
must("system_action_state" not in declared, "the run-time exemption does not use the new state")
state = ast.get_source_segment(sched_src, funcs["system_action_state"])
must(state.index("is_registered_system_action") < state.index("_manifest_system_actions"), "the cheap memory check runs before the manifest read")
args = [a.arg for a in funcs["start_one_off_run"].args.kwonlyargs]
must(args[-1] == "confirmation_id" and args[:3] == ["user", "owner_module", "action_id"], args)
rec = funcs["reconcile_schedule"].args.kwonlyargs
must([a.arg for a in rec][-2:] == ["confirmed_by_request", "confirmation_id"], "reconcile_schedule keeps its last two keywords")
print("       the run-time exemption keeps its answer, the state reads the registry before the manifest, the two public signatures are unchanged")

confirmation = (APP / "system_action_confirmation.py").read_text(encoding="utf-8")
must("_action_declared_as_system_action" not in confirmation.replace("# ", ""), "the creation gate no longer swallows read errors through the run-time function")
must(confirmation.count("system_action_state(") == 2, "one call in is_system_action_schedule, one in _declaration_state")
sa_src = (APP / "system_actions.py").read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.1.0"' in sa_src and '"operations": ["list_actions", "get_action", "run", "describe_confirmation"]' in sa_src, "core.system_actions keeps 1.1.0 and its four operations")
must("MAX_MARKS_PER_RUN = 105" in sa_src and 'KIND_PLAN = "plan"' in sa_src, "the plan mark and the new limit")
sm_src = (APP / "server_maintenance.py").read_text(encoding="utf-8")
must('CAPABILITY_VERSION = "1.1.0"' in sm_src or re.search(r'version="1\.1\.0"', sm_src), "core.server_maintenance stays 1.1.0")
print("       core.system_actions and core.server_maintenance keep version 1.1.0 and their operations")

modules = ROOT.parents[1] / "modules"
if modules.is_dir():
    new_names = re.compile(r"run_system_action|register_system_action|describe_confirmation|system_action_state|system_update_audit|system/updates/jobs|maintenance/jobs/[^\s\"']*/log|read_job_log|log_response|serve_log|read_log_for")
    hits, recon, oneoff = [], set(), set()
    for path in modules.rglob("*"):
        if path.suffix not in (".py", ".js", ".vue", ".json", ".toml") or "node_modules" in path.parts or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        owner = path.relative_to(modules).parts[0]
        if new_names.search(text):
            hits.append((owner, path.name))
        if re.search(r"\breconcile_schedule\b", text):
            recon.add(owner)
        if re.search(r"\bstart_one_off_run\b", text):
            oneoff.add(owner)
    must(not hits, f"a module uses a changed or new name: {hits[:5]}")
    print(f"       modules/ read: no module uses run_system_action, register_system_action, describe_confirmation, the new routes or the audit step; {len(recon)} call reconcile_schedule and {len(oneoff)} call start_one_off_run (ordinary actions are not refused for a read fault)")
else:
    print("       modules/ is not on this PC: the module search was skipped")
print("PASS scheduler compat 1.17.67")
