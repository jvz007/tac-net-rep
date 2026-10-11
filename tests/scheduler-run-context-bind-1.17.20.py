#!/usr/bin/env python3
"""1.17.20 regression (held Medium from the 1.17.19 review): a run context binds to the handler that verifies it.

Same stub harness as tests/scheduler-run-context-1.17.19.py (loaded from that file up to its first scenario). Covered: a context
issued for module A / action X verifies with A/X; it is refused with a wrong module id, a wrong action id, both wrong, a different-case
id, None, an empty string and a non-string; a missing keyword is a TypeError; a context issued for A/X handed to B's handler
(expected B/Y) is refused; the message names no id; module-owned runs with require_owner=False still bind; the docs example and the
contract row name the two keywords.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "scheduler-run-context-1.17.19.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('owner = user(5, "dave")')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ctx_mod, must, user, make_run, issue, STATE, ROOT = (G[k] for k in ("ctx_mod", "must", "user", "make_run", "issue", "STATE", "ROOT"))
Invalid = G["SchedulerRunContextInvalid"]

owner = user(5, "dave")
STATE["run"] = make_run(owner=owner)
A, X = "scriptmanager", "run-script"


def verify(context, module=A, action=X, **kw):
    return ctx_mod.verify_run_context(context, expected_module_id=module, expected_action_id=action, **kw)


def refused(context, module=A, action=X, **kw):
    try:
        verify(context, module, action, **kw)
    except Invalid as exc:
        message = str(exc)
        must(message and "scriptmanager" not in message and "run-script" not in message, message)
        return message
    raise AssertionError(f"verified a context that must be refused: {module!r} {action!r}")


ctx = issue()
verified = verify(ctx)
must(verified.module_id == A and verified.action_id == X and verified.user is owner, verified)

# wrong ids
must(refused(ctx, module="globalsettings") == "This run belongs to another module or action.", "wrong module")
refused(ctx, action="other-action")
refused(ctx, module="globalsettings", action="other-action")
refused(ctx, module="ScriptManager")
refused(ctx, action="Run-Script")
refused(ctx, module=" scriptmanager")
# missing, empty or not a string: fail closed, never skipped
for bad in (None, "", 0, 5, b"scriptmanager", ["scriptmanager"], object()):
    refused(ctx, module=bad)
    refused(ctx, action=bad)
# a missing keyword is a TypeError (required, keyword-only)
for call in (lambda: ctx_mod.verify_run_context(ctx), lambda: ctx_mod.verify_run_context(ctx, expected_module_id=A),
             lambda: ctx_mod.verify_run_context(ctx, expected_action_id=X), lambda: ctx_mod.verify_run_context(ctx, A, X)):
    try:
        call()
        raise AssertionError("a call without both keywords was accepted")
    except TypeError:
        pass

# a context issued for A/X handed to B's handler (expected B/Y) is refused, and the ids are not echoed
refused(ctx, module="globalsettings", action="change-setting")
# the refusal does not consume the context: the real handler still verifies it
must(verify(ctx).run_id == "run-1", "still verifies for its own handler")

# a bad id is refused even for a context Core did not issue
refused({"run_id": "run-1"}, module=None)

# module-owned runs (require_owner=False) still bind
STATE["run"] = make_run(owner_type="module")
free = verify(issue(), require_owner=False)
must(free.user is None and free.module_id == A, free)
refused(issue(), module="globalsettings", require_owner=False)
refused(issue(), action="other-action", require_owner=False)
# a module-owned run without require_owner=False is still refused for having no person
try:
    verify(issue())
    raise AssertionError("a module-owned run verified with require_owner=True")
except Invalid:
    pass

# the run row decides, not the dict: a dict that claims B/Y does not move the binding
STATE["run"] = make_run(owner=owner)
liar = issue()
liar["module_id"], liar["action_id"] = "globalsettings", "change-setting"
refused(liar, module="globalsettings", action="change-setting")
must(verify(liar).module_id == A, "the run row names the module")

docs = " ".join((ROOT / "docs/scheduler.md").read_text(encoding="utf-8").split())
must("expected_module_id" in docs and "expected_action_id" in docs and "confused deputy" in docs, "docs example and reason")
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
row = [line for line in contracts.splitlines() if '"purpose": "verify_run_context(' in line]
must(len(row) == 1 and "expected_module_id" in row[0] and "expected_action_id" in row[0] and ">=1.17.20" in row[0], "contract row")
src = " ".join((ROOT / "framwork/tec_tac/scheduler_run_context.py").read_text(encoding="utf-8").split())
must("expected_module_id" in src.split("def verify_run_context")[0] and "confused deputy" in src, "module docstring")
print("[TEST] PASS scheduler run context bind 1.17.20")
