#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (CQ183, Johan 20 October 2026): a module with capital letters in its id can register event jobs and the job-finished hook.

Module ids are case-sensitive and case-preserving (docs/module-identifiers.md): Core must not case-fold one. So the module part of an event job
id and the owner in a job file keep the module id's own spelling, and the job part after the dot stays lowercase. The setup (stubs, a temporary
job folder, an in-memory hook table) is the first part of tests/server-job-finished-hook-1.17.62.py, read from that file so the two cannot drift.

Covered: ``securityWAF.server_job_finished`` registers for module securityWAF; a job file with owner securityWAF and a finished status gets a hook
row and a published event under that exact id; ``securitywaf.x``, ``SecurityWAF.x`` and ``securityWAF.X`` cannot register for securityWAF; a
module id with a dot or a space is refused; a job whose owner differs only in case is ignored (never folded onto another module); every id that
registered before still registers, and every id that was refused for another reason is still refused (an exhaustive small-alphabet comparison of
the old and new patterns); the source holds no lower() or casefold() on a module id in the three files.
"""
from __future__ import annotations

import itertools
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent / "server-job-finished-hook-1.17.62.py"
text = BASE.read_text(encoding="utf-8")
exec(compile(text[: text.index("# ---- (1) a job finishes with no page open")], str(BASE), "exec"), globals())  # noqa: S102 - the shared setup of the 1.17.62 test


def refused_spec(**kw):
    base = dict(label="x")
    base.update(kw)
    try:
        policy.clean_spec(**base)
    except policy.EventJobPolicyError as exc:
        return str(exc)
    return None


# ---- (1) the registration
reset()
register("securityWAF")
must("securityWAF.server_job_finished" in ej._JOBS and ej._JOBS["securityWAF.server_job_finished"].module_id == "securityWAF", sorted(ej._JOBS))
spec = policy.clean_spec(id="securityWAF.server_job_finished", module_id="securityWAF", label="x")
must(spec.id == "securityWAF.server_job_finished" and spec.module_id == "securityWAF", spec)
must(hooks.hook_job_id("securityWAF") == "securityWAF.server_job_finished", "hook_job_id is unchanged and keeps the spelling")
print("       securityWAF.server_job_finished registers for module securityWAF, spelled exactly")

for bad_id, why in (("securitywaf.x", "all lowercase"), ("SecurityWAF.x", "another capital"), ("SECURITYWAF.x", "all capitals"), ("securityWAF.X", "an upper-case job part"),
                    ("securityWAF.", "no job part"), (".x", "no module part"), ("securityWAF", "no dot"), ("securityWAF.x y", "a space in the job part"),
                    ("security WAF.x", "a space in the module part"), ("securityWAF .x", "a space before the dot"), ("securityWAF.x\n", "a newline"), ("securityWAF.-x", "a leading dash in the job part")):
    must(refused_spec(id=bad_id, module_id="securityWAF") is not None, f"{bad_id!r} ({why}) must not register for securityWAF")
for bad_module in ("security.WAF", "security WAF", "", "_x", "-x", "x" * 65, "securityWAF/", "securityWAF\n", None, 5):
    must(refused_spec(id="securityWAF.x", module_id=bad_module) is not None, f"module id {bad_module!r} must be refused")
must(refused_spec(id="securityWAF.x", module_id="alerts") is not None and refused_spec(id="alerts.x", module_id="securityWAF") is not None, "one module cannot register under another's id")
must(refused_spec(id=5, module_id="securityWAF") is not None, "an id that is not text is refused")
print("       securitywaf.x, SecurityWAF.x, securityWAF.X, a dot or a space in the module id and another module's id are all refused")

# a registration through the real register_event_job: the folder check and the caller are as before
reset()
register("securityWAF")
try:
    plugin("securitywaf")
    ej.register_event_job(id="securityWAF.other", module_id="securitywaf", label="x", handler=lambda context: None)
    raise AssertionError("a lowercase module id registered an id spelled with capitals")
except (ej.EventJobRegistrationError, policy.EventJobPolicyError):
    pass
print("       register_event_job refuses a module id that differs only in case")

# ---- (2) the hook: a job file with owner securityWAF
reset()
register("securityWAF")
jid = new_id()
job_file(jid, owner="securityWAF", action="securityWAF.rotate", status="failed", exit_code=2, classification="script_failed")
counts = tick()
must(counts["delivered"] == 1 and counts["errors"] == 0 and len(STORED) == 1, (counts, STORED))
event_id, key, payload = STORED[0]
must(event_id == "securityWAF.server_job_finished" and key == f"server-job:{jid}", (event_id, key))
must(payload == {"job_id": jid, "action_id": "securityWAF.rotate", "status": "failed", "exit_code": 2, "classification": "script_failed"}, payload)
must(HOOKS[jid]["state"] == "queued" and HOOKS[jid]["module_id"] == "securityWAF", HOOKS)
ej._JOBS[event_id].handler({"payload": payload})
must(len(HANDLED) == 1, "the handler runs for the stored row")
counts = tick()
must(counts["checked"] == 0 and len(STORED) == 1, "at most once, as for a lowercase module")
print("       a job file with owner securityWAF and a finished status gets a hook row and one event under the exact id")

# the owner is read as written: a different spelling reaches no module, and never another one
reset()
register("securityWAF")
a, b, c = new_id(), new_id(), new_id()
job_file(a, owner="securitywaf", action="securitywaf.rotate")
job_file(b, owner="SecurityWAF", action="SecurityWAF.rotate")
job_file(c, owner="security WAF", action="x.y")
counts = tick()
must(counts["ignored"] == 3 and not STORED and {HOOKS[a]["reason"], HOOKS[b]["reason"]} == {"no_hook"} and HOOKS[c]["reason"] == "no_owner", (counts, HOOKS))
reset()
register("securityWAF")
register("securitywaf")  # a different module, a different id
job_file(new_id(), owner="securityWAF", action="securityWAF.rotate")
job_file(new_id(), owner="securitywaf", action="securitywaf.rotate")
tick()
must(sorted(s[0] for s in STORED) == ["securityWAF.server_job_finished", "securitywaf.server_job_finished"], "each reaches its own module only")
print("       an owner spelled differently is ignored and never folded onto another module; two modules that differ in case each get their own job")

# a disabled mixed-case module is skipped like any other
reset()
register("securityWAF")
ENABLED["securityWAF"] = False
jid = new_id()
job_file(jid, owner="securityWAF", action="securityWAF.rotate")
counts = tick()
must(counts["skipped"] == 1 and not STORED and HOOKS[jid]["reason"] == "module_unavailable" and len(hook_audits()) == 1, (counts, HOOKS))
print("       a disabled mixed-case module is skipped with one audit row, as any other")

# the internal publish path takes the exact spelling
reset()
register("securityWAF")
core = compile_as(str(APP / "server_job_hooks.py"), "def go(ej, **kw):\n    return ej.publish_for_core(**kw)\n")
r = core["go"](ej, job_id="securityWAF.server_job_finished", module_id="securityWAF", key="server-job:x", payload={"ok": 1})
must(r.outcome == "queued" and len(STORED) == 1, r)
r = core["go"](ej, job_id="securityWAF.server_job_finished", module_id="securitywaf", key="server-job:y", payload={"ok": 1})
must(r.outcome == "error" and len(STORED) == 1, "another spelling of the module id is another module")
print("       publish_for_core takes the exact spelling and refuses another")

# ---- (3) nothing that worked before changes, nothing that was refused for another reason is allowed
OLD_JOB = re.compile(r"^([a-z0-9][a-z0-9_-]{0,63})\.([a-z0-9][a-z0-9._-]{0,79})$")
OLD_MODULE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
NEW_JOB, NEW_MODULE = policy.JOB_ID_RE, policy.MODULE_ID_RE
alphabet = "aA0-_. "
checked = 0
for size in range(0, 6):
    for chars in itertools.product(alphabet, repeat=size):
        candidate = "".join(chars)
        old, new = OLD_JOB.fullmatch(candidate), NEW_JOB.fullmatch(candidate)
        if old:
            must(new and new.groups() == old.groups(), f"{candidate!r} registered before and must still match the same parts")
        elif new:
            must(any(ch.isupper() for ch in new.group(1)) and not any(ch.isupper() for ch in new.group(2)), f"{candidate!r} newly matches only because of a capital in the module part")
        old_m, new_m = OLD_MODULE.match(candidate), NEW_MODULE.fullmatch(candidate)
        if old_m:
            must(new_m, f"module id {candidate!r} was valid before")
        elif new_m:
            must(any(ch.isupper() for ch in candidate), f"module id {candidate!r} is newly valid only because of a capital")
        checked += 1
for lower_id, module in (("alerts.deliver", "alerts"), ("certificatemanagement.server_job_finished", "certificatemanagement"), ("tacticalupdater.server_job_finished", "tacticalupdater"),
                         ("a.b", "a"), ("tac-1.job_x.y", "tac-1"), ("x" * 64 + ".y", "x" * 64)):
    must(refused_spec(id=lower_id, module_id=module) is None, f"{lower_id} still registers")
for still_bad, module in (("alerts.Deliver", "alerts"), ("alerts.", "alerts"), ("", "alerts"), ("alerts.x", ""), ("backups.x", "alerts"), ("x" * 65 + ".y", "x" * 65), ("alerts.x" + "y" * 80, "alerts")):
    must(refused_spec(id=still_bad, module_id=module) is not None, f"{still_bad!r} is still refused")
print(f"       {checked} small-alphabet strings: every id and module id valid before is valid now with the same parts; a new match always needs a capital in the module part")

# ---- (4) the source: the module id is never lowercased in the three files
for name in ("event_jobs_policy.py", "event_jobs.py", "server_job_hooks.py"):
    src = (APP / name).read_text(encoding="utf-8")
    code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    must(not re.search(r"\.lower\(|\.casefold\(|\.upper\(|str\.lower|re\.IGNORECASE|re\.I\b", code), f"{name} must not fold the case of an id")
hooks_src = (APP / "server_job_hooks.py").read_text(encoding="utf-8")
must('OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")' in hooks_src, "the owner pattern keeps the spelling")
policy_src = (APP / "event_jobs_policy.py").read_text(encoding="utf-8")
must("match.group(1) != module_id" in policy_src, "the module part is compared with the module id exactly")
for doc in ("event-jobs.md", "scheduler.md", "server-maintenance-capability.md"):
    body = " ".join((ROOT / "docs" / doc).read_text(encoding="utf-8").split())
    must("must be lowercase (letters, digits, `-` and `_`)" not in body and "Event job ids are lowercase only" not in body, f"docs/{doc} no longer states the lowercase limit for module ids")
    must("securityWAF" in body, f"docs/{doc} names the rule with securityWAF")
print("       the three files never fold the case of an id; the docs state the rule and no longer the old limit")
print("PASS event jobs mixed case id 1.17.63")
