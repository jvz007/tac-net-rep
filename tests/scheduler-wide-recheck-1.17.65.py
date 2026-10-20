#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.65 regression (AD-13 condition 2 amended, wide rule; CQ184 b, CQ186, CQ189, Johan 20 October 2026): a SCHEDULED run is not re-checked against its creator.

The real scheduler.py (its real tick, ``dispatch_due_schedules``), scheduler_run_context.py, system_actions.py and tasks.py on the stub harness of
scheduler-completion-harness-1.17.61.py. Covered:
(1) the switch is the one literal True; the exemption is reached only through the one helper (source read);
(2) a demoted, deactivated and deleted-but-named creator's user-owned scheduled run of an ORDINARY (non-system) action is queued by the tick and
    verifies in verify_run_context, with no flag; a handler that ignores the person still runs, and a handler that calls has_tactical_permission
    still gets a fresh read (a deactivated owner: verify passes, has_tactical_permission is False, the handler refuses);
(3) the same for a system action: it is sent, and its audit run row carries run_kind scheduled, creator and confirmed_by;
(4) a person-started manual run of the same schedule is still refused (owner_refused) and a one-off run is still re-checked (AuthorizationRevoked);
    a row with no stored name and a deleted creator is still refused; a handler that needs a person (require_owner=True) is refused with none;
(5) every other system-action refusal still holds: module_disabled, replacement_not_honoured, action_not_declared, outside_targets, more than 2000
    endpoints, wrong_module, caller_unverified, context_invalid; a second delivery sends nothing (at-most-once);
(6) a module-owned schedule with a creator name and an ordinary action gets no exemption;
(7) the unattended= keyword keeps its validation and has no effect;
(8) the documents, contract text and release notes carry the new wording and no leftover; no 1.17.65-N literal outside the three allowed places.
"""
from __future__ import annotations

import dataclasses
import re
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HARNESS = HERE / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

BOTH = ("can_manage_winupdates", "can_run_bulk")
IDS = [987654311, 987654312, 987654313]
SCAN = "patching.scan"
CFG = {"action_id": SCAN, "agents": IDS}
alice, carol = User("alice"), User("carol")
REFUSED = {"invalid": "The person who owns this schedule may no longer run it."}
SEEN = []


def AUTO_TARGETS():
    return {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]] if isinstance(CFG["agents"], (list, tuple, set)) else []}


def ignoring_handler(context):  # an ordinary handler that never reads the person
    SEEN.append("ran")
    return {"ok": True}


def person_handler(context):  # the module's own live check: verify, then has_tactical_permission
    try:
        v = rc.verify_run_context(context, expected_module_id="patching", expected_action_id=context["action_id"])
    except sched.SchedulerRunContextInvalid as exc:
        return {"invalid": str(exc)}
    if not v.has_tactical_permission("can_run_bulk"):
        return {"refused": "owner has no permission now", "unattended": v.unattended}
    return {"verified": True, "unattended": v.unattended, "creator": v.creator_username, "confirmed": v.confirmed_by_username}


def optional_person_handler(context):
    try:
        v = rc.verify_run_context(context, expected_module_id="patching", expected_action_id=context["action_id"], require_owner=False)
    except sched.SchedulerRunContextInvalid as exc:
        return {"invalid": str(exc)}
    return {"verified": True, "unattended": v.unattended, "creator": v.creator_username, "user": v.user is not None}


HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
)
roots = {}
MODS = {}


def setup_world():
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    roots["patching"] = plugin("patching", system_actions=["patching.scan", "patching.sys"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan", "patchmanagement.sys"])
    roots["other"] = plugin("other", system_actions=["other.sys"])
    for who in ("alice", "carol"):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = set(IDS) | {5000 + i for i in range(2100)}


def fresh():
    reset()
    setup_world()
    HONOURED["patchmanagement"] = "patching"
    sched._ACTIONS.clear()
    names = dict(sa=sa, CFG=CFG)
    for module in ("patching", "patchmanagement", "other"):
        MODS[module] = compile_as(roots[module] / "handlers.py", HANDLER_SRC, **names)
    sched.register_scheduled_action(id="patching.sys", module_id="patching", label="sys", handler=MODS["patching"]["handler"], timeout_seconds=600)
    sched.register_scheduled_action(id="patchmanagement.sys", module_id="patchmanagement", label="sys", handler=MODS["patchmanagement"]["handler"], timeout_seconds=600)
    sched.register_scheduled_action(id="other.sys", module_id="other", label="sys", handler=MODS["other"]["handler"], timeout_seconds=600)
    sched.register_scheduled_action(id="patching.ordinary", module_id="patching", label="ordinary", handler=ignoring_handler)
    sched.register_scheduled_action(id="patching.person", module_id="patching", label="person", handler=person_handler)
    sched.register_scheduled_action(id="patching.optional", module_id="patching", label="optional", handler=optional_person_handler)
    CFG.update(action_id=SCAN, agents=list(IDS))
    SEEN.clear()
    for user in (alice, carol):
        user.is_active = True
        user.is_installer_user = False
    sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
    sa.register_system_action("patchmanagement.scan", "patchmanagement", "APM scheduled scan", "winupdate.scan", BOTH)


sched.recover_stale_runs = lambda now: {}
sched._recover_event_jobs_safely = lambda now: {}
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0


def make_schedule(action_id="patching.ordinary", *, creator=alice, name="alice", owner_type="user", owner_key="", confirmed="", targets=None):
    return Schedule.objects.create(
        name="s", module_id=action_id.split(".")[0], action_id=action_id, owner_type=owner_type,
        owner_module=action_id.split(".")[0] if owner_type == "module" else "", owner_key=owner_key,
        created_by=creator, created_by_username=name, confirmed_by_username=confirmed, enabled=True, schedule_type="interval", interval_seconds=3600,
        interval_anchor_at=NOW[0] - timedelta(hours=3), targets=targets or {"type": "none"}, last_due_key="", updated_at=None,
    )


def tick():
    del QUEUED_IDS[:]
    return sched.dispatch_due_schedules(NOW[0])


def skipped_types(result):
    return sorted(r.error_type for r in Run.objects.rows if str(r.id) in result["skipped"])


def run_for(schedule, *, manual=False, targets=None):
    return Run.objects.create(
        schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=schedule.module_id, action_id=schedule.action_id,
        owner_type=schedule.owner_type, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", manual=manual,
        scheduled_for=NOW[0], last_queued_at=NOW[0], targets_snapshot=targets if targets is not None else AUTO_TARGETS(),
    )


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def run_rows():
    return [a for a in AUDITS if a["action"] == "run"]


def reason_of(out):
    if isinstance(out, sa.SystemActionRefused):
        return out.reason
    rows = deny_rows()
    if isinstance(out, str) and out.startswith("run no longer active") and len(rows) == 1:
        return rows[0]["metadata"]["reason"]
    return None


def refused(out, reason):
    must(reason_of(out) == reason and not TASK_CALLS and not run_rows(), (reason, out, AUDITS))


# ---- (1) the switch is one literal and it is True
must(sched.AD13_CONDITION_2_AMENDED is True, "the switch is True")
src = (APP / "scheduler.py").read_text(encoding="utf-8")
must(len(re.findall(r"^AD13_CONDITION_2_AMENDED = True$", src, re.M)) == 1 and "AD13_CONDITION_2_AMENDED = False" not in src, "one literal, True")

# ---- (2) ordinary (non-system) action, user-owned: demoted, deactivated and deleted-but-named creators
for how in ("demoted", "deactivated", "deleted"):
    fresh()
    if how == "demoted":
        AUTH["deny"] = True
        FLAGS["alice"] = set()
    elif how == "deactivated":
        alice.is_active = False
    s = make_schedule("patching.ordinary", creator=None if how == "deleted" else alice)
    must(sched._is_unattended_scheduled_run(s) is True, f"{how}: ordinary action, no flag needed")
    r = tick()
    must(len(r["queued"]) == 1 and not r["skipped"], (how, r))
    out = go(run_for(s))
    must(SEEN == ["ran"], (how, out, SEEN))
    optional = make_schedule("patching.optional", creator=None if how == "deleted" else alice)
    out = go(run_for(optional))
    must(out["verified"] is True and out["unattended"] is True and out["creator"] == "alice" and out["user"] is (how != "deleted"), (how, out))
    AUTH["deny"] = False
    alice.is_active = True
print("       a demoted, deactivated and deleted-but-named creator's ordinary scheduled run is queued by the tick, verifies and runs the handler")

# a handler that does its own live check: verify passes, the fresh read refuses
fresh()
s = make_schedule("patching.person")
must(go(run_for(s)).get("verified") is True, "an active, permitted owner passes the handler's own check")
alice.is_active = False
out = go(run_for(s))
must(out.get("refused") and out["unattended"] is True, ("a deactivated owner: verify passes, has_tactical_permission is False, the handler refuses", out))
alice.is_active = True
FLAGS["alice"] = set()
out = go(run_for(s))
must(out.get("refused"), ("a demoted owner: the handler refuses", out))
print("       a handler that calls has_tactical_permission keeps its own live check: verify passes, the fresh read refuses")

# ---- (3) a system action: sent, with the audit row naming the creator and the confirmer
fresh()
FLAGS["alice"] = set()
SCOPE["alice"] = set()
alice.is_active = False
s = make_schedule("patching.sys", confirmed="carol")  # targets none: the tick of an endpoint schedule needs the Tactical resolver, which the stub does not have
r = tick()
must(len(r["queued"]) == 1 and not r["skipped"], r)
run = run_for(s, targets=AUTO_TARGETS())
out = go(run)
must(out["outcome"] == "queued" and len(TASK_CALLS) == 1 and run.status == "succeeded" and len(run_rows()) == 1 and not deny_rows(), (out, AUDITS))
meta = run_rows()[0]["metadata"]
must(meta["run_kind"] == "scheduled" and meta["creator"] == "alice" and meta["confirmed_by"] == "carol" and run_rows()[0]["actor"] is alice, meta)
alice.is_active = True
print("       a demoted, scope-less, deactivated creator's system action is sent; the audit run row carries run_kind scheduled, creator and confirmed_by")

# ---- (4) a person-started run keeps every re-check; a row with no name and no creator is refused; require_owner=True needs a person
fresh()
s = make_schedule("patching.optional")
alice.is_active = False
must(go(run_for(s, manual=True)) == REFUSED, "a manual run is refused (owner_refused) when the owner is deactivated")
alice.is_active = True
AUTH["deny"] = True
must(go(run_for(s, manual=True)) == REFUSED, "a manual run is refused when the owner lost the action or scope")
AUTH["deny"] = False
must(go(run_for(s, manual=True))["unattended"] is False, "a manual run of an active owner verifies as person-started")
fresh()
CFG["agents"] = list(IDS)
s = make_schedule("patching.sys", targets=AUTO_TARGETS())
FLAGS["alice"].discard("can_run_bulk")
run = run_for(s, manual=True)
out = go(run)
refused(out, "permission_lost")
fresh()
alice.is_active = False
one_run = make_run("patching.sys", "patching", user=alice, owner="one-off")
go(one_run)
must(one_run.status == "skipped" and one_run.error_type == "AuthorizationRevoked" and not TASK_CALLS, one_run.__dict__)
alice.is_active = True
print("       a manual run of the same schedule is still refused (owner_refused, permission_lost) and a one-off run is still re-checked (AuthorizationRevoked)")

fresh()
AUTH["deny"] = True
s = make_schedule("patching.ordinary", creator=None, name="")  # made before migration 0036, creator deleted
must(sched._is_unattended_scheduled_run(s) is False, "no stored name and no creator: the helper answers False")
r = tick()
must(not r["queued"] and skipped_types(r) == ["AuthorizationRevoked"], r)
AUTH["deny"] = False
fresh()
s = make_schedule("patching.person", creator=None, name="alice")
out = go(run_for(s))
must(out.get("invalid") and "no person" in out["invalid"], ("require_owner=True still refuses a run with no person behind it", out))
print("       a row with no stored name and a deleted creator is still refused; require_owner=True still needs a person")

# ---- (5) every other system-action check still holds
fresh()
s = make_schedule("patching.sys", targets=AUTO_TARGETS())
ENABLED["patching"] = False
out = go(run_for(s))
must(isinstance(out, sa.SystemActionRefused) and out.reason == "caller_unverified" and not TASK_CALLS and not run_rows(), out)
fresh()
real_enabled = sa._enabled_now
sa._enabled_now = lambda module_id: False
out = go(run_for(make_schedule("patching.sys", targets=AUTO_TARGETS())))
refused(out, "module_disabled")
sa._enabled_now = real_enabled

fresh()
HONOURED.clear()
CFG["action_id"] = "patchmanagement.scan"
out = go(run_for(make_schedule("patchmanagement.sys", targets=AUTO_TARGETS())))
refused(out, "replacement_not_honoured")

fresh()
PLUGINS["patching"].system_actions = ("patching.sys",)  # the signed manifest no longer lists the scan
out = go(run_for(make_schedule("patching.sys", targets=AUTO_TARGETS())))
refused(out, "action_not_declared")

fresh()
CFG["agents"] = [IDS[0], IDS[1]]
out = go(run_for(make_schedule("patching.sys"), targets={"type": "endpoint", "ids": [str(IDS[0])]}))
refused(out, "outside_targets")

fresh()
CFG["agents"] = [6000 + i for i in range(2001)]
out = go(run_for(make_schedule("patching.sys")))
refused(out, "agent_count")

fresh()
out = go(run_for(make_schedule("other.sys", targets=AUTO_TARGETS())))
must(isinstance(out, sa.SystemActionRefused) and out.reason == "wrong_module" and not TASK_CALLS and not run_rows(), out)

fresh()
s = make_schedule("patching.sys", targets=AUTO_TARGETS())
run = run_for(s)
out = go(run)
must(out["outcome"] == "queued" and len(TASK_CALLS) == 1, out)
run.status, run.finished_at, run.result = "queued", None, {}  # a duplicate delivery of the same run
again = go(run)
must(again.get("duplicate") is True and len(TASK_CALLS) == 1 and len(run_rows()) == 1, (again, TASK_CALLS))
print("       module_disabled, replacement_not_honoured, action_not_declared, outside_targets, 2000 cap, wrong_module, caller_unverified and at-most-once all still hold")

fresh()
s = make_schedule("patching.sys", targets=AUTO_TARGETS())
real_verify = rc.verify_run_context


def forged(context, **kw):
    return real_verify({**context}, **kw)  # a copy, not the object Core issued


sa._run_context.verify_run_context = forged
try:
    out = go(run_for(s))
finally:
    sa._run_context.verify_run_context = real_verify
must(reason_of(out) == "context_invalid" and not TASK_CALLS, ("a copied context is refused", out))
fresh()
real_verify = rc.verify_run_context


def wrong_id(context, **kw):
    kw["expected_action_id"] = "patching.other"
    return real_verify(context, **kw)


sa._run_context.verify_run_context = wrong_id
try:
    out = go(run_for(make_schedule("patching.sys", targets=AUTO_TARGETS())))
finally:
    sa._run_context.verify_run_context = real_verify
must(reason_of(out) == "context_invalid" and not TASK_CALLS, ("an expected id mismatch is refused", out))
print("       a copied context and an expected-id mismatch are refused as context_invalid")

# ---- (6) a module-owned schedule with a creator name and an ordinary action gets no exemption
fresh()
mo = make_schedule("patching.ordinary", creator=None, name="alice", owner_type="module", owner_key="recurring")
must(sched._is_unattended_scheduled_run(mo) is False, "module-owned, ordinary action")
sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=ignoring_handler)  # same id as the registered system action
mo_sys = make_schedule("patching.scan", creator=None, name="alice", owner_type="module", owner_key="recurring")
must(sched._is_unattended_scheduled_run(mo_sys) is True, "module-owned, signed system action, creator name stored (CQ176 as in 1.17.63)")
one = make_schedule("patching.sys", creator=alice, name="alice", owner_type="module", owner_key="one-off:abc")
must(sched._is_unattended_scheduled_run(one) is False, "a one-off is never exempt")
print("       a module-owned schedule with an ordinary action gets no exemption; with a signed system action it behaves as in 1.17.63")

# ---- (7) the unattended keyword: accepted, validated, no effect
fresh()
for bad in ("yes", 1, None):
    try:
        sched.register_scheduled_action(id="patching.kw", module_id="patching", label="k", handler=ignoring_handler, unattended=bad)
        raise AssertionError(f"unattended={bad!r} was accepted")
    except sched.SchedulerError:
        pass
try:
    sched.register_scheduled_action(id="patching.unlisted", module_id="patching", label="u", handler=ignoring_handler, unattended=True)
    raise AssertionError("an id outside the signed manifest was accepted")
except sched.SchedulerError:
    pass
flagged = sched.register_scheduled_action(id="patching.scan", module_id="patching", label="scan", handler=ignoring_handler, unattended=True)
must(flagged.unattended is True and dataclasses.fields(sched.ScheduledAction)[-1].name == "unattended", "the field stays last")
fresh()
for aid in ("patching.ordinary", "patching.scan"):
    if aid not in sched._ACTIONS:
        sched.register_scheduled_action(id=aid, module_id="patching", label=aid, handler=ignoring_handler, unattended=(aid == "patching.scan"))
a, b = make_schedule("patching.ordinary"), make_schedule("patching.scan")
must(sched._is_unattended_scheduled_run(a) is sched._is_unattended_scheduled_run(b) is True, "flagged or not, a user-owned scheduled run is exempt")
print("       unattended= keeps its validation and has no effect")

# ---- (1b) the exemption is reached only through the one helper (source read)
must(src.count("def _is_unattended_scheduled_run(") == 1, "one helper")
tick_src = src.split("def dispatch_due_schedules", 1)[1].split("def queue_manual_run", 1)[0]
must("None if _is_unattended_scheduled_run(schedule) else _runtime_authorization_error(schedule)" in tick_src and tick_src.count("_runtime_authorization_error(") == 1, "the tick uses the helper only")
ctx_src = (APP / "scheduler_run_context.py").read_text(encoding="utf-8")
must(ctx_src.count("= _is_unattended_scheduled_run(run)") == 1 and "from .scheduler import _is_unattended_scheduled_run as decide" in ctx_src, "verify_run_context asks the one helper")
sa_src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("_is_unattended_scheduled_run" not in sa_src and 'getattr(verified, "unattended", False)' in sa_src, "system actions read the verified answer only")
must("unattended" not in (APP / "tasks.py").read_text(encoding="utf-8"), "tasks.py holds no exemption")
body = src.split("def _is_unattended_scheduled_run", 1)[1].split("def _runtime_authorization_error", 1)[0]
must("registered.unattended" not in body, "the flag is not read by the decision")
print("       the tick, verify_run_context and the system-action code reach the exemption only through the one helper (source read)")

# ---- (8) documents, contract text and notes
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(tuple(int(x) for x in re.sub(r"-\d+$", "", version).split(".")) >= (1, 17, 65), version)
for doc in ("scheduler.md", "system-actions.md", "module-scheduling.md"):
    text = (ROOT / "docs" / doc).read_text(encoding="utf-8")
    for dead in ("switched OFF", "built but switched off", "not yet recorded", "inactive until", "Status since 1.17.63-1"):
        must(dead not in text, f"docs/{doc} still says {dead!r}")
    must("1.17.65" in text, f"docs/{doc} carries the 1.17.65 wording")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for dead in ("not yet recorded", "inactive until", "until it is; switch scheduler"):
    must(dead not in contracts, f"contracts.py still says {dead!r}")
must("Module-facing change in 1.17.65" in contracts and "Since 1.17.65" in contracts, "the contract rows carry the 1.17.65 text")
if re.fullmatch(r"1\.17\.65", version):
    notes = (ROOT / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
    for heading in ("## Module-facing", "## What I checked in modules/", "## Dev-server checklist"):
        must(heading in notes, f"the notes lack {heading}")
    steps = notes[notes.index("## Dev-server checklist"):]
    must(steps.count("**Step ") >= 5 and steps.count("**FAIL**") >= steps.count("**Step "), "every checklist step has a FAIL line")
    must("| backups |" in notes and "**Behaviour changes.**" in notes and "backups.delete" in notes, "the notes state the effect on backups")
    must("None. A one-off run is still re-checked." not in notes.split("| backups |")[1].split(chr(10))[0], "the backups row does not say None")
    must("CQ191" in notes, "the notes flag the extension-permission effect")
    must("running until someone removes or edits them" in notes and "as in Tactical" in notes, "the plain cost sentence")
# a rebuild must be promotable: no 1.17.65-N literal outside VERSION, tec_tac_package.json and the root notes
pattern = re.compile(r"1\.17\.65-\d")
for folder in ("framwork", "scripts"):
    for path in (ROOT / folder).rglob("*"):
        if path.is_file() and path.suffix in (".py", ".sh", ".json", ".md", ".txt", ".toml", ".yml", ".yaml"):
            must(not pattern.search(path.read_text(encoding="utf-8", errors="ignore")), f"{path} holds a 1.17.65-N literal")
print("       the documents and contract rows carry the new wording, the notes carry the three headings, and no 1.17.65-N literal can block a rebuild")
print("PASS scheduler wide recheck 1.17.65")
