#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.111 regression (AD-43): a module's own Scheduler person action in a delegation grant. Registration, describe_delegation and register_delegation_grant.

The real delegation.py, system_actions.py, system_action_confirmation.py and scheduler.py on the stub harness of delegation-person-action-harness-1.17.111.py (which follows
scheduler-completion-harness-1.17.61.py). Module code is compiled under stub plugin folders so the real frame walk of caller_identity decides who is calling.

Covered. (1) register_scheduled_action(delegable_to=): validated; refused when the id is not listed in the module's signed manifest under scheduler_person_actions (also when the
manifest cannot be read), when it is also a system action, or when a module outside Core's allow-list is named; the default () and the equality of an older action hold; identical
re-registration is idempotent and a changed delegable_to is refused. (2) describe_delegation and register_delegation_grant for wapm.profile-install by maintenance succeed with the
person-action text and a 600 second id; each of the refusals (another owner module, another action id, no action permission even for a scheduler manager, an inactive person, a target
outside the person's scope, over the ceiling, bad parameters, an id not in the manifest, a disabled module, a missing or wrong confirmation id) is ONE deny row; only the confirmed
parameters are stored; a takeover needs the new editor's own covering scope.
"""
from __future__ import annotations

from pathlib import Path

HARNESS_111 = Path(__file__).resolve().parent / "delegation-person-action-harness-1.17.111.py"
exec(compile(HARNESS_111.read_text(encoding="utf-8"), str(HARNESS_111), "exec"), globals())  # noqa: S102 - the shared test harness, not user input


def handler(context):
    return {"ok": True}


def refused_registration(**kw):
    try:
        sched.register_scheduled_action(**kw)
    except sched.SchedulerError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {kw}")


BASE = dict(module_id="wapm", label="x", handler=handler, target_types=("none", "endpoint"), permission=PERMISSION, timeout_seconds=600)

# ---- (1) register_scheduled_action(delegable_to=)
fresh()
action = sched.get_scheduled_action(ACTION)
must(action.delegable_to == ("maintenance",) and sched.get_scheduled_action(OTHER_ACTION).delegable_to == (), "stored; default ()")
older = sched.ScheduledAction("x.y", "x", "label", handler, "", ("none",), None, False, 600, (), False)
must(older.delegable_to == () and older == sched.ScheduledAction("x.y", "x", "label", handler, "", ("none",), None, False, 600, (), False, ()), "an older action builds and compares equal")
must([f.name for f in dataclasses.fields(sched.ScheduledAction)][-1] == "delegable_to", "the new field is last")
again = sched.register_scheduled_action(id=ACTION, label="WAPM profile install", handler=mods["wapm"]["handler"], target_types=("none", "endpoint", "profile"), delegable_to=("maintenance",),
                                        **{k: v for k, v in BASE.items() if k not in ("label", "handler", "target_types")})
must(again is not None and sched.get_scheduled_action(ACTION) == again, "identical re-registration is idempotent")
text = refused_registration(id=ACTION, label="WAPM profile install", handler=mods["wapm"]["handler"], target_types=("none", "endpoint", "profile"), delegable_to=(),
                            **{k: v for k, v in BASE.items() if k not in ("label", "handler", "target_types")})
must("already registered" in text, text)  # a changed delegable_to is a changed definition
fresh()
for bad in ("maintenance", ["Maintenance"], [5], ["wapm"], ["a", "b", "c", "d", "e", "f"], {"x": 1}):
    refused_registration(id="wapm.profile-x", delegable_to=bad, **BASE)
PERSON_LISTED["wapm"] = ("wapm.profile-x",)
refused_registration(id="wapm.profile-x", delegable_to=("other",), **BASE)  # a module Core does not name
refused_registration(id="wapm.profile-x", delegable_to=("maintenance",), **BASE)  # the pair is not in the allow-list (another action id)
fresh()
PERSON_LISTED["wapm"] = ()
must("scheduler_person_actions" in refused_registration(id="wapm.profile-x", delegable_to=("maintenance",), **BASE), "not in the manifest")
sched._ACTIONS.pop(ACTION)
PERSON_LISTED["wapm"] = ()
must("scheduler_person_actions" in refused_registration(id=ACTION, delegable_to=("maintenance",), **BASE), "the allow-listed id is refused when the manifest does not list it")
fresh()
sched._ACTIONS.pop(ACTION)
sched._manifest_person_actions = lambda module_id: (_ for _ in ()).throw(RuntimeError("manifest unreadable"))
must("could not read" in refused_registration(id=ACTION, delegable_to=("maintenance",), **BASE), "an unreadable manifest refuses")
sched._manifest_person_actions = lambda module_id: tuple(PERSON_LISTED.get(module_id, ()))
fresh()
sched._ACTIONS.pop(ACTION)
sa._ACTIONS[ACTION] = sa.SystemActionDefinition(ACTION, "wapm", "x", "winupdate.install", BOTH, "agents", False, None, False, ())
must("system action" in refused_registration(id=ACTION, delegable_to=("maintenance",), **BASE), "an id that is also a system action")
sa._ACTIONS.pop(ACTION)
ok = sched.register_scheduled_action(id=ACTION, delegable_to=("maintenance",), **BASE)
must(ok.delegable_to == ("maintenance",), "allowed once the checks hold")
fresh()
sched._ACTIONS.pop(ACTION)
must(sched.register_scheduled_action(id=ACTION, delegable_to=None, **BASE).delegable_to == () and sched.register_scheduled_action(id="wapm.profile-y", delegable_to=[], **BASE).delegable_to == (), "None and [] mean none")
print("       delegable_to is validated, optional, last, idempotent, and refused for an id outside the manifest, a system action or a pair outside the allow-list")

# ---- (2) describe_delegation
fresh()
good = describe()
must(good["required"] is True and good["expires_in"] == 600 and good["total"] == 2 and good["groups"] is None and good["kind"] == "person_action" and good["confirmation_id"], good)
text = good["text"]
for needle in (
    "WAPM profile install: 2 endpoint(s).", "maintenance will start this for you later", "with nobody signed in", "each time its own schedule says so",
    "Core checks that this confirmation is unchanged", "the modules involved are on", "every endpoint is inside the targets you confirm here", "Core does not look at your account again",
    "even if your account is later disabled", "Editing or removing the profile stops it", "Requested by alice. Do you want to continue?",
):
    must(needle in text, (needle, text))
must("replacement" not in text and sa.REAPPROVE_WARNING not in text and "group(s)" not in text, "the Tactical-function parts are not in a person-action text")
must(not deny_rows(), "no deny row for an allowed describe")
system_answer = call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS)
must(system_answer["kind"] == "system_action" and system_answer["groups"] == 1, system_answer)
dangerous = sched.get_scheduled_action(ACTION)
sched._ACTIONS[ACTION] = dataclasses.replace(dangerous, dangerous=True)
must("This action can change many endpoints at once." in describe()["text"], "the dangerous warning")
sched._ACTIONS[ACTION] = dangerous
del AUDITS[:]


def one_deny(call_, reason):
    before = len(deny_rows())
    try:
        call_()
    except (deleg.DelegationRefused, conf.SystemActionCreationRefused) as exc:
        must(exc.reason == reason, (reason, exc.reason, str(exc)))
    else:
        raise AssertionError(f"accepted instead of {reason}")
    rows = deny_rows()
    must(len(rows) == before + 1 and rows[-1]["metadata"]["reason"] == reason, (reason, rows[before:]))
    must(not any(x in repr(rows[-1]["metadata"].values()) for x in ("[1, 2]", "[1, 4]", "agent_ids")), "no endpoint in a deny row")


def case(label, setup, reason, call_=None):
    fresh()
    setup()
    one_deny(call_ or (lambda: describe()), reason)


case("another owner module", lambda: None, "not_delegable", lambda: describe(owner_module="wapm", caller="wapm"))
case("another action id", lambda: None, "not_delegable", lambda: describe(action_id=OTHER_ACTION))
case("another provider", lambda: None, "unknown_action", lambda: describe(provider_module="patchmanagement"))
case("an unregistered action", lambda: None, "unknown_action", lambda: describe(action_id="wapm.nothing"))
case("the provider does not name the owner", lambda: sched._ACTIONS.__setitem__(ACTION, dataclasses.replace(sched._ACTIONS[ACTION], delegable_to=())), "not_delegable")
case("the allow-list does not name the pair", lambda: deleg.PERSON_ACTION_DELEGATION.clear(), "not_delegable")
case("not in the manifest", lambda: PERSON_LISTED.__setitem__("wapm", ()), "action_not_declared")
case("the provider is disabled", lambda: ENABLED.__setitem__("wapm", False), "module_disabled")
case("the owner is disabled", lambda: ENABLED.__setitem__("maintenance", False), "caller_unverified")
case("no action permission", lambda: EXT_PERMS.__setitem__("alice", set()), "not_permitted")
case("no action permission, even as a scheduler manager", lambda: (EXT_PERMS.__setitem__("alice", set()), MANAGERS.add("alice")), "not_permitted")
case("an inactive person", lambda: setattr(alice, "is_active", False), "owner_inactive")
case("the installer user", lambda: setattr(alice, "is_installer_user", True), "owner_inactive")
case("a target outside the person's scope", lambda: SCOPE.__setitem__("alice", {1}), "out_of_scope")
case("no resolver", lambda: RESOLVED_MODULE_TARGETS.clear(), "targets_unresolved")
case("over the ceiling", lambda: RESOLVED_MODULE_TARGETS.__setitem__(("maintenance", "profile"), set(range(1, sa.MAX_AGENTS + 2))), "agent_count")
case("no endpoint", lambda: RESOLVED_MODULE_TARGETS.__setitem__(("maintenance", "profile"), set()), "agent_count")
for label, bad in (
    ("a list", {sa.PARAMETERS_KEY: [1]}), ("text", {sa.PARAMETERS_KEY: "x"}), ("a nested dict", {sa.PARAMETERS_KEY: {"a": {"b": 1}}}), ("a list value", {sa.PARAMETERS_KEY: {"a": [1]}}),
    ("a float", {sa.PARAMETERS_KEY: {"a": 1.5}}), ("None as a value", {sa.PARAMETERS_KEY: {"a": None}}), ("the marker key", {sa.PARAMETERS_KEY: {deleg.MARKER_KEY: "x"}}),
    ("a bad key", {sa.PARAMETERS_KEY: {"Bad": 1}}), ("a key that starts with a digit", {sa.PARAMETERS_KEY: {"1a": 1}}), ("a long key", {sa.PARAMETERS_KEY: {"a" * 41: 1}}),
    ("eleven keys", {sa.PARAMETERS_KEY: {f"k{i}": i for i in range(11)}}), ("201 characters", {sa.PARAMETERS_KEY: {"a": "x" * 201}}), ("a control character", {sa.PARAMETERS_KEY: {"a": "x\ny"}}),
    ("a huge number", {sa.PARAMETERS_KEY: {"a": 2**70}}), ("a non-dict record", "text"), ("a list record", [1]),
):
    case(label, lambda: None, "bad_parameters", lambda bad=bad: describe(parameters=bad))
fresh()
for fine in (None, {}, {sa.PARAMETERS_KEY: None}, {sa.PARAMETERS_KEY: {}}, {sa.PARAMETERS_KEY: {f"k{i}": i for i in range(10)}}, {sa.PARAMETERS_KEY: {"a": "x" * 200, "b": True, "c": -5}}):
    must(describe(parameters=fine)["required"] is True, fine)
refused(lambda: sa.describe_delegation(RealRequest(alice), owner_module="maintenance", provider_module="wapm", action_id=ACTION, targets=TARGETS), "caller_unverified")
refused(lambda: describe(caller="wapm"), "wrong_module")
refused(lambda: call("maintenance", "describe", RealRequest(alice, session=False), owner_module="maintenance", provider_module="wapm", action_id=ACTION, targets=TARGETS), "no_person")
# the strict permission check: an action with no permission entry refuses, a Tactical flag entry is read as a flag, no manager bypass
fresh()
sched._ACTIONS[ACTION] = dataclasses.replace(sched._ACTIONS[ACTION], permission=None)
MANAGERS.add("alice")
one_deny(lambda: describe(), "not_permitted")
sched._ACTIONS[ACTION] = dataclasses.replace(sched._ACTIONS[ACTION], permission="tactical:can_run_bulk")
must(describe()["required"] is True, "a Tactical flag entry holds for a person who has the flag")
FLAGS["alice"] = set()
one_deny(lambda: describe(), "not_permitted")
print("       describe_delegation answers the person-action text and a 600 second id; every refusal is one deny row; a scheduler manager has no bypass for the action permission")

# ---- (3) register_delegation_grant
fresh()
token = describe()["confirmation_id"]
refused(lambda: register(None), "confirmation_required")
refused(lambda: register("garbage"), "confirmation_invalid")
refused(lambda: register(token, targets={"type": "profile", "ids": [8]}), "confirmation_invalid")
refused(lambda: register(token, user=bob), "confirmation_invalid")
refused(lambda: register(token, parameters={sa.PARAMETERS_KEY: {"profile_id": 8}}), "confirmation_invalid")  # other parameters
refused(lambda: register(token, action_id=OTHER_ACTION), "not_delegable")
refused(lambda: register(token, caller="wapm"), "wrong_module")
CLOCK[0] += 601
refused(lambda: register(token), "confirmation_invalid")
must(not grants(), "a refused call stores nothing")
CLOCK[0] -= 601
del AUDITS[:]
done = register(token)
must(done == {"grant_key": GK, "created": True, "owner_changed": False}, done)
grant = grants()[0]
must(grant.owner_module == "maintenance" and grant.provider_module == "wapm" and grant.action_id == ACTION and grant.created_by is alice and grant.created_by_username == "alice", grant.__dict__)
must(grant.parameters == {sa.PARAMETERS_KEY: CONFIRMED}, grant.parameters)
must(grant.creation_scope["captured_for"] == "alice" and grant.enabled is True, grant.creation_scope)
rows = [a for a in AUDITS if a["object_type"] == "delegation_grant" and a["action"] != "deny"]
must(len(rows) == 1 and rows[0]["action"] == "add" and rows[0]["strict"] is True and rows[0]["metadata"]["action_id"] == ACTION and rows[0]["metadata"]["total_agents"] == 2 and rows[0]["metadata"]["groups"] is None, rows)
must(not any(x in repr(rows) for x in ("'1'", "[1, 2]")), "no endpoint id in the audit row")
# only the confirmed record is stored: no other top-level key, and no marker key can ride along
fresh()
save_grant(parameters={sa.PARAMETERS_KEY: {"a": 1}, deleg.MARKER_KEY: "forged", "extra": {"x": 1}})
must(grants()[0].parameters == {sa.PARAMETERS_KEY: {"a": 1}}, grants()[0].parameters)
fresh()
save_grant(parameters=None)
must(grants()[0].parameters == {}, grants()[0].parameters)
# a repeat save changes the digest; a strict audit failure stops it
fresh()
save_grant()
first = deleg.grant_digest(grants()[0])
save_grant()
must(deleg.grant_digest(grants()[0]) != first and len(grants()) == 1, "every save revokes earlier tickets")
fresh()
token = describe()["confirmation_id"]
AUDIT_FAIL["strict"] = True
try:
    register(token)
    raise AssertionError("a strict audit failure must stop the grant")
except sched.SchedulerTransientError:
    pass
AUDIT_FAIL["strict"] = False  # (the stub has no database rollback, so only the refusal is asserted here, as in delegation-grant-1.17.68.py)
# register repeats every creation-time control, with one deny row
for label, setup, reason in (
    ("no permission", lambda: EXT_PERMS.__setitem__("alice", set()), "not_permitted"),
    ("out of scope", lambda: SCOPE.__setitem__("alice", {1}), "out_of_scope"),
    ("inactive", lambda: setattr(alice, "is_active", False), "owner_inactive"),
):
    fresh()
    token = describe()["confirmation_id"]
    setup()
    one_deny(lambda: register(token), reason)
    must(not grants(), label)
# a takeover: only when the new editor's own scope covers every target
fresh()
save_grant()
before = dict(grants()[0].__dict__)
deleg._person_covers = lambda person, action, targets: False
carol_token = describe(carol)["confirmation_id"]
del AUDITS[:]
refused(lambda: register(carol_token, carol), "takeover_out_of_scope")
must(grants()[0].created_by is alice and grants()[0].creation_scope == before["creation_scope"], "the grant is as it was")
must(len(deny_rows()) == 1 and not [a for a in AUDITS if a["action"] == "modify"], "one deny row, no change row")
deleg._person_covers = lambda person, action, targets: True
moved = register(carol_token, carol)
must(moved["owner_changed"] is True and grants()[0].created_by is carol and grants()[0].parameters == {sa.PARAMETERS_KEY: CONFIRMED}, moved)
print("       register stores only the confirmed record, writes one strict row, repeats the creation-time controls with one deny row, and a takeover needs the new editor's covering scope")
print("PASS delegation person action 1.17.111")
