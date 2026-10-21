#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 regression (S4): the delegation grant a person confirms once so that one module may start another module's scheduled install later.

The real delegation.py, system_actions.py (the five thin wrappers and register_system_action's delegable_to), system_action_confirmation.py,
scheduler.py and scheduler_creation_scope.py on the stub harness of scheduler-completion-harness-1.17.61.py. Module code is compiled under stub plugin
folders so the real frame walk of caller_identity decides who is calling (the capability route and a direct call give the same answer).

Covered. (1) delegable_to: validated, stored on the definition, shown in list_actions, default none, an older definition still compares equal. (2) describe_delegation: the
caller must be the owner module (Core code and another module are refused), the request must be a real, session-checked one, the provider must have named the owner in
delegable_to and still list the action in its signed manifest, both modules enabled, a replacement honoured; every creation-time control runs for the person
(permission, each Tactical flag with no manager bypass, scope of every resolved endpoint, the ceiling, parameters) with one deny row; the text names what will happen and
the answer carries a 600 second id. (3) register_delegation_grant: needs that id (a schedule's id and an id for other arguments are refused, a stale id expires), stores
the confirmed record, the person by row and by stored name and the person's scope, writes ONE strict audit row with no endpoint id, holds at most 20 grants per owner module, a
repeat save by the same person changes the digest, a second person takes it over only when their own scope covers every target (otherwise nothing changes and one deny row
is written) and a strict audit failure stops it. (4) remove_delegation_grant: the owner module only, one strict row, True or False. (5) The compat: run_system_action and
describe_confirmation keep their signature and wrong_module.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
deleg = load("tec_tac.delegation", "delegation.py")
deleg._secret = lambda: b"test-secret-key"
CLOCK = [1_000_000.0]
deleg._clock = lambda: CLOCK[0]
conf._clock = lambda: CLOCK[0]

BOTH = ("can_manage_winupdates", "can_run_bulk")
INSTALL, SCAN, OTHER = "patchmanagement.install", "patchmanagement.scan", "patchmanagement.other"
alice, bob, carol = User("alice"), User("bob"), User("carol")
roots = {}
PERMS = {"alice": True, "bob": True, "carol": True}
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: PERMS.get(user.username, False)


class RealRequest:
    def __init__(self, user, session=True):
        self.user = user
        self.tec_tac_session = object() if session else None


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
sched._verified_person = lambda request: request.user if isinstance(request, RealRequest) and request.tec_tac_session is not None else (_ for _ in ()).throw(sched.SchedulerNotAllowed("no person"))


def handler(context):
    return {"ok": True}


MODULE_SRC = (
    "def describe(sa, request, **kw):\n    return sa.describe_delegation(request, **kw)\n"
    "def register(sa, request, **kw):\n    return sa.register_delegation_grant(request, **kw)\n"
    "def remove(sa, **kw):\n    return sa.remove_delegation_grant(**kw)\n"
    "def issue(sa, context, **kw):\n    return sa.issue_delegation_ticket(context, **kw)\n"
    "def start(sa, ticket, **kw):\n    return sa.start_delegated_run(ticket, **kw)\n"
)
mods = {}
ROWS = {
    1: dict(agent_id="1", hostname="h1", platform="windows", client_id=10, site_id=100),
    2: dict(agent_id="2", hostname="h2", platform="windows", client_id=10, site_id=101),
    3: dict(agent_id="3", hostname="h3", platform="windows", client_id=20, site_id=200),
    4: dict(agent_id="4", hostname="h4", platform="windows", client_id=30, site_id=300),
}
TARGETS = {"type": "profile", "ids": [7]}
GK = "profile:7"


def fresh(*, delegable=("maintenance",)):
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sched._ACTIONS.clear()
    roots["maintenance"] = plugin("maintenance", category="core", system_actions=[])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=[INSTALL, SCAN, OTHER])
    roots["patching"] = plugin("patching", system_actions=[])
    HONOURED["patchmanagement"] = "patching"
    for name in ("maintenance", "patchmanagement"):
        mods[name] = compile_as(roots[name] / "apps.py", MODULE_SRC)
    for action_id in (INSTALL, SCAN, OTHER):
        sched.register_scheduled_action(id=action_id, module_id="patchmanagement", label=action_id, handler=handler, target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, delegable_to=delegable)
    sa.register_system_action(SCAN, "patchmanagement", "Advanced Patch Management scan", "winupdate.scan", BOTH)
    for who in ("alice", "bob", "carol"):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = {1, 2, 3, 4}
        PERMS[who] = True
        user = {"alice": alice, "bob": bob, "carol": carol}[who]
        user.is_active = True
    AGENT_ROWS.update({pk: dict(row) for pk, row in ROWS.items()})
    DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    DESCRIPTORS["bob"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10, 20], "site_ids": []}
    DESCRIPTORS["carol"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
    CLOCK[0] = 1_000_000.0
    deleg._person_covers = lambda person, action, targets: set(SCOPE[person.username]) >= {1, 2}  # the strict scope check the real code asks of the person


def call(module, name, *args, **kw):
    return mods[module][name](sa, *args, **kw)


def describe(user=alice, *, caller="maintenance", **over):
    kw = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS, parameters=None)
    kw.update(over)
    return call(caller, "describe", RealRequest(user), **kw)


def register(token, user=alice, *, caller="maintenance", **over):
    kw = dict(owner_module="maintenance", grant_key=GK, provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS, parameters=None, confirmation_id=token)
    kw.update(over)
    return call(caller, "register", RealRequest(user), **kw)


def refused(call_, reason, kind=deleg.DelegationRefused):
    try:
        call_()
    except kind as exc:
        must(getattr(exc, "reason", None) == reason, (reason, getattr(exc, "reason", None), str(exc)))
        return exc
    raise AssertionError(f"accepted instead of {reason}")


def deny_rows():
    return [a for a in AUDITS if a["action"] == "deny"]


def grant_rows():
    return [a for a in AUDITS if a["object_type"] == "delegation_grant" and a["action"] != "deny"]


def grants():
    return Grant.objects.rows


# ---- (1) delegable_to
fresh()
definition = sa._ACTIONS[INSTALL]
must(definition.delegable_to == ("maintenance",) and sa.get_system_action(INSTALL)["delegable_to"] == ["maintenance"] and sa.get_system_action(SCAN)["delegable_to"] == [], "stored and listed")
for bad in ("maintenance", ["Maintenance"], [5], ["patchmanagement"], ["a", "b", "c", "d", "e", "f"], {"x": 1}):
    try:
        sa._build_definition(OTHER, "patchmanagement", "x", "winupdate.install", BOTH, "agents", False, None, bad)
        raise AssertionError(f"{bad!r} was accepted")
    except sa.SystemActionRegistrationError:
        pass
older = sa.SystemActionDefinition(SCAN, "patchmanagement", "APM scan", "winupdate.scan", BOTH, "agents", False, None, True)
must(older.delegable_to == () and sa.SystemActionDefinition(SCAN, "patchmanagement", "APM scan", "winupdate.scan", BOTH, "agents", False, None, True, ()) == older, "an older positional definition still builds and compares equal")
must(sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, delegable_to=("maintenance",)) is definition, "identical re-registration is idempotent")
try:
    sa.register_system_action(INSTALL, "patchmanagement", "Advanced Patch Management install", "winupdate.install", BOTH, delegable_to=("other",))
    raise AssertionError("a different definition was accepted")
except sa.SystemActionRegistrationError:
    pass
print("       delegable_to is validated, stored, listed, optional and keeps an older definition equal")

# ---- (2) describe_delegation: who may ask, what is checked
fresh()
good = describe()
must(good["required"] is True and good["expires_in"] == 600 and good["total"] == 2 and good["groups"] == 1 and good["confirmation_id"], good)
text = good["text"]
for needle in (
    "Advanced Patch Management install: 2 endpoint(s)", "group(s) of at most 2000", "maintenance will start this for you later", "with nobody signed in",
    "each time its own schedule says so", "Core checks that this confirmation is unchanged", "the modules involved are on", "the replacement is still in place",
    "every endpoint is inside the targets you confirm here", "Core does not look at your account again", "even if your account is later disabled",
    "Editing or removing the profile stops it", "Requested by alice. Do you want to continue?",
):
    must(needle in text, (needle, text))
must("does not check your rights" not in text and "checks your rights again each time it starts" not in text, "the old over-short and held sentences are gone")
LIVE_SWITCH = deleg.DECISION_RECORDED
deleg.DECISION_RECORDED = False  # the switch is tested explicitly: the text is the same, because it states the live behaviour
try:
    must(describe()["text"] == text, "one wording")
finally:
    deleg.DECISION_RECORDED = LIVE_SWITCH
must(sa.REAPPROVE_WARNING in text, "the re-approve warning stays while Tactical's own approve is not made inert here")
must(not deny_rows() and good["confirmation_id"].count(".") == 1, "no deny row for an allowed describe")
refused(lambda: sa.describe_delegation(RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS), "caller_unverified")  # Core code is not a module
refused(lambda: describe(caller="patchmanagement"), "wrong_module")  # another module may not describe for maintenance
refused(lambda: describe(owner_module="patchmanagement", caller="patchmanagement", provider_module="patchmanagement"), "not_delegable")  # the provider may not delegate to itself
for label, request in (("a user", alice), ("a stand-in", SimpleNamespace(user=alice, tec_tac_session=object())), ("a request with no session proof", RealRequest(alice, session=False))):
    refused(lambda request=request: call("maintenance", "describe", request, owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=TARGETS), "no_person")
refused(lambda: describe(action_id=SCAN), "not_delegable")  # the provider did not name maintenance for it
refused(lambda: describe(action_id="patchmanagement.nothing"), "unknown_action")
refused(lambda: describe(provider_module="patching"), "unknown_action")
refused(lambda: describe(owner_module="Maintenance!"), "bad_module")
fresh(delegable=())
refused(lambda: describe(), "not_delegable")
fresh()
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[SCAN, OTHER])  # the install is no longer listed in the signed manifest
refused(lambda: describe(), "action_not_declared")
fresh()
ENABLED["maintenance"] = False
refused(lambda: describe(caller="maintenance"), "caller_unverified")  # a disabled module is not a caller at all
ENABLED["maintenance"] = True
ENABLED["patchmanagement"] = False
refused(lambda: describe(), "module_disabled")
ENABLED["patchmanagement"] = True
HONOURED.clear()
refused(lambda: describe(), "replacement_not_honoured")
HONOURED["patchmanagement"] = "patching"
must(all("1" not in str(r["metadata"].get("agents", "")) for r in deny_rows()) and all(r["metadata"]["requested_by"] == "delegation" for r in deny_rows()), "deny rows carry a reason and no endpoint")
# the shared creation-time controls
for label, setup, reason in (
    ("no action permission", lambda: PERMS.update(alice=False), "not_permitted"),
    ("a missing Tactical flag", lambda: FLAGS.update(alice={"can_run_bulk"}), "not_permitted"),
    ("an endpoint outside the person's scope", lambda: SCOPE.update(alice={1}), "out_of_scope"),
):
    fresh()
    setup()
    n = len(deny_rows())
    try:
        describe()
        raise AssertionError(label)
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == reason, (label, exc.reason))
    must(len(deny_rows()) == n + 1, "one deny row")
fresh()
RESOLVED_MODULE_TARGETS.clear()
try:
    describe()
    raise AssertionError("no resolver")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "targets_unresolved", exc.reason)
fresh()
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = set(range(1, sa.MAX_AGENTS + 2))
try:
    describe()
    raise AssertionError("ceiling")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason in ("agent_count", "out_of_scope"), exc.reason)
fresh()
mgr = User("mgr")
FLAGS["mgr"] = set()
SCOPE["mgr"] = {1, 2}
PERMS["mgr"] = True
try:
    describe(user=mgr)
    raise AssertionError("a scheduler manager has no bypass for a Tactical flag")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "not_permitted", exc.reason)
print("       describe_delegation: only the owner module with a real request, only for an action the provider delegated and still lists, every creation-time control with one deny row each")

# ---- (3) register_delegation_grant
fresh()
token = describe()["confirmation_id"]
refused(lambda: register(None), "confirmation_required")
refused(lambda: register(""), "confirmation_required")
refused(lambda: register("garbage"), "confirmation_invalid")
refused(lambda: register(token, targets={"type": "profile", "ids": [8]}), "confirmation_invalid")  # other targets
refused(lambda: register(token, user=bob), "confirmation_invalid")  # another person
refused(lambda: register(token, action_id=SCAN), "not_delegable")
refused(lambda: register(token, grant_key="BAD KEY"), "bad_grant_key")
refused(lambda: register(token, caller="patchmanagement"), "wrong_module")
schedule_style = conf.describe_confirmation(alice, INSTALL, {"type": "endpoint", "ids": ["1", "2"]}, None, {"schedule_type": "once", "run_at": "now"})
refused(lambda: register(schedule_style["confirmation_id"]), "confirmation_invalid")  # a schedule's id cannot be reused here
refused(lambda: register(schedule_style["confirmation_id"], targets={"type": "endpoint", "ids": ["1", "2"]}), "confirmation_invalid")
CLOCK[0] += 601
refused(lambda: register(token), "confirmation_invalid")  # expired
must(not grants() and not grant_rows(), "a refused call stores nothing and writes no change row")
CLOCK[0] -= 601
done = register(token)
must(done == {"grant_key": GK, "created": True, "owner_changed": False}, done)
grant = grants()[0]
must(grant.owner_module == "maintenance" and grant.grant_key == GK and grant.provider_module == "patchmanagement" and grant.action_id == INSTALL, grant.__dict__)
must(grant.created_by is alice and grant.created_by_username == "alice" and grant.confirmed_by_username == "alice" and grant.enabled is True and grant.targets == TARGETS, grant.__dict__)
must(grant.creation_scope["captured_for"] == "alice" and grant.creation_scope["scope"]["whole_client_ids"] == [10] and sorted(grant.creation_scope["flags"]) == sorted(BOTH), grant.creation_scope)
rows = grant_rows()
must(len(rows) == 1 and rows[0]["action"] == "add" and rows[0]["strict"] is True and rows[0]["actor"] is alice and rows[0]["module_id"] == "core", rows)
meta = rows[0]["metadata"]
must(meta["owner_module"] == "maintenance" and meta["grant_key"] == GK and meta["provider_module"] == "patchmanagement" and meta["creator"] == "alice" and meta["total_agents"] == 2 and meta["groups"] == 1, meta)
must(not any(str(i) in repr(rows) for i in ("'1'", "'2'", "[1, 2]")) and "endpoint" not in repr(meta), "no endpoint id in the audit row")
digest_first = deleg.grant_digest(grant)
again = register(describe()["confirmation_id"])
must(again["created"] is False and again["owner_changed"] is False and len(grants()) == 1, again)
must(deleg.grant_digest(grant) != digest_first, "every save changes the digest, so every ticket made before it stops working")
must(len(grant_rows()) == 2 and grant_rows()[1]["action"] == "modify" and "owner_changed_from" not in grant_rows()[1]["metadata"], grant_rows())
print("       register needs the right id (not a schedule's, not for other arguments, not stale), stores the confirmed record, the person and the scope, writes one strict row and changes the digest on every save")

# ---- the limit and the strict audit
fresh()
for i in range(deleg.MAX_GRANTS_PER_OWNER):
    register(describe()["confirmation_id"], grant_key=f"profile:{i}")
must(len(grants()) == 20, len(grants()))
refused(lambda: register(describe()["confirmation_id"], grant_key="profile:99"), "grant_limit")
register(describe()["confirmation_id"], grant_key="profile:3")  # replacing an existing one is not a new grant
must(len(grants()) == 20, "the limit counts grants, not saves")
fresh()
token = describe()["confirmation_id"]
AUDIT_FAIL["strict"] = True
try:
    register(token)
    raise AssertionError("a strict audit failure must stop the grant")
except sched.SchedulerTransientError as exc:
    must("could not be written" in str(exc), exc)
AUDIT_FAIL["strict"] = False
print("       at most 20 grants per owner module; a strict audit failure stops the change")

# ---- a second person takes it over only when their own scope covers every target
fresh()
register(describe()["confirmation_id"])
before = dict(grants()[0].__dict__)
del AUDITS[:]
SCOPE["carol"] = {1}  # carol cannot see endpoint 2: her own scope does not cover the targets (but she may create the confirmation for a narrower set elsewhere)
RESOLVED_MODULE_TARGETS[("maintenance", "profile")] = {1, 2}
deleg._person_covers = lambda person, action, targets: set(SCOPE[person.username]) >= {1, 2}
carol_token = None
try:
    carol_token = describe(user=carol)["confirmation_id"]
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "out_of_scope", "the shared controls already refuse a person who cannot see every endpoint")
must(carol_token is None, "carol cannot even get the text")
SCOPE["carol"] = {1, 2, 3, 4}
deleg._person_covers = lambda person, action, targets: False  # the strict takeover check says no (for example a narrower role at takeover time)
carol_token = describe(user=carol)["confirmation_id"]
del AUDITS[:]
refused(lambda: register(carol_token, user=carol), "takeover_out_of_scope")
must(grants()[0].created_by is alice and grants()[0].created_by_username == "alice" and grants()[0].creation_scope == before["creation_scope"] and grants()[0].targets == before["targets"], "the grant is exactly as it was")
must(not grant_rows() and len(deny_rows()) == 1 and deny_rows()[0]["metadata"]["reason"] == "takeover_out_of_scope" and deny_rows()[0]["actor"] is carol, "one deny row, no change row")
deleg._person_covers = lambda person, action, targets: True
digest_before = deleg.grant_digest(grants()[0])
moved = register(carol_token, user=carol)
must(moved == {"grant_key": GK, "created": False, "owner_changed": True}, moved)
g = grants()[0]
must(g.created_by is carol and g.created_by_username == "carol" and g.confirmed_by_username == "carol" and g.creation_scope["captured_for"] == "carol", g.__dict__)
rows = grant_rows()
must(len(rows) == 1 and rows[0]["action"] == "modify" and rows[0]["strict"] is True and rows[0]["metadata"]["owner_changed_from"] == "alice" and rows[0]["metadata"]["owner_changed_to"] == "carol" and rows[0]["metadata"]["previous_confirmed_by"] == "alice", rows)
must(deleg.grant_digest(g) != digest_before, "a takeover revokes every ticket")
print("       a second person takes the grant over only when their own scope covers every target; otherwise nothing changes and one deny row is written; a move is one strict row")

# ---- (4) remove
fresh()
register(describe()["confirmation_id"])
refused(lambda: call("patchmanagement", "remove", owner_module="maintenance", grant_key=GK), "wrong_module")
refused(lambda: sa.remove_delegation_grant(owner_module="maintenance", grant_key=GK), "caller_unverified")
refused(lambda: call("maintenance", "remove", owner_module="maintenance", grant_key="BAD KEY"), "bad_grant_key")
must(len(grants()) == 1, "a refused removal removes nothing")
del AUDITS[:]
must(call("maintenance", "remove", owner_module="maintenance", grant_key=GK) is True and not grants(), "removed")
rows = [a for a in AUDITS if a["action"] == "delete" and a["object_type"] == "delegation_grant"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["metadata"]["grant_key"] == GK, rows)
must(call("maintenance", "remove", owner_module="maintenance", grant_key=GK) is False, "nothing left to remove")
register_again = register(describe()["confirmation_id"])
AUDIT_FAIL["strict"] = True
try:
    call("maintenance", "remove", owner_module="maintenance", grant_key=GK)
    raise AssertionError("a strict audit failure must stop the removal")
except sched.SchedulerTransientError:
    pass
AUDIT_FAIL["strict"] = False
must(register_again["created"] is True, "register after remove makes a fresh grant")
print("       remove is for the owner module only, writes one strict row, answers True or False, and stops on a strict audit failure")

# ---- (5) the older contract is unchanged
src = (APP / "system_actions.py").read_text(encoding="utf-8")
must("def run_system_action(context, *, action_id, agent_ids, parameters=None) -> dict:" in src, "run_system_action keeps its signature")
must("def describe_confirmation(self, request, *, action_id, targets, parameters=None, when=None) -> dict:" in src, "the capability's describe_confirmation keeps its signature")
must('"wrong_module": "Only the module that owns this run and this action can run it."' in src and "if identity.module_id != verified.module_id:" in src and "if definition.module_id != identity.module_id:" in src, "wrong_module stays as it was")
params = list(inspect.signature(sa.register_system_action).parameters)
must(params == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "delegable_to"], params)
for name in ("describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"):
    must(name in sa.OPERATIONS and callable(getattr(sa._PROVIDER, name)), name)
must(sa.OPERATIONS[:4] == ("list_actions", "get_action", "run", "describe_confirmation"), "the four earlier operations stay first")
print("       run_system_action, describe_confirmation and wrong_module are unchanged; the five operations are appended")
print("PASS delegation grant 1.17.68")
