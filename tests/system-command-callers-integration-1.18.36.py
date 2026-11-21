#!/usr/bin/env python3
# ruff: noqa: F821
"""1.18.36 regression (ORDER of 21 November 2026): the command row ``agent.command`` can be created AND run for TWO callers on the real code paths:
``softwarerepository`` and, on the legacy path, ``communicator`` (the compatibility proof). Same harness as ``system-command-integration-1.17.75.py``
(``scheduler-completion-harness-1.17.61.py``: real system_action_confirmation.py, scheduler.py, scheduler_run_context.py, caller_identity.py, system_actions.py and
system_commands.py).

Covered: each module creates its schedule through ``describe_confirmation`` and ``reconcile_schedule`` and its own handler reaches ``run_one``; the strict rows name the
calling module; a schedule that names templates of another module is refused ``bad_parameters`` when it is made (both directions); a stored schedule that names
another module's template is refused ``action_not_allowed`` at run time before the claim and the send (no confused deputy); the registrant and an unrelated module
may not schedule the row; the contract metadata lists callers and legacy_callers; the Scheduler keeps one scheduled action per id, so a second module cannot register
``remote-background.command`` while the first holds it (pinned: Software Repository's Schedule release needs Communicator 0.6.17 gone from that server).

What stays FAKED: as in the 1.17.75 test (Django models, audit sink, cache claim, the send, Tactical's roles and scope, the module registry, the clock) plus the route
and view guards of ``_send``, which the 1.17.75 test never faked and which need Tactical's urls.
"""
from __future__ import annotations

from datetime import time
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
conf._secret = lambda: b"test-secret-key"
conf._clock = lambda: 1_000_000.0
sc = sys.modules["tec_tac.system_commands"]
KNOWN_FLAGS.add("can_send_cmd")

CMD = "remote-background.command"
FLAGSET = {"can_send_cmd"}
BASE = 1000
alice = User("alice")
views = sys.modules["tec_tac.scheduler_views"]
views._can_use_action = lambda user, action: True
views._can_access_target_scope = lambda user, targets, **kw: True


class RealRequest:
    def __init__(self, user):
        self.user = user
        self.tec_tac_session = object()


mod("tec_tac.tactical_operations", _is_real_request=lambda request: isinstance(request, RealRequest))
_orig_save = Schedule.save


def _save(self, update_fields=None):
    if self not in Schedule.objects.rows:
        Schedule.objects.rows.append(self)
    _orig_save(self, update_fields)


Schedule.save = _save

SEEN = {"run_one": 0, "claims": 0, "resolve": 0, "sent": [], "callers": []}
_run_one, _resolve = sc.run_one, sc.resolve


def spy_run_one(**kw):
    SEEN["run_one"] += 1
    return _run_one(**kw)


def spy_resolve(command, cleaned, **kw):
    SEEN["resolve"] += 1
    SEEN["callers"].append(kw.get("caller"))
    return _resolve(command, cleaned, **kw)


def fake_claim(agent_id, command_id):
    SEEN["claims"] += 1
    return True


sc.run_one, sc.resolve, sc.claim, sc.release, sc.available = spy_run_one, spy_resolve, fake_claim, lambda a, c: None, lambda: True
sc.count_run = lambda run_id: 1
sc.route_agent_id = lambda pk: "A" * 21 + str(pk)
sc._already_recorded = lambda a, c: False
sc._service_user = lambda: object()
sc._check_route = lambda path: None  # the route guards need Tactical's urls (not faked by the 1.17.75 test, which ran before they existed)
sc._resolve_view = lambda path: None
sc._send = lambda route_agent, call, username, user=None: (SEEN["sent"].append((int(route_agent[21:]), call["shell"], call["command"], call["timeout"])), "done")[1]

LEAK = {}
CFG = {"action_id": CMD, "command": None}
HANDLER_SRC = (
    "def handler(context):\n"
    "    LEAK.clear()\n"
    "    try:\n"
    "        LEAK['out'] = sa.run_system_command(context, action_id=CFG['action_id'], command=CFG['command'])\n"
    "    except sa.SystemActionRefused as exc:\n"
    "        LEAK['err'] = exc.reason\n"
    "    return {'ok': True}\n"
)
READY = {
    "communicator": (
        "def ready():\n"
        "    sa.register_command_template('communicator', 'communicator.notice', shell='cmd', text='msg * /time:{mins} {text}', timeout=20,\n"
        "        slots={'mins': {'type': 'int', 'min': 1, 'max': 60}, 'text': {'type': 'text', 'max': 40, 'chars': 'abcdefghijklmnopqrstuvwxyz0123456789.:-'}})\n"
        "def hashes(ids):\n"
        "    return sa.command_template_hashes(ids)\n"
    ),
    "softwarerepository": (
        "def ready():\n"
        "    sa.register_command_template('softwarerepository', 'softwarerepository.launch', shell='powershell', text='Run-Package {token} {size} {host}', timeout=30,\n"
        "        slots={'token': {'type': 'text', 'max': 64, 'chars': '0123456789abcdef'}, 'size': {'type': 'text', 'max': 12, 'chars': '0123456789'},\n"
        "               'host': {'type': 'text', 'max': 100, 'chars': 'abcdefghijklmnopqrstuvwxyz0123456789.-'}})\n"
        "def hashes(ids):\n"
        "    return sa.command_template_hashes(ids)\n"
    ),
}
TEMPLATE = {"communicator": "communicator.notice", "softwarerepository": "softwarerepository.launch"}
RIGHT = {"communicator": "communicator.send", "softwarerepository": "softwarerepository.deploy"}
TOKEN, HOST = "a1b2c3d4" * 4, "repo.example.co.za"
GOOD = {
    "communicator": {"agent_id": BASE, "command_id": "run1-1000", "template_id": "communicator.notice", "params": {"mins": 5, "text": "reboot.soon"}},
    "softwarerepository": {"agent_id": BASE, "command_id": "run1-1000", "template_id": "softwarerepository.launch", "params": {"token": TOKEN, "size": "1073741824", "host": HOST}},
}
RENDERED = {"communicator": "msg * /time:5 reboot.soon", "softwarerepository": f"Run-Package {TOKEN} 1073741824 {HOST}"}


def endpoints(count=3):
    return {"type": "endpoint", "ids": [str(BASE + i) for i in range(count)]}


roots = {}
CODE = {}


def world(scheduler_module="communicator", perms=("can_send_cmd",)):
    """A fresh world. ``scheduler_module`` holds the Scheduler action ``remote-background.command`` (the Scheduler keeps one scheduled action per id)."""
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sc._TEMPLATES.clear()
    sched._ACTIONS.pop(CMD, None)
    SEEN.update(run_one=0, claims=0, resolve=0, sent=[], callers=[])
    for name in ("remote-background", "communicator", "softwarerepository", "checks"):
        roots[name] = plugin(name, system_actions=[CMD] if name == "remote-background" else [])
    AGENT_ROWS.update({BASE + i: {"agent_id": f"a{i}", "hostname": f"h{i}", "platform": "windows", "client_id": 10, "site_id": 1} for i in range(3)})
    DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    FLAGS["alice"] = set(FLAGSET)
    SCOPE["alice"] = set(range(BASE, BASE + 50))
    USERS_BY = {u.username: u for u in USERS.values()}
    USERS_BY["alice"].is_active = True
    sa.register_system_action(CMD, "remote-background", "Send a command", "agent.command", list(perms), dangerous=True)
    names = {"sa": sa, "LEAK": LEAK, "CFG": CFG}
    for name in ("communicator", "softwarerepository"):
        CODE[name] = compile_as(roots[name] / "code.py", HANDLER_SRC + READY[name], **names)
        CODE[name]["ready"]()
    sched.register_scheduled_action(id=CMD, module_id=scheduler_module, label=CMD, handler=CODE[scheduler_module]["handler"], target_types=("none", "endpoint"), timeout_seconds=600, unattended=True)
    return CODE


def params(module, ids=None, rights=None):
    ids = ids or [TEMPLATE[module]]
    owner_of_ids = ids[0].split(".")[0]
    return {"system_action_parameters": {"allowed_templates": ids, "template_hashes": CODE[owner_of_ids]["hashes"](ids), "rights": rights or [RIGHT[owner_of_ids]], "max_timeout": 30}}


KW = {"schedule_type": "daily", "run_time": time(3, 0)}
DAILY = {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"}


def create(module, parameters=None):
    parameters = parameters or params(module)
    said = conf.describe_confirmation(alice, CMD, endpoints(), parameters, DAILY)
    return sched.reconcile_schedule(owner_module=module, owner_key="deploy", action_id=CMD, targets=endpoints(), parameters=parameters,
                                    confirmed_by_request=RealRequest(alice), confirmation_id=said["confirmation_id"], **KW), said


def run_of(schedule, module):
    return Run.objects.create(schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=module, action_id=CMD, owner_type=schedule.owner_type,
                              manual=False, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", scheduled_for=NOW[0],
                              retry_count_snapshot=0, last_queued_at=NOW[0], targets_snapshot=dict(schedule.targets), parameters_snapshot=dict(schedule.parameters))


def deny_reasons():
    return [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def action(module):
    return SimpleNamespace(id=CMD, module_id=module)


# ---- the contract metadata
world()
meta = sa.system_actions_contract_metadata()["command"]
must(meta["callers"] == ["softwarerepository"] and meta["legacy_callers"] == ["communicator"], meta["callers"])
must(meta["rights_by_module"] == {"communicator": ["communicator.send", "communicator.reboot"], "softwarerepository": ["softwarerepository.deploy"]} and meta["one_module_per_schedule"] is True, meta)
must(sa.system_actions_contract_metadata()["version"] == "1.6.0", "core.system_actions stays at 1.6.0")
must(sa.is_registered_system_action("softwarerepository", CMD) and sa.is_registered_system_action("communicator", CMD)
     and not sa.is_registered_system_action("remote-background", CMD) and not sa.is_registered_system_action("checks", CMD) and not sa.is_registered_system_action("endpoint-comms", CMD),
     "softwarerepository and (legacy) communicator may schedule the row; the registrant and others may not")
must(sa.declaring_module("softwarerepository", CMD) == "remote-background" and sa.declaring_module("communicator", CMD) == "remote-background" and sa.declaring_module("checks", CMD) == "checks",
     "remote-background lists the id in its signed manifest for both callers")
print("       the contract metadata lists callers and legacy_callers; both callers are registered, others are not")

# ---- each module: create the schedule, run it, check the rows
for module in ("softwarerepository", "communicator"):
    world(module)
    schedule, said = create(module)
    must(said["required"] is True and TEMPLATE[module] in said["text"] and "fixed commands" in said["text"], said)
    must(schedule.module_id == module and schedule.action_id == CMD and schedule.created_by_username == "alice", f"the schedule is {module}'s, made by the person")
    must(not deny_reasons(), "creation wrote no deny row")
    CFG.update(action_id=CMD, command=dict(GOOD[module]))
    run = run_of(schedule, module)
    out = go(run)
    must(run.status == "succeeded" and out != "retried", (run.__dict__, out))
    must(SEEN["run_one"] == 1 and LEAK.get("out", {}).get("outcome") == "ran" and "err" not in LEAK, (SEEN, LEAK))
    must(SEEN["callers"] == [module], f"resolve got the verified caller {module}: {SEEN['callers']}")
    must(SEEN["sent"] == [(BASE, "cmd" if module == "communicator" else "powershell", RENDERED[module], 20 if module == "communicator" else 30)], (module, SEEN["sent"]))
    rows_ = [a for a in AUDITS if a["object_type"] == "system_action" and a["action"] in ("run", sc.CLOSING_ACTION)]
    must(len(rows_) == 2 and all(r["metadata"]["run_as"] == module and r["metadata"]["caller_module"] == module for r in rows_), [r["metadata"] for r in rows_])
    must(f"as the {module} module" in rows_[0]["message"] and rows_[0]["metadata"]["template_id"] == TEMPLATE[module], rows_[0]["message"])
    must(RENDERED[module] not in repr(AUDITS) and TOKEN not in repr(AUDITS) and HOST not in repr(AUDITS), "strict rows hold the template, never the text, the token or the host")
    print(f"       {module}: the person creates the schedule, its handler reaches run_one, the rows name {module}")

# ---- creation: a schedule of one module may not name another module's templates
for module, other in (("softwarerepository", "communicator"), ("communicator", "softwarerepository")):
    world(module)
    mixed = params(module, ids=[TEMPLATE[other]])
    try:
        conf._controls(alice, action(module), endpoints(), mixed)
        must(False, f"{module} may not schedule {other}'s templates")
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == "bad_parameters", (module, exc.reason))
    must(deny_reasons() == ["bad_parameters"], deny_reasons())
    conf._controls(alice, action(module), endpoints(), params(module))
    must(deny_reasons() == ["bad_parameters"], "its own templates are accepted")
    both = params(module, ids=sorted(TEMPLATE.values()), rights=["communicator.send", "softwarerepository.deploy"])
    try:
        conf._controls(alice, action(module), endpoints(), both)
        must(False, "two modules' templates in one schedule are refused")
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == "bad_parameters", exc.reason)
    print(f"       a {module} schedule naming {other}'s templates is refused bad_parameters when it is made")

# ---- creation: the registrant itself and an unrelated module are refused
world("softwarerepository")
for who in ("remote-background", "checks", "endpoint-comms"):
    try:
        conf._controls(alice, action(who), endpoints(), params("softwarerepository"))
        must(False, f"{who} may not schedule the command row")
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == "unknown_action", (who, exc.reason))
print("       the registrant and unrelated modules cannot schedule the command row")

# ---- run: a stored schedule that names another module's template is refused before the claim (no confused deputy)
for module, other in (("softwarerepository", "communicator"), ("communicator", "softwarerepository")):
    world(module)
    schedule, said = create(module)
    schedule.parameters = params(module, ids=[TEMPLATE[other]])  # what a tampered or bad stored schedule would hold
    CFG.update(action_id=CMD, command=dict(GOOD[other]))
    run = run_of(schedule, module)
    go(run)
    must(LEAK.get("err") == "action_not_allowed" and SEEN["claims"] == 0 and SEEN["sent"] == [] and SEEN["run_one"] == 0, (module, LEAK, SEEN))
    must(SEEN["callers"] == [module] and run.status == "succeeded", "the refusal is judged against the verified caller and does not end the run")
    print(f"       a {module} run naming {other}'s template is action_not_allowed before the claim and the send")

# ---- 1.18.36 (AD-60, fail closed): the row is registered with NO flags, exactly as remote-background does; the new caller still needs can_send_cmd
world("softwarerepository", perms=())
FLAGS["alice"] = set()
try:
    conf._controls(alice, action("softwarerepository"), endpoints(), params("softwarerepository"))
    must(False, "a softwarerepository schedule by an owner without can_send_cmd is refused")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "not_permitted", exc.reason)
try:
    create("softwarerepository")
    must(False, "describe_confirmation refuses too")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "not_permitted", exc.reason)
FLAGS["alice"] = set(FLAGSET)
schedule, said = create("softwarerepository")
must(schedule.module_id == "softwarerepository", "with can_send_cmd the schedule is made")
print("       softwarerepository without can_send_cmd is refused not_permitted at creation (row registered with no flags)")

CFG.update(action_id=CMD, command=dict(GOOD["softwarerepository"]))
schedule.creation_scope = dict(schedule.creation_scope, flags=[f for f in schedule.creation_scope["flags"] if f != "can_send_cmd"])
FLAGS["alice"] = set(FLAGSET)  # the live role is irrelevant for an unattended run: the stored flags decide
run = run_of(schedule, "softwarerepository")
go(run)
must(LEAK.get("err") == "permission_lost" and SEEN["claims"] == 0 and SEEN["sent"] == [] and SEEN["run_one"] == 0, (LEAK, SEEN))
must("permission_lost" in deny_reasons(), deny_reasons())
print("       a stored softwarerepository schedule without can_send_cmd at creation is refused permission_lost, nothing sent")

world("softwarerepository", perms=())
schedule, said = create("softwarerepository")
CFG.update(action_id=CMD, command=dict(GOOD["softwarerepository"]))
run = run_of(schedule, "softwarerepository")
go(run)
must(LEAK.get("out", {}).get("outcome") == "ran" and len(SEEN["sent"]) == 1, (LEAK, SEEN))
print("       with the flag held at creation the softwarerepository run is sent")

world("communicator", perms=())
FLAGS["alice"] = set()
schedule, said = create("communicator")
CFG.update(action_id=CMD, command=dict(GOOD["communicator"]))
run = run_of(schedule, "communicator")
go(run)
must(LEAK.get("out", {}).get("outcome") == "ran" and len(SEEN["sent"]) == 1 and "err" not in LEAK, (LEAK, SEEN))
print("       the Communicator legacy path still creates and runs without can_send_cmd (AD-50)")

# ---- the Scheduler keeps one scheduled action per id (pinned limitation, see the release notes)
world("communicator")
try:
    sched.register_scheduled_action(id=CMD, module_id="softwarerepository", label=CMD, handler=CODE["softwarerepository"]["handler"], target_types=("none", "endpoint"), timeout_seconds=600, unattended=True)
    must(False, "a second module cannot hold the same scheduled action id")
except sched.SchedulerError:
    must(True, "a second module cannot hold the same scheduled action id")
print("       pinned: remote-background.command is one scheduled action per server; the second module's registration is refused")

print("PASS system command callers integration 1.18.36")
