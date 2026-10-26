#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.77 regression: a person makes the Communicator background sending schedule (the worker of ``remote-background.command``) in the Scheduler.

Same real code paths and the same stub harness as ``system-command-integration-1.17.75.py``. Covered: (1) Core takes Communicator's scheduled action
``remote-background.command`` beside Remote Background's system action row of the same id; (2) a person creates the schedule with a CLIENT target (and a site
target) and the run may send to an endpoint of that client that did not exist when the schedule was saved, while an endpoint of another client is refused
``outside_targets``; an ENDPOINT-list schedule refuses a queued endpoint that is not on its list; (3) the confirmed parameters are exactly
``allowed_templates``, ``template_hashes``, ``rights`` and (optional) ``max_timeout``, so the shape in the request, without ``rights``, is refused
``bad_parameters`` at creation.
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
OTHER = "communicator.other"
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

SEEN = {"run_one": 0, "claims": 0, "resolve": 0, "sent": []}
_run_one, _resolve = sc.run_one, sc.resolve


def spy_run_one(**kw):
    SEEN["run_one"] += 1
    return _run_one(**kw)


def spy_resolve(command, cleaned):
    SEEN["resolve"] += 1
    return _resolve(command, cleaned)


def fake_claim(agent_id, command_id):
    SEEN["claims"] += 1
    return True


sc.run_one, sc.resolve, sc.claim, sc.release, sc.available = spy_run_one, spy_resolve, fake_claim, lambda a, c: None, lambda: True
sc.count_run = lambda run_id: 1
sc.route_agent_id = lambda pk: "A" * 21 + str(pk)
sc._already_recorded = lambda a, c: False
sc._check_route = lambda path: None  # 1.17.79: run_one checks the route before the claim; the owner table is covered by system-command-1.17.78.py and 1.17.79.py
sc._service_user = lambda: object()  # 1.17.76: run_one reads the installed service user first; the dispatch itself is faked here
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
READY_SRC = (
    "def ready():\n"
    "    sa.register_command_template('communicator', 'communicator.notice', shell='cmd', text='msg * /time:{mins} {text}', timeout=20,\n"
    "        slots={'mins': {'type': 'int', 'min': 1, 'max': 60}, 'text': {'type': 'text', 'max': 40, 'chars': 'abcdefghijklmnopqrstuvwxyz0123456789.:-'}})\n"
    "def hashes(ids):\n"
    "    return sa.command_template_hashes(ids)\n"
)


def endpoints(count=3):
    return {"type": "endpoint", "ids": [str(BASE + i) for i in range(count)]}


roots = {}


def world():
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    sc._TEMPLATES.clear()
    SEEN.update(run_one=0, claims=0, resolve=0, sent=[])
    for name in ("remote-background", "communicator", "checks"):
        roots[name] = plugin(name, system_actions=[CMD] if name == "remote-background" else [])
    AGENT_ROWS.update({BASE + i: {"agent_id": f"a{i}", "hostname": f"h{i}", "platform": "windows", "client_id": 10, "site_id": 1} for i in range(3)})
    DESCRIPTORS["alice"] = {"mode": "clients", "unrestricted": False, "whole_client_ids": [10], "site_ids": []}
    FLAGS["alice"] = set(FLAGSET)
    SCOPE["alice"] = set(range(BASE, BASE + 50))
    USERS_BY = {u.username: u for u in USERS.values()}
    USERS_BY["alice"].is_active = True
    sa.register_system_action(CMD, "remote-background", "Send a command", "agent.command", ["can_send_cmd"], dangerous=True)
    names = {"sa": sa, "LEAK": LEAK, "CFG": CFG}
    comm = compile_as(roots["communicator"] / "code.py", HANDLER_SRC + READY_SRC, **names)
    comm["ready"]()
    chk = compile_as(roots["checks"] / "code.py", HANDLER_SRC, **names)
    for aid, module, fn in ((CMD, "communicator", comm["handler"]), (OTHER, "communicator", comm["handler"]), ("checks.cmd", "checks", chk["handler"])):
        if aid not in sched._ACTIONS:
            sched.register_scheduled_action(id=aid, module_id=module, label=aid, handler=fn, target_types=("none", "endpoint"), timeout_seconds=600, unattended=(aid == CMD))
    return comm


def params(comm):
    ids = ["communicator.notice"]
    return {"system_action_parameters": {"allowed_templates": ids, "template_hashes": comm["hashes"](ids), "rights": ["communicator.send"], "max_timeout": 30}}


KW = {"schedule_type": "daily", "run_time": time(3, 0)}
DAILY = {"schedule_type": "daily", "run_time": "03:00", "timezone": "UTC"}


def create(comm, module="communicator", action=CMD):
    parameters = params(comm)
    said = conf.describe_confirmation(alice, action, endpoints(), parameters, DAILY)
    return sched.reconcile_schedule(owner_module=module, owner_key="notice", action_id=action, targets=endpoints(), parameters=parameters,
                                    confirmed_by_request=RealRequest(alice), confirmation_id=said["confirmation_id"], **KW), said


def run_of(schedule, module="communicator", action=CMD):
    return Run.objects.create(schedule=schedule, schedule_snapshot_id=schedule.id, schedule_name="s", module_id=module, action_id=action, owner_type=schedule.owner_type,
                              manual=False, owner_module=schedule.owner_module, owner_key=schedule.owner_key, status="queued", scheduled_for=NOW[0],
                              retry_count_snapshot=0, last_queued_at=NOW[0], targets_snapshot=dict(schedule.targets), parameters_snapshot=dict(schedule.parameters))


def deny_reasons():
    return [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


GOOD = {"agent_id": BASE, "command_id": "run1-1000", "template_id": "communicator.notice", "params": {"mins": 5, "text": "reboot.soon"}}


def worker_world(types_=("client", "site", "endpoint")):
    comm = world()
    sched._ACTIONS.pop(CMD, None)
    names = {"sa": sa, "LEAK": LEAK, "CFG": CFG}
    comm2 = compile_as(roots["communicator"] / "code.py", HANDLER_SRC + READY_SRC.replace("def ready", "def ready2"), **names)
    sched.register_scheduled_action(id=CMD, module_id="communicator", label="Communicator background sending", handler=comm2["handler"], target_types=tuple(types_),
                                    timeout_seconds=600, unattended=True)
    CLIENT_AGENTS.clear()
    CLIENT_AGENTS[10] = {BASE, BASE + 1}
    SITE_AGENTS.clear()
    SITE_AGENTS[1] = {BASE, BASE + 1}
    return comm


def make(comm, targets, parameters=None):
    parameters = parameters or params(comm)
    said = conf.describe_confirmation(alice, CMD, targets, parameters, DAILY)
    return sched.reconcile_schedule(owner_module="communicator", owner_key="worker", action_id=CMD, targets=targets, parameters=parameters,
                                    confirmed_by_request=RealRequest(alice), confirmation_id=said["confirmation_id"], **KW), said


# (1) + (2) a client target: the schedule is made, and a later endpoint of the client is sent to
for kind, key, value in (("client", "client", 10), ("site", "site", 1)):
    comm = worker_world()
    schedule, said = make(comm, {"type": kind, "ids": [value]})
    must(schedule.module_id == "communicator" and schedule.action_id == CMD and not deny_reasons(), f"a {kind} target creates the worker schedule")
    AGENT_ROWS[BASE + 7] = {"agent_id": "late", "hostname": "late", "platform": "windows", "client_id": 10, "site_id": 1}
    (CLIENT_AGENTS if kind == "client" else SITE_AGENTS)[value].add(BASE + 7)
    CFG.update(action_id=CMD, command={**GOOD, "agent_id": BASE + 7, "command_id": f"late-{kind}"})
    run = run_of(schedule)
    go(run)
    must(LEAK.get("out", {}).get("outcome") == "ran" and SEEN["run_one"] == 1, (kind, LEAK, deny_reasons()))
    print(f"       a {kind} target: an endpoint added to it after the schedule was saved is sent to")

# an endpoint of another client is outside the targets
comm = worker_world()
schedule, said = make(comm, {"type": "client", "ids": [10]})
AGENT_ROWS[BASE + 8] = {"agent_id": "far", "hostname": "far", "platform": "windows", "client_id": 11, "site_id": 2}
CFG.update(action_id=CMD, command={**GOOD, "agent_id": BASE + 8, "command_id": "far-1"})
run = run_of(schedule)
go(run)
must(LEAK.get("err") == "outside_targets" and SEEN["run_one"] == 0 and SEEN["claims"] == 0, (LEAK, SEEN))
print("       an endpoint of another client is refused outside_targets; nothing is claimed or sent")

# an endpoint-list schedule refuses a queued endpoint that is not on its list
comm = worker_world()
schedule, said = make(comm, {"type": "endpoint", "ids": [str(BASE)]})
CFG.update(action_id=CMD, command={**GOOD, "agent_id": BASE + 1, "command_id": "unlisted-1"})
run = run_of(schedule)
go(run)
must(LEAK.get("err") == "outside_targets" and SEEN["run_one"] == 0, (LEAK, SEEN))
print("       an endpoint-list schedule refuses a queued endpoint that is not on its list")

# a client target is refused when the module registered the action for endpoints only
comm = worker_world(("endpoint", "endpoints"))
try:
    make(comm, {"type": "client", "ids": [10]})
    must(False, "a client target needs the action to list it in target_types")
except Exception as exc:  # noqa: BLE001
    must("target" in str(exc).lower() or "type" in str(exc).lower(), str(exc))
print("       an action that lists only endpoint targets refuses a client target")

# (3) the parameters shape: without rights it is refused at creation
comm = worker_world()
bad = {"system_action_parameters": {k: v for k, v in params(comm)["system_action_parameters"].items() if k != "rights"}}
try:
    conf._controls(alice, SimpleNamespace(id=CMD, module_id="communicator"), {"type": "client", "ids": [10]}, bad)
    must(False, "parameters without rights are refused")
except conf.SystemActionCreationRefused as exc:
    must(exc.reason == "bad_parameters", exc.reason)
good = {k: v for k, v in params(comm)["system_action_parameters"].items() if k != "max_timeout"}
conf._controls(alice, SimpleNamespace(id=CMD, module_id="communicator"), {"type": "client", "ids": [10]}, {"system_action_parameters": good})
print("       the confirmed parameters need rights; max_timeout is optional")

print("PASS system command worker schedule 1.17.77")
