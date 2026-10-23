#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.75 regression (AD-45, AD-49): ``agent.command`` can be created AND run, end to end, on the real code paths.

Real files on the stub harness (``scheduler-completion-harness-1.17.61.py``): system_action_confirmation.py (``describe_confirmation`` and the creation
checks), scheduler.py (``reconcile_schedule``, ``register_scheduled_action``, the worker through ``execute_schedule_run``), scheduler_run_context.py,
caller_identity.py (the real stack walk: the handler and the registration code are compiled under Communicator's directory), system_actions.py
(``_run``) and system_commands.py (templates, ``resolve``, ``run_one``).

Covered: the schedule is owned by ``communicator`` (on the row's callers) while ``remote-background`` registered and declares the row; the person
creates it through ``describe_confirmation`` and ``reconcile_schedule`` (the registrant itself, and a module off the callers list, are refused
``unknown_action``); the Communicator handler reaches ``run_one`` and the command is the rendered template; a run of another module gets
``wrong_module``; a Communicator run whose own action is another one gets ``wrong_module`` before ``resolve`` and before the claim (no confused
deputy); a missing stored creation scope is ``creation_scope_unavailable``, one deny row, the run not ended.

What stays FAKED: the Django models (stub Schedule and Run), the audit sink, the cache claim and the send to the agent (``claim``, ``release``,
``available`` and ``_send`` are replaced; ``run_one`` and everything around it is real), Tactical's roles and scope, the module registry and the clock.
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

# ---- creation: the person creates a schedule owned by communicator through describe_confirmation and reconcile_schedule
comm = world()
schedule, said = create(comm)
must(said["required"] is True and "communicator.notice" in said["text"] and "fixed commands" in said["text"], said)
must(schedule.module_id == "communicator" and schedule.action_id == CMD and schedule.created_by_username == "alice", "the schedule is Communicator's, made by the person")
must(not deny_reasons(), "creation wrote no deny row")
print("       a person creates the command schedule for communicator through describe_confirmation and reconcile_schedule")

# ---- creation refusals: the registrant itself and a module off the callers list
comm = world()
parameters = params(comm)
for who in ("remote-background", "checks"):
    try:
        conf._controls(alice, SimpleNamespace(id=CMD, module_id=who), endpoints(), parameters)
        must(False, f"{who} may not schedule the command row")
    except conf.SystemActionCreationRefused as exc:
        must(exc.reason == "unknown_action", (who, exc.reason))
conf._controls(alice, SimpleNamespace(id=CMD, module_id="communicator"), endpoints(), parameters)
must(deny_reasons() == ["unknown_action", "unknown_action"], deny_reasons())
must(not sa.is_registered_system_action("checks", CMD) and not sa.is_registered_system_action("remote-background", OTHER) and sa.is_registered_system_action("communicator", CMD)
     and not sa.is_registered_system_action("remote-background", CMD), "only a module on callers schedules the row; the registrant never does")
print("       the registrant itself and a module off the callers list cannot schedule the command row")

# ---- the run: the Communicator handler reaches run_one
comm = world()
schedule, said = create(comm)
CFG.update(action_id=CMD, command=dict(GOOD))
run = run_of(schedule)
out = go(run)
must(run.status == "succeeded" and out != "retried", (run.__dict__, out))
must(SEEN["run_one"] == 1 and LEAK.get("out", {}).get("outcome") == "ran" and "err" not in LEAK, (SEEN, LEAK))
must(SEEN["sent"] == [(BASE, "cmd", "msg * /time:5 reboot.soon", 20)], "Core rendered the template; the shell and the timeout came from the template")
rows_ = [a for a in AUDITS if a["object_type"] == "system_action" and a["action"] in ("run", sc.CLOSING_ACTION)]
must(len(rows_) == 2 and rows_[0]["metadata"]["template_id"] == "communicator.notice" and "reboot.soon" not in repr(AUDITS), "strict rows hold the template, never the text")
print("       the Communicator handler of the schedule reaches run_one; the command is the rendered template")

# ---- a run of another module gets wrong_module
comm = world()
CFG.update(action_id=CMD, command=dict(GOOD))
run = make_run("checks.cmd", "checks", user=alice, owner="user", targets=endpoints())
go(run)
must(LEAK.get("err") == "wrong_module" and SEEN["run_one"] == 0 and SEEN["claims"] == 0 and SEEN["resolve"] == 0 and deny_reasons() == ["wrong_module"], (LEAK, SEEN, deny_reasons()))
print("       a run of a module off the callers list gets wrong_module")

# ---- confused deputy: a Communicator run of ANOTHER action may not drive the command row
comm = world()
CFG.update(action_id=CMD, command=dict(GOOD))
run = make_run(OTHER, "communicator", user=alice, owner="user", targets=endpoints())
go(run)
must(LEAK.get("err") == "wrong_module" and SEEN["resolve"] == 0 and SEEN["claims"] == 0 and SEEN["run_one"] == 0 and deny_reasons() == ["wrong_module"], (LEAK, SEEN, deny_reasons()))
must(run.status == "succeeded", "a refusal of a command call does not end the run")
print("       a Communicator run whose own action differs is refused wrong_module before resolve and before the claim")

# ---- no stored creation scope: refused, one deny row, the run is not ended
comm = world()
schedule, said = create(comm)
schedule.creation_scope = {}
CFG.update(action_id=CMD, command=dict(GOOD))
run = run_of(schedule)
go(run)
must(LEAK.get("err") == "creation_scope_unavailable" and deny_reasons() == ["creation_scope_unavailable"], (LEAK, deny_reasons(), AUDITS))
must(run.status == "succeeded" and SEEN["claims"] == 0 and SEEN["run_one"] == 0, "the run was not ended and nothing was claimed or sent")
print("       a missing stored creation scope is creation_scope_unavailable with one deny row; the run is not ended")

print("PASS system command integration 1.17.75")
