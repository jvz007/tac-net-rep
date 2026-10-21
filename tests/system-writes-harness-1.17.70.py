#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""Shared stub harness for the 1.17.70 system-write tests (exec'd by them, like scheduler-completion-harness-1.17.61.py, which it builds on).

It adds, on top of the 1.17.61 harness: an in-memory stand-in of Tactical's ``winupdate.models.WinUpdate`` and
``winupdate.serializers.WinUpdateSerializer`` (so the REAL ``system_writes.py`` seams run: the update-to-endpoint read, the 'before' read and the locked
compare-and-set write), the real ``system_writes.py`` itself, an honoured replacement ``patchmanagement`` of ``patching``, a handler compiled under that
module's folder (so the real frame walk names the caller) and small helpers. No Django, no database.

Run on its own, this file only builds the harness and prints nothing.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True

# ---- Tactical's WinUpdate, as much of it as Core touches
UPD: dict = {}  # update number -> {"agent": endpoint number, "action": str, "installed": bool, "kb": str}
HOOKS = {"before_lock": None, "serializer_fail": False, "read_fail": False, "after_save": None}
SER_CALLS: list = []  # every (update number, data) the serializer saved
LOCKED: list = []  # the update numbers read under a row lock
CHOICES = ("inherit", "approve", "ignore", "nothing")


class _Row:
    def __init__(self, pk):
        self.pk = pk
        self.action = UPD[pk]["action"]
        self.installed = UPD[pk]["installed"]
        self.kb = UPD[pk]["kb"]


class _QS(list):
    def order_by(self, *fields):
        return _QS(sorted(self, key=lambda r: r.pk))

    def values_list(self, *fields):
        out = []
        for row in self:
            values = {"pk": row.pk, "agent__pk": UPD[row.pk]["agent"], "action": row.action}
            out.append(tuple(values[f] for f in fields))
        return out


class _Objects:
    def __init__(self, locking=False):
        self.locking = locking

    def select_for_update(self):
        if HOOKS["before_lock"]:
            HOOKS["before_lock"]()  # a person decides here, between Core's 'before' read and its locked write
        return _Objects(True)

    def filter(self, pk__in):
        if HOOKS["read_fail"]:
            raise RuntimeError("tactical database unreachable")
        wanted = set(pk__in)
        rows = _QS(_Row(pk) for pk in sorted(UPD) if pk in wanted)
        if self.locking:
            LOCKED.extend(row.pk for row in rows)
        return rows


class WinUpdate:
    objects = _Objects()


class WinUpdateSerializer:
    """The stand-in of Tactical's ModelSerializer(fields='__all__'): a partial save of ``action`` only; any other column in ``data`` is a test failure."""

    def __init__(self, instance=None, data=None, partial=False, context=None):
        self.instance, self.data_in, self.partial, self.context = instance, dict(data or {}), partial, context

    def is_valid(self, raise_exception=False):
        must(self.partial is True, "the serializer must be saved partial")
        must(set(self.data_in) == {"action"}, f"only the action column may be written, got {sorted(self.data_in)}")
        must(self.data_in["action"] in CHOICES, "a valid choice")
        return True

    def save(self):
        if HOOKS["serializer_fail"]:
            raise RuntimeError("tactical refused the save")
        SER_CALLS.append((self.instance.pk, dict(self.data_in)))
        UPD[self.instance.pk]["action"] = self.data_in["action"]
        if HOOKS["after_save"]:
            HOOKS["after_save"](self.instance.pk)


mod("winupdate.models", WinUpdate=WinUpdate)
mod("winupdate.serializers", WinUpdateSerializer=WinUpdateSerializer)
writer = load("tec_tac.system_writes", "system_writes.py")

BOTH = ("can_manage_winupdates", "can_run_bulk")
WRITE_FLAGS = ("can_manage_winupdates",)
WRITE = "patchmanagement.setaction"  # the system action id the honoured replacement registers
HANDLER = "patchmanagement.handler"  # its Scheduler action
BASE = 1000  # first endpoint number
UBASE = 5000  # first update number
ALLOWED = {"allowed_actions": ["approve", "ignore"]}
CONFIRMED = {sa.PARAMETERS_KEY: ALLOWED}
CFG = {"action_id": WRITE, "changes": [], "agents": [], "task_action": "patching.scan"}
roots: dict = {}
alice = User("alice")
HANDLER_SRC = (
    "def handler(context):\n"
    "    return sa.run_system_write(context, action_id=CFG['action_id'], changes=CFG['changes'])\n"
    "def task_handler(context):\n"
    "    return sa.run_system_action(context, action_id=CFG['action_id'], agent_ids=CFG['agents'])\n"
)
AUTO_TARGETS = lambda: {"type": "endpoint", "ids": [str(i) for i in CFG["agents"]]}  # noqa: E731 - the schedule targets exactly the endpoints in play


def fresh(updates=0, agents=3):
    """A clean world: ``agents`` endpoints, ``updates`` Windows updates spread over them (all 'nothing'), Windows Patching, and Advanced Patch
    Management as the honoured replacement with the write action registered."""
    reset()
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    sa._clear_for_tests()
    UPD.clear()
    SER_CALLS.clear()
    LOCKED.clear()
    HOOKS.update(before_lock=None, serializer_fail=False, read_fail=False, after_save=None)
    roots["patching"] = plugin("patching", system_actions=["patching.scan"])
    roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=[WRITE])
    HONOURED["patchmanagement"] = "patching"
    for who in ("alice",):
        FLAGS[who] = set(BOTH)
        SCOPE[who] = set(range(BASE, BASE + 41000))
    CFG.update(action_id=WRITE, changes=[], agents=list(range(BASE, BASE + agents)), task_action="patching.scan")
    for i in range(updates):
        UPD[UBASE + i] = {"agent": BASE + (i % agents), "action": "nothing", "installed": False, "kb": f"KB{i}"}
    ns = compile_as(roots["patchmanagement"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
    for action_id, name in ((HANDLER, "handler"), ("patchmanagement.task_handler", "task_handler")):
        if action_id not in sched._ACTIONS:
            sched.register_scheduled_action(id=action_id, module_id="patchmanagement", label=name, handler=ns[name], target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sa.register_system_action(WRITE, "patchmanagement", "Advanced Patch Management update decisions", "winupdate.set_action", WRITE_FLAGS, dangerous=True)
    sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)


def decide(numbers, action="approve"):
    return [{"update_id": n, "action": action} for n in numbers]


def start(changes=None, *, handler=HANDLER, module="patchmanagement", retries=0, params=CONFIRMED, **kw):
    """A person-started run (manual) with the confirmed parameters on its snapshot. Returns ``(run, what the handler returned or raised)``."""
    if changes is not None:
        CFG["changes"] = changes
    run = make_run(handler, module, user=alice, owner="user", retries=retries, manual=True, **kw)
    if params is not None:
        run.parameters_snapshot = {**dict(run.parameters_snapshot or {}), **params}
    return run, go(run, retries=0)


def deny_reasons():
    return [a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny" and a["object_type"] == "system_action"]


def before_rows():
    return [a for a in AUDITS if a["action"] == "run" and a["object_type"] == "system_action"]


def closing_rows():
    return [a for a in AUDITS if a["action"] == writer.CLOSING_ACTION]


def group_marks(run):
    return [m for m in run.system_action_marks if m.get("kind") != "plan"]


def current(numbers):
    return {n: UPD[n]["action"] for n in numbers}


def refused_with(out, reason):
    """The handler returned an exception: it must be a SystemActionRefused with ``reason``."""
    must(isinstance(out, sa.SystemActionRefused) and out.reason == reason, (reason, repr(out)))
