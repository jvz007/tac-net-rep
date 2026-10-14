#!/usr/bin/env python3
"""1.17.33 regression: the dev-server probe (tests/tactical-websocket-runtime-1.17.33.py), checked on the development PC with no Django.

The probe itself needs Django, channels, Redis and Tactical, which are only on the dev server. This test reads it with ast.

Covered: pick_agent is extracted and run against a fake Agent. The fake raises FieldError on exclude(status=...) and filter(status=...)
and carries status as a Python property, as Tactical v1.5.2 does (agents/models.py). An offline agent is chosen in Python, and the walk
stops at the first match; the environment override wins and must find its agent; all agents online gives the first agent and the two
WARN lines; a failing query, or a failing status read, prints one plain line and exits with SystemExit, with no traceback; the source
never filters on status in the database. The rewrite's shape: no transaction.atomic and no rollback, a wsprobe- sweep before the work,
the deletes in a finally block, committed rows, the stale-connection step, deletes limited to wsprobe- names, and asgiref only.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE / "tactical-websocket-runtime-1.17.33.py"
source = PROBE.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(PROBE))


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("PASS", msg)


# ------------------------------------------------------------------------------------------------ pick_agent against a fake Agent
class FieldError(Exception):
    pass


class FakeAgent:
    def __init__(self, pk, agent_id, status):
        self.pk, self.agent_id, self._status = pk, agent_id, status

    @property
    def status(self):  # a property, not a column: the database cannot filter on it
        if isinstance(self._status, Exception):
            raise self._status
        return self._status


class FakeQuery:
    def __init__(self, rows, log):
        self.rows, self.log = rows, log

    def order_by(self, *fields):
        if self.log.get("order_fails"):
            raise RuntimeError("database unavailable")
        return FakeQuery(sorted(self.rows, key=lambda a: a.pk), self.log)

    def iterator(self):
        for row in self.rows:
            self.log["yielded"] = self.log.get("yielded", 0) + 1
            yield row

    def filter(self, **kwargs):
        if "status" in kwargs or any(k.startswith("status__") for k in kwargs):
            raise FieldError("Cannot resolve keyword 'status' into field.")
        return FakeQuery([a for a in self.rows if all(getattr(a, k) == v for k, v in kwargs.items())], self.log)

    def exclude(self, **kwargs):
        if "status" in kwargs or any(k.startswith("status__") for k in kwargs):
            raise FieldError("Cannot resolve keyword 'status' into field.")
        return FakeQuery([a for a in self.rows if not all(getattr(a, k) == v for k, v in kwargs.items())], self.log)

    def first(self):
        return self.rows[0] if self.rows else None


def load_pick_agent(agents, log):
    """The real pick_agent, must and ONLINE from the probe's source, run against a fake Agent."""
    wanted = {"pick_agent", "must"}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    nodes += [n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "ONLINE" for t in n.targets)]
    module = ast.Module(body=nodes, type_ignores=[])
    namespace = {"os": os, "Agent": type("Agent", (), {"objects": FakeQuery(agents, log)})}
    exec(compile(module, str(PROBE), "exec"), namespace)  # noqa: S102 - the probe's own functions, against a fake
    return namespace["pick_agent"]


def run_pick(agents, *, env=None, log=None):
    log = {} if log is None else log
    pick = load_pick_agent(agents, log)
    saved = os.environ.pop("TECTAC_WS_PROBE_AGENT", None)
    if env is not None:
        os.environ["TECTAC_WS_PROBE_AGENT"] = env
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            try:
                return pick(), out.getvalue(), None
            except BaseException as exc:  # noqa: BLE001 - the test inspects what escaped
                return None, out.getvalue(), exc
    finally:
        os.environ.pop("TECTAC_WS_PROBE_AGENT", None)
        if saved is not None:
            os.environ["TECTAC_WS_PROBE_AGENT"] = saved


fleet = [FakeAgent(3, "agent-c", "offline"), FakeAgent(1, "agent-a", "online"), FakeAgent(2, "agent-b", "offline")]

# the fake behaves like Tactical: a database filter on status fails
for call in ("exclude", "filter"):
    try:
        getattr(FakeQuery(fleet, {}), call)(status="online")
    except FieldError:
        pass
    else:
        raise AssertionError(f"the fake must raise FieldError on {call}(status=...)")

log: dict = {}
picked, out, error = run_pick(fleet, log=log)
must(error is None and picked is not None and picked.agent_id == "agent-b", "an offline agent is chosen in Python (the first by primary key)")
must("WARN" not in out, "no warning when an agent is offline")
must(log["yielded"] == 2, f"the walk stops at the first match (read {log['yielded']} agents, not all 3)")

picked, out, error = run_pick(fleet, env="agent-c")
must(error is None and picked.agent_id == "agent-c", "the environment override wins")
picked, out, error = run_pick(fleet, env="no-such-agent")
must(isinstance(error, AssertionError), "an override that names no agent stops the probe")

online = [FakeAgent(2, "agent-b", "online"), FakeAgent(1, "agent-a", "online")]
picked, out, error = run_pick(online)
lines = [line for line in out.splitlines() if line]
must(error is None and picked.agent_id == "agent-a", "all online gives the first agent")
must(len(lines) == 2 and all(line.startswith("WARN") for line in lines) and "TECTAC_WS_PROBE_AGENT" in lines[1],
     "all online prints the two WARN lines")

picked, out, error = run_pick([], env=None)
must(error is None and picked is None and out == "", "no agents gives None and prints nothing")

picked, out, error = run_pick(fleet, log={"order_fails": True})
lines = [line for line in out.splitlines() if line]
must(isinstance(error, SystemExit), "a failing query ends the probe with SystemExit, not a traceback")
must(len(lines) == 1 and "TECTAC_WS_PROBE_AGENT=<agent_id>" in lines[0] and "RuntimeError" in lines[0],
     "a failing query prints one plain line that says what failed and how to choose an agent")

broken = [FakeAgent(1, "agent-a", RuntimeError("status read failed")), FakeAgent(2, "agent-b", "offline")]
picked, out, error = run_pick(broken)
lines = [line for line in out.splitlines() if line]
must(isinstance(error, SystemExit) and len(lines) == 1 and "TECTAC_WS_PROBE_AGENT=<agent_id>" in lines[0],
     "a failing status read prints one plain line and exits cleanly")

# ------------------------------------------------------------------------------------------------ the source
must("exclude(status=" not in source and "filter(status=" not in source, "the source never contains exclude(status= or filter(status=")
must("status__" not in source, "the source has no status lookup of any kind")

# ------------------------------------------------------------------------------------------------ the rewrite's shape (ast, not text)
imports = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.add(node.module)
        imports.update(f"{node.module}.{alias.name}" for alias in node.names)
must("django.db.transaction" not in imports, "the probe does not import transaction")
atomic_or_rollback = [
    n for n in ast.walk(tree)
    if (isinstance(n, ast.Attribute) and n.attr in ("atomic", "set_rollback", "rollback"))
    or (isinstance(n, ast.Name) and n.id in ("atomic", "transaction"))
]
must(not atomic_or_rollback, "no transaction.atomic and no rollback in the code")
must(not [n for n in ast.walk(tree) if isinstance(n, ast.With)], "no with block holds the work (nothing wraps it in a transaction)")
must("channels.testing" not in imports and not any(name.split(".")[0] in ("daphne", "channels") for name in imports),
     "asgiref only: no channels.testing and no daphne")
must("asgiref.testing.ApplicationCommunicator" in imports and "asgiref.sync.async_to_sync" in imports, "it drives the app with asgiref")

top_try = next(n for n in tree.body if isinstance(n, ast.Try))


def calls_named(node, name):
    return [c for c in ast.walk(node) if isinstance(c, ast.Call) and getattr(c.func, "id", getattr(c.func, "attr", "")) == name]


sweep_calls = [c for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.ClassDef)) for c in calls_named(n, "remove_probe_rows")]
before_try = [c for n in tree.body if n.lineno < top_try.lineno and not isinstance(n, (ast.FunctionDef, ast.ClassDef))
              for c in calls_named(n, "remove_probe_rows")]
must(len(before_try) == 1, "a wsprobe- sweep runs before the work starts")
final = ast.Module(body=top_try.finalbody, type_ignores=[])
must(calls_named(final, "remove_probe_rows"), "the deletes run in a finally block")
must(calls_named(final, "delete"), "the finally block clears every minted ticket key from the cache")
must(len(sweep_calls) == 2, "the sweep runs once at the start and once in the finally block")

create_calls = [c for c in calls_named(top_try, "create") if "objects" in ast.dump(c.func)]
must(len(create_calls) >= 3, f"the probe commits real rows (user, role, token, session): {len(create_calls)} create calls in the work")

remove = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "remove_probe_rows")
filters = [c for c in ast.walk(remove) if isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "filter"]
must(filters and all(any(k.arg and k.arg.endswith("startswith") for k in c.keywords) for c in filters),
     "every delete is filtered by a startswith on the wsprobe- prefix")
rm_src = ast.get_source_segment(source, remove)
left_src = ast.get_source_segment(source, next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "probe_rows_left"))
must("AuditLog" not in rm_src and "audit rows" not in rm_src.split('"""')[2], "CQ103: the probe never deletes audit rows (option b until Johan answers)")
must("AuditLog" not in left_src, "CQ103: the no-rows-left check does not count audit rows")
must('PREFIX = "wsprobe-"' in source, "the prefix is wsprobe-")
must("startswith(PREFIX)" in source, "the sweep refuses a prefix that does not start with wsprobe-")

must(any(isinstance(n, ast.FunctionDef) and n.name == "break_this_threads_connection" for n in tree.body), "there is a stale-connection step")
must("connection" in imports or "django.db.connection" in imports, "the probe uses this thread's database connection")
stale = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "break_this_threads_connection")
must(calls_named(stale, "close"), "the stale step closes this thread's database connection")
must("stale_leg" in source and "stale_ticket" in source and "async_to_sync(stale_leg)()" in source,
     "a socket with a fresh ticket is opened after the connection was closed")
must(source.index("stale_ticket = new_ticket()") < source.index("how = break_this_threads_connection()"), "the ticket is minted before the break")

for needle in ("4401", "4003", "evil.example.invalid", "CORS_ORIGIN_WHITELIST", "custom:terminal-start", "starts.count() == 1", "short-ticket"):
    must(needle in source, f"the probe still checks {needle}")
must("no wsprobe rows left" in source, "the probe ends with a no-rows-left check")
must("tactical-websocket-runtime-1.17.33: ok" in source, "the probe ends with its ok line")
must(not (HERE / "tactical-websocket-runtime-1.17.32.py").exists(), "the 1.17.32 probe is removed")

print("tactical-websocket-probe-1.17.33: ok")
