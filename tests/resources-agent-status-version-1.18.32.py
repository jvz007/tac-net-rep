#!/usr/bin/env python3
"""1.18.32 regression: status and version on the agent record (core.resources 1.12.0 -> 1.13.0).

Closes the request "agent record: status and version" (remote-background 0.11.2). The real resources.py, resources_adapter.py and
resource_views.py run against the in-memory Tactical of tests/resource-alert-template-1.17.17.py. Django and a real database are not needed.

Covered: AGENT_FIELDS and the described fields; the status rule as a table with a fixed clock (never reported, online, offline, overdue, custom
limits, the limits themselves, a naive time, a non-datetime); list_agents and get_agent keys and order, version as text; the scope (an agent outside
the caller's scope stays absent, a scoped list never gains rows); an old stub row without offline_time, overdue_time and version; the contract
version, the docs and the contract text.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import sys

sys.dont_write_bytecode = True
_here = pathlib.Path(__file__).resolve().parent
_source = (_here / "resource-alert-template-1.17.17.py").read_text(encoding="utf-8")
exec(compile(_source[: _source.index("# ---- harness end")], str(_here / "resource-alert-template-1.17.17.py"), "exec"), globals())  # noqa: S102 - test-only: the shared harness
H = globals()
must, resources, adapter, views = H["must"], H["resources"], H["adapter"], H["views"]
reset_tactical, Site, Agent, User, Role = H["reset_tactical"], H["Site"], H["Agent"], H["User"], H["Role"]
ctx_for = H["ctx_for"]

OLD = ("type", "id", "hostname", "client_id", "site_id", "active", "platform", "monitoring_type", "last_seen")
ROOT = _here.parent

# (1) the field list and the description
must(resources.AGENT_FIELDS == OLD + ("status", "version"), resources.AGENT_FIELDS)
meta = resources.resource_contract_metadata()
must(tuple(meta["resource_types"]["agent"]["fields"]) == resources.AGENT_FIELDS, meta["resource_types"]["agent"])
must(resources.CONTRACT_VERSION == "1.13.0" and meta["version"] == "1.13.0" and meta["version"].split(".")[0] == "1", meta["version"])
print("       AGENT_FIELDS = the nine old keys + status, version; metadata 1.13.0")

# (2) the status rule, fixed clock
NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.timezone.utc)
ago = lambda minutes, seconds=0: NOW - dt.timedelta(minutes=minutes, seconds=seconds)
status = lambda seen, off=4, over=30: adapter.agent_status(seen, off, over, now=NOW)
must(status(None) == "offline", "never reported")
must(status(ago(1)) == "online", "1 minute")
must(status(ago(10)) == "offline", "10 minutes: older than 4, not older than 30")
must(status(ago(45)) == "overdue", "45 minutes: older than both")
must(status(ago(10), 15, 60) == "online" and status(ago(20), 15, 60) == "offline" and status(ago(61), 15, 60) == "overdue", "custom limits")
must(status(ago(4)) == "online", "exactly on offline_time is online, as in Tactical (not strictly older)")
must(status(ago(4, 1)) == "offline", "one second past offline_time")
must(status(ago(30)) == "online", "exactly on overdue_time: neither branch matches, Tactical answers online")
must(status(ago(30, 1)) == "overdue", "one second past overdue_time")
must(adapter.agent_status(ago(10), None, None, now=NOW) == "offline" and adapter.agent_status(ago(45), None, None, now=NOW) == "overdue", "defaults 4 and 30")
must(adapter.agent_status(NOW.replace(tzinfo=None) - dt.timedelta(minutes=10), 4, 30, now=NOW) == "offline", "a naive time is read as UTC")
must(adapter.agent_status("2026-11-21", 4, 30, now=NOW) == "offline" and adapter.agent_status(12345, 4, 30, now=NOW) == "offline", "a non-datetime is never reported")
must(adapter.agent_status(dt.datetime.now(dt.timezone.utc)) == "online", "the real clock works without now")
print("       status table: never, online, offline, overdue, custom limits, the limits themselves")

# (3) list and get through the adapter
UTC = dt.timezone.utc
now = dt.datetime.now(UTC)
AGENTS = [  # id, hostname, site, last_seen, offline_time, overdue_time, version
    ("a-1", "alpha", 11, now - dt.timedelta(minutes=1), 4, 30, "2.9.0"),
    ("a-2", "bravo", 12, now - dt.timedelta(minutes=10), 4, 30, "2.8.1"),
    ("a-3", "charlie", 21, now - dt.timedelta(minutes=45), 4, 30, ""),
    ("a-4", "delta", 11, None, 4, 30, None),
]


def world():
    reset_tactical()
    Agent.STORE.clear()
    for n, (agent_id, host, site, seen, off, over, version) in enumerate(AGENTS, start=1):
        Agent.STORE[agent_id] = {"pk": n, "agent_id": agent_id, "hostname": host, "site_id": site, "site__client_id": Site.STORE[site]["client_id"], "plat": "windows",
                                 "monitoring_type": "workstation", "last_seen": seen, "offline_time": off, "overdue_time": over, "version": version}


admin = User(Role())
site_11 = User(Role(sites=[11]))
world()
listed = {row["id"]: row for row in resources.list_agents(context=ctx_for(admin))["items"]}
must(all(tuple(row) == resources.AGENT_FIELDS for row in listed.values()), [tuple(r) for r in listed.values()])
must({k: v["status"] for k, v in listed.items()} == {"a-1": "online", "a-2": "offline", "a-3": "overdue", "a-4": "offline"}, listed)
must({k: v["version"] for k, v in listed.items()} == {"a-1": "2.9.0", "a-2": "2.8.1", "a-3": "", "a-4": ""}, "version is text, blank is the empty string")
must(listed["a-1"]["hostname"] == "alpha" and listed["a-1"]["client_id"] == 1 and listed["a-1"]["platform"] == "windows" and listed["a-4"]["last_seen"] is None, listed["a-1"])
one = resources.get_agent("a-3", context=ctx_for(admin))
must(tuple(one) == resources.AGENT_FIELDS and one["status"] == "overdue" and one["version"] == "", one)
print("       list_agents and get_agent return the keys in order; the old keys are unchanged")

# (4) scope: nothing new is readable
scoped = resources.list_agents(context=ctx_for(site_11))["items"]
must(sorted(r["id"] for r in scoped) == ["a-1", "a-4"] and all(tuple(r) == resources.AGENT_FIELDS for r in scoped), scoped)
for agent_id in ("a-2", "a-3"):
    try:
        resources.get_agent(agent_id, context=ctx_for(site_11))
        raise AssertionError("an agent outside the scope must stay hidden")
    except (resources.ResourceNotFound, resources.ResourcePermissionDenied):
        pass
must(len(scoped) <= len(resources.list_agents(context=ctx_for(admin))["items"]), "a scoped list never gains rows")
print("       the scope is unchanged: no new global read")

# (5) an old stub row without the new columns still serialises with defaults
old_row = {"agent_id": "a-old", "hostname": "old", "site_id": 11, "site__client_id": 1, "plat": "windows", "monitoring_type": "server", "last_seen": now - dt.timedelta(minutes=45)}
row = adapter.agent_row(old_row)
must(tuple(row) == resources.AGENT_FIELDS and row["status"] == "overdue" and row["version"] == "", row)
must(adapter.agent_row({**old_row, "last_seen": None})["status"] == "offline", "never reported")
Agent.STORE["a-old"] = {"pk": 9, "agent_id": "a-old", "hostname": "old", "site_id": 11, "site__client_id": 1, "plat": "windows", "monitoring_type": "server", "last_seen": None}
must(resources.get_agent("a-old", context=ctx_for(admin))["version"] == "", "a stub row lacking the columns works")
print("       an old stub row serialises with Tactical's defaults")

# (6) docs and contract text
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.13.0`" in doc and "`status`" in doc and "`version`" in doc and "Agent status and version (since 1.13.0" in doc, "docs/resource-directory.md")
must("`monitoring_type`, `last_seen`, `status`, `version`." in doc, "stable fields line")
text = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must(text.count("core.resources 1.13.0") >= 2 and "status (Tactical" in text, "contracts.py names the two keys")
for name in ("resources.py", "resources_adapter.py"):
    must("1.13.0" in (ROOT / "framwork" / "tec_tac" / name).read_text(encoding="utf-8"), name)
print("[TEST] PASS resources agent status and version 1.18.32")
