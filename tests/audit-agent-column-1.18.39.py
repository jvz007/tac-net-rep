#!/usr/bin/env python3
"""1.18.39 regression: audit.record(..., agent_id=None) and the agent column on Core's own agent-download rows.

Closes 'From Johan's Part B test (21 November 2026): agent download audit rows without the agent column'. Reuses the stub harness of
tests/audit-declared-browser-events-1.17.0.py (everything before its first scenario), so the real audit.py runs with only the Tactical ORM
boundary faked: AuditLog.objects.create captures its keyword arguments and agents.models.Agent is a stub with a call counter. The real
agent_downloads.py writes the grant, revoke, served and refusal rows through the real audit writer. Django is not installed on this PC.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, tech = H["audit"], H["ROWS"], H["reset"], H["tech"]
ROOT = H["ROOT"]
Manager = H["FakeAuditLog"].objects


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ the Tactical Agent stub
LOOKUPS: list = []
DEVICES = {"agentone": "ALPHA-PC", "longname": "H" * 400}
LOOKUP_FAIL = [False]


class AgentQuery:
    def __init__(self, agent_id):
        self.agent_id = agent_id

    def values_list(self, *fields, flat=False):
        must(fields == ("hostname",) and flat is True, "the lookup reads the hostname only")
        return self

    def first(self):
        if LOOKUP_FAIL[0]:
            raise RuntimeError("database down")
        return DEVICES.get(self.agent_id)


class AgentManager:
    @staticmethod
    def filter(**kw):
        must(list(kw) == ["agent_id"], "one indexed filter on agent_id")
        LOOKUPS.append(kw["agent_id"])
        return AgentQuery(kw["agent_id"])


agents_models = types.ModuleType("agents.models")
agents_models.Agent = type("Agent", (), {"objects": AgentManager()})
sys.modules["agents"] = types.ModuleType("agents")
sys.modules["agents.models"] = agents_models

WARNINGS: list = []


class Capture(logging.Handler):
    def emit(self, record):
        if record.levelno >= logging.WARNING:
            WARNINGS.append(record)


logging.getLogger().addHandler(Capture())


def fresh():
    reset()
    LOOKUPS.clear()
    WARNINGS.clear()
    LOOKUP_FAIL[0] = False
    Manager.fail = False


def write(**kw):
    base = dict(actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1")
    base.update(kw)
    return audit.record(**base)


# ------------------------------------------------------------------ 1. a known device
fresh()
res = write(agent_id="agentone")
must(res["recorded"] is True and len(ROWS) == 1, res)
must(ROWS[0]["agent"] == "ALPHA-PC" and ROWS[0]["agent_id"] == "agentone", ROWS[0])
must(LOOKUPS == ["agentone"], "one lookup")
must(ROWS[0]["debug_info"]["object_id"] == "a-1", "object_id keeps its own meaning")
fresh()
res = audit.get_audit_provider().record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1", agent_id="agentone")
must(res["recorded"] is True and ROWS[0]["agent"] == "ALPHA-PC" and ROWS[0]["agent_id"] == "agentone", "the provider forwards agent_id with no signature change")
fresh()
write(agent_id="longname")
must(len(ROWS[0]["agent"]) == 255 and ROWS[0]["agent"] == "H" * 255, "the hostname is bounded to 255 characters")

# ------------------------------------------------------------------ 2. an unknown device and a lookup fault
fresh()
write(agent_id="deleted-agent")
must(ROWS[0]["agent"] is None and ROWS[0]["agent_id"] == "deleted-agent", "an unknown device keeps agent_id with agent None")
for strict in (False, True):
    fresh()
    LOOKUP_FAIL[0] = True
    res = write(agent_id="agentone", strict=strict)
    must(res["recorded"] is True and len(ROWS) == 1 and ROWS[0]["agent"] is None and ROWS[0]["agent_id"] == "agentone", f"a lookup fault still writes the row (strict={strict})")
    must(WARNINGS and "device name" in WARNINGS[0].getMessage(), "the fault is logged as a warning")
    must("agentone" not in WARNINGS[0].getMessage(), "the warning carries no row data")
# a write fault is still a write fault: strict raises, non-strict reports
fresh()
Manager.fail = True
must(write(agent_id="agentone")["recorded"] is False, "a database write fault is reported as before")
try:
    write(agent_id="agentone", strict=True)
    raise AssertionError("strict must raise on a write fault")
except audit.AuditWriteError:
    pass

# ------------------------------------------------------------------ 3. no agent_id: byte for byte as before
fresh()
res = write()
must(res["recorded"] is True and "agent" not in ROWS[0] and "agent_id" not in ROWS[0], f"no agent keys: {sorted(ROWS[0])}")
must(set(ROWS[0]) == {"username", "action", "object_type", "before_value", "after_value", "message", "debug_info"}, "the create() call keeps its old shape")
must(LOOKUPS == [], "no lookup runs when agent_id is None")
fresh()
write(agent_id=None)
must(LOOKUPS == [] and "agent_id" not in ROWS[0], "an explicit None is the same")

# ------------------------------------------------------------------ 4. bad shapes
for bad in ("", "a" * 81, "has space", "a/b", "a\\b", "x\n", "é", 123, True, False, b"agentone", ["agentone"], {"id": "x"}):
    fresh()
    try:
        write(agent_id=bad)
    except audit.AuditContractError as exc:
        must("agent_id" in str(exc), str(exc))
    else:
        raise AssertionError(f"{bad!r} was accepted")
    must(not ROWS and not LOOKUPS, f"{bad!r}: nothing written, no lookup")
for good in ("a", "A.b_c-9", "a" * 80):
    fresh()
    write(agent_id=good)
    must(ROWS[0]["agent_id"] == good, good)

# ------------------------------------------------------------------ 5. the signature
params = inspect.signature(audit.record).parameters
names = list(params)
must(names[-1] == "agent_id" and params["agent_id"].default is None and params["agent_id"].kind is inspect.Parameter.KEYWORD_ONLY, "agent_id is last, keyword-only, default None")
OLD = ["actor", "module_id", "action", "object_type", "object_id", "message", "before", "after", "metadata", "operation_context", "request",
       "correlation_id", "strict", "verified_run"]
must(names[:-1] == OLD, f"every older keyword keeps its position: {names}")
must(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params.values()), "all keyword-only, as before")
defaults = {n: params[n].default for n in OLD}
must(defaults["strict"] is False and defaults["verified_run"] is None and defaults["object_id"] is None and defaults["metadata"] is None, "older defaults are unchanged")
# a Core-owned context key is still refused, with or without agent_id
for key in audit.CORE_CONTEXT_KEYS:
    fresh()
    try:
        write(agent_id="agentone", operation_context={key: "x"})
    except audit.AuditContractError as exc:
        must("Core-owned" in str(exc), str(exc))
    else:
        raise AssertionError(f"{key} was accepted")
    must(not ROWS, "nothing written")
# the Core-only action is still refused
fresh()
try:
    write(agent_id="agentone", action="custom:operation-failed")
    raise AssertionError("custom:operation-failed was accepted")
except audit.AuditContractError:
    pass

# ------------------------------------------------------------------ 6. Core's own agent-download rows through the real agent_downloads
et = importlib.import_module("tec_tac.endpoint_transport")
ad = importlib.import_module("tec_tac.agent_downloads")
et.refusal_row_allowed = lambda: True


class Cache:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value, timeout=None):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


CACHE = Cache()
SHA = "0" * 64
PATH = "/opt/plugins/endpoint-agent-management/files/agent.msi"
TOKEN_LIKE = []
ad._cache = lambda: CACHE
ad._verified_module_id = lambda: "endpoint-agent-management"
ad.check_path = lambda module_id, path: (None, "/opt/plugins/endpoint-agent-management")
ad.open_verified = lambda module_id, path, sha256, expected_size=None: (types.SimpleNamespace(close=lambda: None), 1234, None)
ad._link_host = lambda: "rmm-api.example.com"

fresh()
granted = ad.grant_download("endpoint-agent-management", agent_id="agentone", path=PATH, sha256=SHA)
must(granted["outcome"] == "ok", granted)
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:agent-download-granted", "one granted row")
must(ROWS[0]["agent"] == "ALPHA-PC" and ROWS[0]["agent_id"] == "agentone", "the granted row carries Agent")
link_token = granted["path"].rstrip("/").rsplit("/", 1)[1]
res = ad.revoke_download("endpoint-agent-management", agent_id="agentone", path=PATH)
must(res == {"outcome": "ok", "revoked": True}, res)
must(ROWS[-1]["action"] == "custom:agent-download-revoked" and ROWS[-1]["agent"] == "ALPHA-PC" and ROWS[-1]["agent_id"] == "agentone", "the revoked row carries Agent")
ad.record_served({"module_id": "endpoint-agent-management", "name": "agent.msi", "size": 1234, "sha256": SHA}, "agentone", "203.0.113.9")
must(ROWS[-1]["action"] == "custom:agent-download-served" and ROWS[-1]["agent"] == "ALPHA-PC" and ROWS[-1]["agent_id"] == "agentone", "the served row carries Agent")
must(ROWS[-1]["username"] and "agentone" in ROWS[-1]["username"], "the served row still names the device as the actor")
count = len(ROWS)
ad.record_refusal("bad_token", "agentone", "203.0.113.9")
must(ROWS[-1]["action"] == "custom:agent-download-refused" and ROWS[-1]["agent_id"] == "agentone" and ROWS[-1]["agent"] == "ALPHA-PC", "a refusal with a well-formed id carries it")
for odd in ("bad id!", None, "x" * 200, 5):
    before = len(ROWS)
    ad.record_refusal("bad_token", odd, "203.0.113.9")
    must(len(ROWS) == before + 1 and "agent_id" not in ROWS[-1] and "agent" not in ROWS[-1], f"a refusal with {odd!r} carries no agent columns")
for row in ROWS:
    text = repr(row)
    must(link_token not in text and "/api/tfd/agent-downloads" not in text and "/opt/plugins" not in text and "Token " not in text, "no token, link or path reaches a row")
# an audit lookup fault never fails the strict grant
fresh()
LOOKUP_FAIL[0] = True
granted = ad.grant_download("endpoint-agent-management", agent_id="agentone", path=PATH, sha256=SHA)
must(granted["outcome"] == "ok" and ROWS and ROWS[0]["agent"] is None and ROWS[0]["agent_id"] == "agentone", "a lookup fault does not stop a strict grant")
LOOKUP_FAIL[0] = False

# the endpoint-transport rows are outside this patch
src = (ROOT / "framwork" / "tec_tac" / "audit.py").read_bytes().decode("utf-8")
transport_part = src[src.index("def _record_endpoint_transport("):src.index("def _record_agent_installer(") if src.index("def _record_agent_installer(") > src.index("def _record_endpoint_transport(") else src.index("def _record_row(")]
must("agent_id=agent_id" not in transport_part.split("return _record_row(")[1].split("def ")[0], "_record_endpoint_transport is unchanged")
must(b"\r\n" in src.encode() and src.count("\n") == src.count("\r\n"), "audit.py keeps CRLF")
for name in ("framwork/tec_tac/contracts.py", "docs/module-audit.md"):
    data = (ROOT / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " keeps CRLF")
must("agent_id" in (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8") and "1.18.39" in (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8"), "docs/module-audit.md has the paragraph")
contracts_src = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("Since 1.18.39 (additive; needs framework >=1.18.39) record() takes the optional keyword agent_id" in contracts_src, "the audit.record contract text has the paragraph")

print("[TEST] PASS audit agent column 1.18.39")
