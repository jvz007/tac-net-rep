#!/usr/bin/env python3
"""1.17.114 regression: Core parses secret_inputs by the root helper's rules, refuses an unparseable value with action_invalid (no read, no job,
no hand-over row), and never lets the helper inherit the worker's stdin (stdin=DEVNULL when there is no hand-over).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import logging
import os
import sys
import tempfile
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
POSIX = os.name != "nt"
VALUE = "TOPSECRET-VALUE-8c1f-do-not-leak"
VALUE2 = "SECOND-SECRET-b7e2-do-not-leak"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


LOGS = ListHandler()
logging.getLogger().addHandler(LOGS)
logging.getLogger().setLevel(logging.DEBUG)

TMP = tempfile.TemporaryDirectory()
BASE = Path(TMP.name)
STATE, REGISTRY = BASE / "state", BASE / "registry"
for folder in ("jobs", "signal-requests", "cancel-requests", "logs", "running"):
    (STATE / folder).mkdir(parents=True)
REGISTRY.mkdir()
ENABLED = {"sigmod": True}
LEGACY = {"sigmod": False}
AUDITS, RUNS = [], []
AUDIT_FAIL = []
KEY = bytes(range(32))
ROWS = {}  # (owner, name) -> row


def atomic_json(path, payload, *, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, default=default), encoding="utf-8")


class User:
    is_authenticated = True
    is_superuser = True

    def __init__(self, username):
        self.username = username


def audit_record(**kw):
    if AUDIT_FAIL:
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.safe_files", atomic_json=atomic_json)
mod("tec_tac.capabilities", build_operation_context=lambda *, source_module, source_action, source_run_id=None, requested_by=None, **extra: {
    "source_module": str(source_module or "").strip(), "source_action": str(source_action or "").strip(),
    "source_run_id": source_run_id, "requested_by": str(requested_by) if requested_by else None, **extra},
    register_capability=lambda **kw: SimpleNamespace(**kw))
mod("tec_tac.config", load_layout=lambda: {"TEC_TAC_SERVER_MAINTENANCE_ROOT": str(STATE), "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT": str(REGISTRY)})
mod("tec_tac.module_state", is_enabled=lambda module_id: ENABLED.get(module_id, False))
mod("tec_tac.rbac", has_extension_permission=lambda user, code: True)
audit = mod("tec_tac.audit", record=audit_record, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw),
            AuditActor=lambda **kw: SimpleNamespace(**kw))
pkg.audit = audit
mod("tec_tac.caller_identity", calling_module_for_core_provider=lambda **kw: None)
mod("tec_tac.event_jobs_policy", ENABLED_CACHE_SECONDS=1)
mod("tec_tac.registry", get_plugins=lambda: [SimpleNamespace(plugin_id=k, plugin_type="extension", legacy=LEGACY.get(k, False)) for k in ENABLED])

ss = load("tec_tac.secret_store", APP / "secret_store.py")
pkg.secret_store = ss


class Row:
    def __init__(self, owner, name, ciphertext, key_id):
        self.owner_module, self.name, self.ciphertext, self.key_id = owner, name, ciphertext, key_id
        self.pk, self.last_read_at = (owner, name), None


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, **kw):
        return Query([r for r in self.rows if all(getattr(r, k, None) == v for k, v in kw.items())])

    def first(self):
        return self.rows[0] if self.rows else None

    def update(self, **kw):
        return 0


ss._table = lambda: Query(list(ROWS.values()))
ss._load_master_key = lambda: KEY


def configure(owner, name, value):
    scope = ss._Scope(owner)
    ROWS[(owner, name)] = Row(owner, name, ss._encrypt(KEY, scope, name, ss._encode_value(value)), ss._key_id(KEY))


sm = load("tec_tac.server_maintenance", APP / "server_maintenance.py")
HELPER_FILE = BASE / "helper-present"
HELPER_FILE.write_text("x", encoding="utf-8")
sm.HELPER = HELPER_FILE


def fake_run(argv, **kw):
    RUNS.append({"argv": list(argv), **kw})
    if RUN_FAIL:
        raise sm.subprocess.CalledProcessError(1, argv, stderr=RUN_FAIL[0])


RUN_FAIL = []
sm.subprocess = SimpleNamespace(run=fake_run, CalledProcessError=__import__("subprocess").CalledProcessError, TimeoutExpired=__import__("subprocess").TimeoutExpired,
                                DEVNULL=-3, PIPE=-1)
provider = sm.get_server_maintenance_provider()
ctx = {"source_module": "sigmod", "source_action": "sigmod.renew", "requested_by": "tester"}
boss = User("boss")

SECRET_LIST = [{"name": "dns-token", "required": True}, {"name": "api-key", "required": False}]


def register(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "description": action_id, "executable": "/x", "argv": [], "timeout_seconds": 600,
                "owner_module": "sigmod", "registered_by": "module-manifest", "parameters": {}}
    manifest.update(extra)
    (REGISTRY / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


register("sigmod.cert", permission="sigmod.renew", secret_inputs=SECRET_LIST)
register("sigmod.opt", permission="sigmod.renew", secret_inputs=[{"name": "api-key", "required": False}])
register("sigmod.plain", permission="sigmod.renew")
register("sigmod.hand", permission="sigmod.renew", registered_by=None, secret_inputs=SECRET_LIST)
register("sigmod.bad", permission="sigmod.renew", secret_inputs=[{"name": "Bad Name", "required": True}])
register("sigmod.nopermission", secret_inputs=SECRET_LIST)
register("sigmod.crossowner", secret_inputs=SECRET_LIST, owner_module="other")


def all_state_text():
    out = []
    for path in STATE.rglob("*"):
        if path.is_file():
            out.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


def jobs_on_disk():
    return sorted(p.name for p in (STATE / "jobs").glob("*.json"))


def refuse(call, classification):
    try:
        call()
    except sm.ServerMaintenanceError as exc:
        must(getattr(exc, "classification", None) == classification, (classification, getattr(exc, "classification", None), str(exc)))
        must(VALUE not in str(exc) and VALUE2 not in str(exc), "a refusal never carries a value")
        return exc
    raise AssertionError("call was accepted")


def handover_rows():
    return [a for a in AUDITS if "secret_names" in (a.get("metadata") or {})]

# ================================================================================================ load the helper for the shared table (item 6)
for name, attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None}, "grp": {}, "pwd": {"getpwnam": lambda n: SimpleNamespace(pw_gid=0)}}.items():
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            mod(name, **attrs)
helper = load("sm_helper_parse_1_17_114", ROOT / "scripts" / "server-maintenance-helper.py")

# a registry file Core did not write itself: plain strings, an object with no required, and the unparseable ones
register("sigmod.strings", permission="sigmod.renew", secret_inputs=["dns-token"])
register("sigmod.noreq", permission="sigmod.renew", secret_inputs=[{"name": "dns-token"}])
register("sigmod.num", permission="sigmod.renew", secret_inputs=5)
register("sigmod.extra", permission="sigmod.renew", secret_inputs=[{"name": "dns-token", "owner": "other"}])
register("sigmod.badname", permission="sigmod.renew", secret_inputs=["Bad Name"])
register("sigmod.repeat", permission="sigmod.renew", secret_inputs=["a", {"name": "a", "required": False}])
register("sigmod.nine", permission="sigmod.renew", secret_inputs=[f"s{i}" for i in range(9)])
register("sigmod.reqstr", permission="sigmod.renew", secret_inputs=[{"name": "dns-token", "required": "yes"}])

# ================================================================================================ 1. plain strings are handed over
configure("sigmod", "dns-token", VALUE)
RUNS.clear()
job = provider.start(action="sigmod.strings", context=ctx, user=boss)
must(len(RUNS) == 1 and RUNS[0]["argv"][3:] == ["--dispatch", job["id"]], RUNS)
must(base64.b64decode(json.loads(RUNS[0]["input"])["dns-token"]).decode() == VALUE and "stdin" not in RUNS[0], "plain-string registry: the hand-over reaches the fake dispatch as stdin input")
must(handover_rows()[-1]["metadata"]["secret_names"] == ["dns-token"], handover_rows()[-1])

# ================================================================================================ 2. an object without required means required
del ROWS[("sigmod", "dns-token")]
RUNS.clear()
refuse(lambda: provider.start(action="sigmod.noreq", context=ctx, user=boss), "secret_not_configured")
must(not RUNS, "refused, nothing dispatched")
configure("sigmod", "dns-token", VALUE)
RUNS.clear()
provider.start(action="sigmod.noreq", context=ctx, user=boss)
must(json.loads(RUNS[0]["input"]).keys() == {"dns-token"}, "configured: handed over")

# ================================================================================================ 3. an unparseable value refuses with action_invalid
for bad in ("sigmod.num", "sigmod.extra", "sigmod.badname", "sigmod.repeat", "sigmod.nine", "sigmod.reqstr"):
    RUNS.clear()
    jobs_before, rows_before, state_before = jobs_on_disk(), len(handover_rows()), all_state_text()
    read_calls = []
    real_read = ss._read_for_server_maintenance
    ss._read_for_server_maintenance = lambda *a, _log=read_calls, _real=real_read, **k: (_log.append(a), _real(*a, **k))[1]
    refuse(lambda bad=bad: provider.start(action=bad, context=ctx, user=boss), "action_invalid")
    ss._read_for_server_maintenance = real_read
    must(not RUNS and not read_calls and jobs_on_disk() == jobs_before and len(handover_rows()) == rows_before and all_state_text() == state_before,
         f"{bad}: no dispatch, no read, no job file, no hand-over row")

# ================================================================================================ 4. stdin handling of every dispatch
RUNS.clear()
sm._dispatch("--cancel", str(uuid.uuid4()))
sm._dispatch("--signal", str(uuid.uuid4()))
sm._dispatch("--dispatch", str(uuid.uuid4()))
must(len(RUNS) == 3, RUNS)
for run in RUNS:
    must(run.get("stdin") == sm.subprocess.DEVNULL and "input" not in run, f"no hand-over: stdin=DEVNULL and no input= ({run['argv'][3]})")
RUNS.clear()
sm._dispatch("--dispatch", str(uuid.uuid4()), sm._SecretHandOver(["x"], {"x": b"v"}))
must("input" in RUNS[0] and "stdin" not in RUNS[0], "a hand-over has input= and no stdin kwarg")
# the public start/cancel/signal paths use the same function
RUNS.clear()
provider.start(action="sigmod.plain", context=ctx, user=boss)
must(RUNS[0].get("stdin") == sm.subprocess.DEVNULL and "input" not in RUNS[0], "start() of an action with no secrets: stdin=DEVNULL")
source = (APP / "server_maintenance.py").read_text(encoding="utf-8")
must("subprocess.DEVNULL}" in source, "the source passes stdin=DEVNULL when there is no hand-over")

# ================================================================================================ 5. list_actions still lists an unparseable action, with no names
listed = {row["id"]: row for row in provider.list_actions(context=ctx)}
for bad in ("sigmod.num", "sigmod.extra", "sigmod.badname", "sigmod.repeat", "sigmod.nine", "sigmod.reqstr"):
    must(bad in listed and listed[bad]["secret_inputs"] == [], f"{bad} is listed with no secret names")
must(listed["sigmod.strings"]["secret_inputs"] == [{"name": "dns-token", "required": True}] and listed["sigmod.noreq"]["secret_inputs"] == [{"name": "dns-token", "required": True}],
     "the lenient shapes list with required filled in")

# ================================================================================================ 6. Core's parser equals the helper's, over one table
TABLE = [
    None, [], "x", 5, {"name": "a"}, ["a"], ["a", "b"], [{"name": "a"}], [{"name": "a", "required": True}], [{"name": "a", "required": False}],
    [{"name": "a", "required": "yes"}], [{"name": "a", "required": 1}], [{"name": "a", "required": None}], [{"name": "a", "owner": "o"}], [{"required": True}],
    [{}], [5], [None], [["a"]], ["Upper"], ["-lead"], [""], ["a b"], ["x" * 64], ["x" * 65], ["../x"], ["a", "a"], ["a", {"name": "a", "required": False}],
    [f"s{i}" for i in range(8)], [f"s{i}" for i in range(9)], ["a.b_c-d9"], [{"name": 5}], [{"name": None}], ("a",),
]
for case in TABLE:
    try:
        theirs = helper.normalize_secret_inputs(case)
    except RuntimeError:
        theirs = "refused"
    try:
        ours = sm._parse_secret_inputs(case)
    except ValueError:
        ours = "refused"
    must(ours == theirs, f"Core and the helper disagree on {case!r}: core {ours!r}, helper {theirs!r}")
    must(sm._action_secret_inputs({"secret_inputs": case}) == ([] if ours == "refused" else ours), f"display of {case!r}")
must(sm._action_secret_inputs({}) == [], "a missing key is none")

print("[TEST] PASS server maintenance secret_inputs parser and stdin 1.17.114")
