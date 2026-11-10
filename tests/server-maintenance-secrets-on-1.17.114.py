#!/usr/bin/env python3
"""1.17.114 regression: secret_inputs for core.server_maintenance is ON (AD-62, Johan, 10 November 2026).

Covered: shipped default True and provider metadata; start() hands a configured secret over on stdin only (never argv, env, job file, audit row
or log), one audit row before the dispatch; a compile()-forged _resolve_secret_inputs gets caller_not_allowed with the switch on, for its own
and another module's action (the 1.17.113 High); the switch False refuses with secret_inputs_disabled, reads nothing, creates no job; the
contract text states ON since 1.17.114.
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

# ================================================================================================ 1. the switch is on by default
must(sm.SECRET_INPUTS_ENABLED is True, "SECRET_INPUTS_ENABLED is True as shipped (AD-62)")
registered = sm.register_core_server_maintenance_capability()
must(registered.metadata["secret_inputs_enabled"] is True, "provider metadata shows secret_inputs_enabled true")
must(registered.version == "1.3.0" and sm.CAPABILITY_VERSION == "1.3.0", "the capability stays 1.3.0")
listed = {row["id"]: row for row in provider.list_actions(context=ctx)}
must(listed["sigmod.cert"]["secret_inputs"] == SECRET_LIST, "list_actions shows the names and flags of an action with secret inputs")
# only the AD-62 purpose: the module-level read functions are not part of any contract
must(not hasattr(ss._PROVIDER, "_read_for_server_maintenance") and "_read_for_server_maintenance" not in json.dumps(ss.secrets_contract_metadata()), "no new public read")

# ================================================================================================ 2. a start() with the default switch hands the secret over
configure("sigmod", "dns-token", VALUE)
RUNS.clear()
before_audits = len(AUDITS)
order = []
real_record = audit_record
audit.record = lambda **kw: (order.append(("audit", jobs_on_disk())), real_record(**kw))[1]
jobs_before = len(jobs_on_disk())
job = provider.start(action="sigmod.cert", context=ctx, user=boss)
audit.record = real_record
must(len(RUNS) == 1, RUNS)
call = RUNS[0]
must(call["argv"][3:] == ["--dispatch", job["id"]] and VALUE not in " ".join(call["argv"]), "argv carries no value")
must("env" not in call and "input" in call and "stdin" not in call, "the hand-over is stdin input only: " + str(set(call)))
must(base64.b64decode(json.loads(call["input"])["dns-token"]).decode() == VALUE, "stdin carries the value")
must(VALUE not in all_state_text() and VALUE not in repr(AUDITS) and VALUE not in json.dumps(job, default=str), "no value in the job file, audit rows or the public job")
must(not any(VALUE in line for line in LOGS.lines), "no value in the log")
rows = handover_rows()
must(len(rows) == 1 and rows[0]["metadata"]["secret_names"] == ["dns-token"] and rows[0]["strict"] is True, rows)
must(len(AUDITS) - before_audits == 1, "one audit row for the hand-over")
must(order and len(order[0][1]) == jobs_before, "the audit row is written before the job file and the dispatch")

# ================================================================================================ 3. the forged frame is still refused with the switch ON
must(sm.SECRET_INPUTS_ENABLED is True, "switch on")
forged = {"sm": sm, "ss": ss, "__name__": "tec_tac.server_maintenance"}
exec(compile("def _resolve_secret_inputs(a, n):\n    return ss._read_for_server_maintenance(a, n)\n", str(APP / "server_maintenance.py"), "exec"), forged)
for action_id in ("sigmod.cert", "other.act", "nope.x"):
    try:
        forged["_resolve_secret_inputs"](action_id, "dns-token")
        raise AssertionError(f"a compile()-forged _resolve_secret_inputs read {action_id}")
    except ss.SecretStoreError as exc:
        must(exc.code == "caller_not_allowed" and VALUE not in str(exc), (action_id, exc.code))
# and a forged call of the resolver itself (not start()) is refused
forged_start = {"sm": sm, "__name__": "sigmod.views"}
exec(compile("def go(i):\n    return sm._resolve_secret_inputs(i)\n", str(BASE / "sigmod" / "views.py"), "exec"), forged_start)
for action_id in ("sigmod.cert", "other.act"):
    try:
        forged_start["go"](action_id)
        raise AssertionError("a forged resolver call was accepted")
    except sm.ServerMaintenanceValidationError as exc:
        must(exc.classification == "secret_not_allowed", exc.classification)
must(not [a for a in AUDITS if VALUE in repr(a)], "nothing leaked by the forged attempts")

# ================================================================================================ 4. the kill switch: False refuses, reads nothing, creates no job
sm.SECRET_INPUTS_ENABLED = False
read_calls = []
real_read = ss._read_for_server_maintenance
ss._read_for_server_maintenance = lambda *a, **k: (read_calls.append(a), real_read(*a, **k))[1]
RUNS.clear()
jobs_before, rows_before = jobs_on_disk(), len(handover_rows())
refuse(lambda: provider.start(action="sigmod.cert", context=ctx, user=boss), "secret_inputs_disabled")
must(not read_calls and not RUNS and jobs_on_disk() == jobs_before and len(handover_rows()) == rows_before, "nothing read, no dispatch, no job, no row")
must(sm.register_core_server_maintenance_capability().metadata["secret_inputs_enabled"] is False, "metadata follows the switch")
provider.start(action="sigmod.plain", context=ctx, user=boss)
must(len(RUNS) == 1 and "input" not in RUNS[0], "an action with no secrets still starts with the switch off")
ss._read_for_server_maintenance = real_read
sm.SECRET_INPUTS_ENABLED = True

# ================================================================================================ 5. the contract text
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must("switched OFF" not in contracts and "switched off in the shipped build" not in contracts, "the contract no longer says OFF")
must("ON since 1.17.114" in contracts and "AD-62" in contracts and "secret_inputs_enabled is true" in contracts, "the contract states ON since 1.17.114 (AD-62)")
for src in ("server_maintenance.py", "secret_store.py"):
    text = (APP / src).read_text(encoding="utf-8")
    must("until Johan signs" not in text and "off until" not in text.lower(), f"{src} no longer says the feature is off")

print("[TEST] PASS server maintenance secret inputs switched on 1.17.114")
