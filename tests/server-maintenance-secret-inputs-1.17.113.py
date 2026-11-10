#!/usr/bin/env python3
"""1.17.113 regression: secret_inputs for core.server_maintenance (1.2.0 -> 1.3.0), request of certificatemanagement 0.5.0 and 0.6.0.

A module's own root program can receive one of the module's own core.secrets values without it appearing in the job, argv, the
environment or the logs. Real server_maintenance.py, secret_store.py (real AES-GCM, a fake table), registry.py and the root helper,
against stubs and temporary folders; subprocess.run and Popen are recording fakes. Covered:

* registry.py accepts a list of objects and plain strings, refuses a non-list, more than 8, a bad or repeated name, a floor below
  >=1.17.113, and the key on a reportset; the helper's validate_manifest and module-manifest reader agree;
* start(): a configured secret reaches the dispatch only as stdin input (never argv, never env); the test value is found nowhere under
  the state root, in the audit rows, in the log lines, in an exception text or in repr() of the wrapper; a missing required secret
  refuses (secret_not_configured) with no job and no hand-over row; an optional one may be missing; an unreadable one refuses; an
  action with no secret_inputs behaves as in 1.17.112; a failing audit blocks the hand-over; a dispatch error that echoes a value is scrubbed;
* secret_store._read_for_server_maintenance refuses a caller that is not server_maintenance.py's _resolve_secret_inputs, a disabled or
  legacy owner, a name the action does not list, a registration that is not a module manifest, and an action id outside the owner;
* the helper: --dispatch reads stdin only when the ROOT registry lists secret_inputs (a job file that claims secrets for another action is
  ignored), writes 0700/0400 files under a temporary 'run' root, drops extra names, fails secret_missing when a required name is absent or
  a value is too large, refuses --register with the key, and runs a registration that is not a module manifest without secrets
  (secret_missing); run_job sets TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR only for such an action and the child can read the file; the
  folder is gone after success, failure, timeout, worker error, cancel and cancelled-before-execution; the scrub replaces the value with
  *** in all three logs; the sweep removes the folder of a terminal or unknown job and keeps a running job's.

What cannot run here: the helper as root through sudo and systemd, tmpfs, root ownership. See
tests/server-maintenance-secrets-runtime-1.17.113.sh (dev server only). Symlink and FIFO cases are skipped on Windows.
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import logging
import os
import stat
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
must(sm.SECRET_INPUTS_ENABLED is True, "1.17.114 (AD-62): secret_inputs is ON by default; the 1.17.114 tests pin it")
sm.SECRET_INPUTS_ENABLED = True  # the checks below test the mechanism with the switch on


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


# ================================================================================================ registry.py
reg = load("reg_real_1_17_113", APP / "registry.py")
plug = BASE / "plug"
(plug / "server_maintenance" / "actions").mkdir(parents=True)
(plug / "server_maintenance" / "actions" / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
GROUPS = [("Admin", ["sigmod.renew"])]
PUBLISHER = ["server_maintenance.register"]


def parse(secret_inputs=None, *, framework=">=1.17.113,<2.0.0", plugin_type="extension", raw_key=True):
    entry = {"id": "sigmod.cert", "permission": "sigmod.renew", "executable": "server_maintenance/actions/run.sh"}
    if raw_key:
        entry["secret_inputs"] = secret_inputs
    payload = {"id": "sigmod", "server_maintenance_actions": [entry]}
    if framework is not None:
        payload["requires"] = {"framework": framework}
    return reg._server_maintenance_actions(payload, plugin_type, "sigmod", plug, GROUPS, PUBLISHER)


def reg_refused(*args, **kw):
    try:
        parse(*args, **kw)
    except reg.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"registry accepted {args} {kw}")


must(parse(raw_key=False)[0]["secret_inputs"] == [], "no key means none")
must(parse(SECRET_LIST)[0]["secret_inputs"] == SECRET_LIST, "objects")
must(parse(["dns-token", {"name": "api-key", "required": False}])[0]["secret_inputs"] == [{"name": "dns-token", "required": True}, {"name": "api-key", "required": False}], "strings and objects")
must(parse([{"name": "a.b_c-d9"}])[0]["secret_inputs"] == [{"name": "a.b_c-d9", "required": True}], "required defaults to true")
must(len(parse([f"s{i}" for i in range(8)])[0]["secret_inputs"]) == 8, "eight is the limit")
must("at most 8" in reg_refused("not-a-list") and "at most 8" in reg_refused([f"s{i}" for i in range(9)]), "non-list and nine")
for bad in ("Upper", "-lead", "", "a b", "x" * 65, "../x", 5, None):
    reg_refused([bad])
reg_refused([{"name": "a", "owner": "other"}])
reg_refused([{"name": "a", "required": "yes"}])
must("repeats" in reg_refused(["a", {"name": "a", "required": False}]), "a repeated name")
must(">=1.17.113" in reg_refused(SECRET_LIST, framework=">=1.17.112") and ">=1.17.113" in reg_refused(SECRET_LIST, framework=None), "the floor gate")
must(parse(SECRET_LIST, framework=">=1.18.0")[0]["secret_inputs"] == SECRET_LIST, "a higher floor passes")
parse([], framework=None)  # an empty list needs no floor
try:
    parse(SECRET_LIST, plugin_type="reportset")
    raise AssertionError("a reportset may not declare it")
except reg.RegistryError as exc:
    must("Reportset" in str(exc), str(exc))

# ================================================================================================ the root helper (loaded now, used below)
for name, attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None}, "grp": {}, "pwd": {"getpwnam": lambda n: SimpleNamespace(pw_gid=0)}}.items():
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            mod(name, **attrs)
for shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, shim):
        setattr(os, shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000
if not hasattr(os, "getgid"):
    os.getgid = lambda: 0
h = load("sm_helper_secrets_1_17_113", ROOT / "scripts" / "server-maintenance-helper.py")
HSTATE, HREG, HACT, HRUN = BASE / "hstate", BASE / "hreg", BASE / "hact", BASE / "run" / "secrets"
for p in (HSTATE, HREG, HACT):
    p.mkdir()
h.STATE_ROOT, h.JOBS_ROOT, h.CANCEL_ROOT = HSTATE, HSTATE / "jobs", HSTATE / "cancel-requests"
h.LOGS_ROOT, h.RUNNING_ROOT, h.AUDIT_FILE, h.LOCK_FILE = HSTATE / "logs", HSTATE / "running", HSTATE / "audit.jsonl", HSTATE / "server-maintenance.lock"
h.REGISTRY_ROOT, h.ACTION_ROOT, h.SECRETS_ROOT = HREG, HACT, HRUN
h.validate_executable = lambda value: Path(str(value))
h.load_config = dict
for p in (h.JOBS_ROOT, h.CANCEL_ROOT, h.LOGS_ROOT, h.RUNNING_ROOT, h.signal_request_root()):
    p.mkdir()
EXE = HACT / "run.sh"
EXE.write_bytes(b"#!/bin/sh\nexit 0\n")

# the helper agrees with registry.py
must(h.normalize_secret_inputs(SECRET_LIST) == SECRET_LIST and h.normalize_secret_inputs(["a"]) == [{"name": "a", "required": True}] and h.normalize_secret_inputs(None) == [], "helper parses the same shapes")
for bad in ("x", [f"s{i}" for i in range(9)], ["Bad"], ["a", "a"], [{"name": "a", "owner": "o"}], [{"name": "a", "required": 1}], [5]):
    try:
        h.normalize_secret_inputs(bad)
        raise AssertionError(f"helper accepted {bad!r}")
    except RuntimeError:
        pass
manifest = h.validate_manifest({"id": "sigmod.cert", "executable": str(EXE), "argv": [], "secret_inputs": ["dns-token"]})
must(manifest["secret_inputs"] == [{"name": "dns-token", "required": True}], manifest)
must("secret_inputs" not in h.validate_manifest({"id": "sigmod.plain", "executable": str(EXE), "argv": []}), "a registry file with no secrets stays as before")
for bad in (["Bad"], "x"):
    try:
        h.validate_manifest({"id": "sigmod.cert", "executable": str(EXE), "argv": [], "secret_inputs": bad})
        raise AssertionError("validate_manifest accepted a bad key")
    except RuntimeError:
        pass
module_payload = {"id": "sigmod", "type": "extension", "version": "1.0.0", "requires": {"framework": ">=1.17.113"}, "publisher_permissions": PUBLISHER,
                  "permission_groups": {"Admin": ["sigmod.renew"]},
                  "server_maintenance_actions": [{"id": "sigmod.cert", "permission": "sigmod.renew", "executable": "server_maintenance/actions/run.sh", "secret_inputs": SECRET_LIST}]}
version, actions = h._module_actions_from_manifest("sigmod", module_payload)
must(actions[0]["secret_inputs"] == SECRET_LIST, actions)
module_payload["requires"] = {"framework": ">=1.17.112"}
try:
    h._module_actions_from_manifest("sigmod", module_payload)
    raise AssertionError("a floor below 1.17.113 was accepted")
except RuntimeError as exc:
    must("1.17.113" in str(exc), str(exc))
module_payload["requires"] = {"framework": ">=1.17.113"}
module_payload["server_maintenance_actions"][0]["secret_inputs"] = ["Bad"]
try:
    h._module_actions_from_manifest("sigmod", module_payload)
    raise AssertionError("a bad name was accepted")
except RuntimeError:
    pass
module_payload["server_maintenance_actions"][0].pop("secret_inputs")
must("secret_inputs" not in h._module_actions_from_manifest("sigmod", module_payload)[1][0], "an action without the key is unchanged")
module_payload["requires"] = {}
must(h._module_actions_from_manifest("sigmod", module_payload)[1], "an action without the key needs no floor")

hand = BASE / "hand.json"
hand.write_text(json.dumps({"id": "sigmod.hand", "executable": str(EXE), "argv": [], "secret_inputs": ["x"]}), encoding="utf-8")
try:
    h.register_manifest(hand)
    raise AssertionError("--register accepted secret_inputs")
except RuntimeError as exc:
    must("module manifest" in str(exc), str(exc))
hand.write_text(json.dumps({"id": "sigmod.hand", "executable": str(EXE), "argv": [], "secret_inputs": []}), encoding="utf-8")
try:
    h.register_manifest(hand)
    raise AssertionError("--register accepted the key, even empty")
except RuntimeError:
    pass

# ================================================================================================ the capability
registered = sm.register_core_server_maintenance_capability()
must(sm.CAPABILITY_VERSION == "1.3.0" and registered.version == "1.3.0" and registered.id == "core.server_maintenance", registered.version)
must(registered.operations[:5] == ("start", "get_job", "cancel", "list_jobs", "list_actions") and "send_signal" in registered.operations, registered.operations)
must(registered.metadata["action_manifest_keys_added_in_1_3_0"] == ["secret_inputs"] and registered.metadata["secret_input_limits"]["names_per_action"] == 8
     and registered.metadata["secret_input_limits"]["value_bytes"] == 16384 and registered.metadata["secret_input_limits"]["total_bytes"] == 65536, registered.metadata)
must(registered.metadata["action_manifest_keys_added_in_1_2_0"] == ["signals", "waits_for_person"] and registered.metadata["per_action_permission"] is True, "earlier metadata stays")
must("_read_for_server_maintenance" not in json.dumps(ss.secrets_contract_metadata()) and ss.secrets_contract_metadata()["operations"] == ["put", "get", "delete", "configured", "list_names"], "the private read is not in the contract")
must(not hasattr(ss._PROVIDER, "_read_for_server_maintenance") and ss.CAPABILITY_VERSION == "1.0.0", "core.secrets is unchanged and does not offer it")

# ================================================================================================ start(): a configured secret
configure("sigmod", "dns-token", VALUE)
job = provider.start(action="sigmod.cert", context=ctx, user=boss)
must(len(RUNS) == 1, RUNS)
call = RUNS[0]
must(call["argv"][:3] == ["sudo", "-n", str(HELPER_FILE)] and call["argv"][3:] == ["--dispatch", job["id"]], call["argv"])
must("env" not in call and set(call) <= {"argv", "check", "stdout", "stderr", "text", "timeout", "input"}, "no environment is passed: " + str(set(call)))
must(VALUE not in " ".join(call["argv"]), "argv carries no value")
sent = json.loads(call["input"])
must(set(sent) == {"dns-token"} and base64.b64decode(sent["dns-token"]).decode() == VALUE, "stdin carries the value, base64 in JSON, only the configured name")
stored = json.loads((STATE / "jobs" / f"{job['id']}.json").read_text(encoding="utf-8"))
must(stored["secret_inputs"] == ["dns-token"], stored)
must(job["secret_inputs"] == ["dns-token"] and provider.get_job(job_id=job["id"], context=ctx)["secret_inputs"] == ["dns-token"], job)
must(VALUE not in all_state_text() and VALUE not in json.dumps(job, default=str), "no value in any file under the state root or the public job")
must(base64.b64encode(VALUE.encode()).decode() not in all_state_text(), "no base64 form either")
rows = handover_rows()
must(len(rows) == 1 and rows[0]["action"] == "run" and rows[0]["object_type"] == "server_maintenance_job" and rows[0]["module_id"] == "core" and rows[0]["strict"] is True, rows)
must(rows[0]["metadata"] == {"job_id": job["id"], "action": "sigmod.cert", "owner_module": "sigmod", "secret_names": ["dns-token"]}, rows[0]["metadata"])
must(VALUE not in repr(AUDITS), "no value in any audit row")
listed = {row["id"]: row for row in provider.list_actions(context=ctx)}
must(listed["sigmod.cert"]["secret_inputs"] == SECRET_LIST and listed["sigmod.plain"]["secret_inputs"] == [] and listed["sigmod.bad"]["secret_inputs"] == [], "list_actions rows carry names and flags only")
must(VALUE not in repr(listed), "no value in list_actions")
# the file was written before the audit row? the job file does not exist when the audit row is written: audit first
order = []
real_record = audit_record
audit.record = lambda **kw: (order.append(("audit", jobs_on_disk())), real_record(**kw))[1]
before = len(jobs_on_disk())
provider.start(action="sigmod.cert", context=ctx, user=boss)
must(order and len(order[0][1]) == before, "the strict audit row is written before the job file and the dispatch")
audit.record = real_record

# both configured: both travel, names sorted
configure("sigmod", "api-key", VALUE2)
RUNS.clear()
job2 = provider.start(action="sigmod.cert", context=ctx, user=boss)
sent = json.loads(RUNS[0]["input"])
must(sorted(sent) == ["api-key", "dns-token"] and handover_rows()[-1]["metadata"]["secret_names"] == ["api-key", "dns-token"], sent)
must(VALUE not in all_state_text() and VALUE2 not in all_state_text() and VALUE2 not in repr(AUDITS), "still nowhere durable")
del ROWS[("sigmod", "api-key")]

# an optional secret that is missing: the start goes ahead
RUNS.clear()
provider.start(action="sigmod.cert", context=ctx, user=boss)
must(sorted(json.loads(RUNS[0]["input"])) == ["dns-token"], "optional api-key missing, required dns-token sent")
RUNS.clear()
provider.start(action="sigmod.opt", context=ctx, user=boss)
must(json.loads(RUNS[0]["input"]) == {} and handover_rows()[-1]["metadata"]["secret_names"] == [], "only optional names, none configured: starts, nothing sent")

# ================================================================================================ start(): refusals create nothing
del ROWS[("sigmod", "dns-token")]
RUNS.clear()
jobs_before, rows_before = jobs_on_disk(), len(handover_rows())
exc = refuse(lambda: provider.start(action="sigmod.cert", context=ctx, user=boss), "secret_not_configured")
must("dns-token" in str(exc), str(exc))
must(jobs_on_disk() == jobs_before and RUNS == [] and len(handover_rows()) == rows_before, "no job file, no dispatch, no hand-over row")
configure("sigmod", "dns-token", VALUE)

original_decrypt = ss._decrypt
ss._decrypt = lambda *a: (_ for _ in ()).throw(ValueError("bad tag"))
LOGS.lines.clear()
refuse(lambda: provider.start(action="sigmod.cert", context=ctx, user=boss), "secret_unreadable")
must(jobs_on_disk() == jobs_before and RUNS == [] and len(handover_rows()) == rows_before, "an unreadable secret refuses, nothing created")
ss._decrypt = original_decrypt
ss._load_master_key = lambda: (_ for _ in ()).throw(ss.SecretStoreError("master_key_unavailable", "no key", 503))
refuse(lambda: provider.start(action="sigmod.cert", context=ctx, user=boss), "secret_unreadable")
ss._load_master_key = lambda: KEY

AUDIT_FAIL.append(1)
refuse(lambda: provider.start(action="sigmod.cert", context=ctx, user=boss), "audit_failed")
AUDIT_FAIL.clear()
must(jobs_on_disk() == jobs_before and RUNS == [], "an audit that fails blocks the hand-over: no job, no dispatch")

refuse(lambda: provider.start(action="sigmod.hand", context=ctx, user=boss), "secret_not_configured")  # not registered by a module manifest
must(RUNS == [], "no dispatch for a hand registration")
ENABLED["sigmod"] = False
refuse(lambda: provider.start(action="sigmod.nopermission", context=ctx, user=boss), "secret_not_allowed")  # owner disabled
ENABLED["sigmod"] = True
LEGACY["sigmod"] = True
refuse(lambda: provider.start(action="sigmod.nopermission", context=ctx, user=boss), "secret_not_allowed")  # owner legacy
LEGACY["sigmod"] = False
refuse(lambda: provider.start(action="sigmod.crossowner", context=ctx, user=boss), "secret_not_allowed")  # action id outside the owner
must(RUNS == [] and jobs_on_disk() == jobs_before, "nothing was handed over in any refusal")
must(provider.start(action="sigmod.nopermission", context=ctx, user=boss)["secret_inputs"] == ["dns-token"], "an enabled, non-legacy owner works with no permission")
RUNS.clear()

# a plain action: exactly as in 1.17.112
plain = provider.start(action="sigmod.plain", context=ctx, user=boss)
call = RUNS[-1]
must("input" not in call and call["argv"][3:] == ["--dispatch", plain["id"]] and "env" not in call, call)
must(json.loads((STATE / "jobs" / f"{plain['id']}.json").read_text(encoding="utf-8"))["secret_inputs"] == [] and plain["secret_inputs"] == [], "no secrets recorded")

# a dispatch error that echoes a value is scrubbed everywhere
RUNS.clear()
RUN_FAIL.append(f"helper said: {VALUE} and {base64.b64encode(VALUE.encode()).decode()}")
try:
    provider.start(action="sigmod.cert", context=ctx, user=boss)
    raise AssertionError("dispatch failure expected")
except sm.ServerMaintenanceError as exc:
    must(VALUE not in str(exc) and "***" in str(exc) and exc.classification == "dispatch_failed", str(exc))
RUN_FAIL.clear()
must(VALUE not in all_state_text() and base64.b64encode(VALUE.encode()).decode() not in all_state_text(), "the failed job record carries no value")
must(VALUE not in "\n".join(LOGS.lines) and VALUE2 not in "\n".join(LOGS.lines), "no log line carries a value")

# the wrappers
secret = ss.SecretValue(VALUE.encode())
must(repr(secret) == "<redacted>" and str(secret) == "<redacted>" and VALUE not in f"{secret!r} {secret} {[secret]} {{'k': secret}}", "SecretValue shows nothing")
import pickle  # noqa: E402

for obj in (secret, sm._SecretHandOver(["dns-token"], {"dns-token": VALUE.encode()})):
    try:
        pickle.dumps(obj)
        raise AssertionError("pickled")
    except TypeError:
        pass
must(repr(sm._SecretHandOver(["x"], {"x": b"v"})) == "<redacted>", "the hand-over shows nothing")
must(ss.SecretValue.__slots__ == ("_data",) and not hasattr(secret, "__dict__"), "no attribute dictionary to dump")
must("secret_input" not in "".join(m for m in dir(sm.ServerMaintenanceProvider) if not m.startswith("_") and "secret" in m), "no public method returns a secret")

# ================================================================================================ the private read: who may call it
for args in (("sigmod.cert", "dns-token"),):
    try:
        ss._read_for_server_maintenance(*args)
        raise AssertionError("a direct call from a test (any module-style caller) was accepted")
    except ss.SecretStoreError as exc:
        must(exc.code == "caller_not_allowed" and exc.status_code == 403 and VALUE not in str(exc), exc.code)
module_style = {"ss": ss, "__name__": "sigmod.views"}
exec(compile("def _resolve_secret_inputs(a, n):\n    return ss._read_for_server_maintenance(a, n)\n", str(BASE / "sigmod" / "views.py"), "exec"), module_style)
try:
    module_style["_resolve_secret_inputs"]("sigmod.cert", "dns-token")
    raise AssertionError("a module-style caller with the right function name was accepted")
except ss.SecretStoreError as exc:
    must(exc.code == "caller_not_allowed", exc.code)
other_function = {"ss": ss, "__name__": "tec_tac.server_maintenance"}
exec(compile("def helper(a, n):\n    return ss._read_for_server_maintenance(a, n)\n", str(APP / "server_maintenance.py"), "exec"), other_function)
try:
    other_function["helper"]("sigmod.cert", "dns-token")
    raise AssertionError("a function with another name in that file was accepted")
except ss.SecretStoreError as exc:
    must(exc.code == "caller_not_allowed", exc.code)
# a frame that looks right (the file, the function name, the module name) still gets only what the ROOT registry lists for that action
looks_right = {"ss": ss, "__name__": "tec_tac.server_maintenance"}
exec(compile("def _resolve_secret_inputs(a, n):\n    return ss._read_for_server_maintenance(a, n)\n", str(APP / "server_maintenance.py"), "exec"), looks_right)
forged_call = looks_right["_resolve_secret_inputs"]
# 1.17.113-1: that forged shape (real file, real name, real __name__) is refused for its own and another module's action, switch off or on
for switch in (False, True):
    sm.SECRET_INPUTS_ENABLED = switch
    for action_id in ("sigmod.cert", "other.act", "nope.x"):
        try:
            forged_call(action_id, "dns-token")
            raise AssertionError(f"a compile()-forged _resolve_secret_inputs read {action_id} (switch {switch})")
        except ss.SecretStoreError as exc:
            must(exc.code == "caller_not_allowed" and exc.status_code == 403 and VALUE not in str(exc), (switch, action_id, exc.code))
# the real function (its code object) is the only accepted caller, and only with the switch on
_orig_resolve = sm._resolve_secret_inputs


def _genuine(a, n):
    return ss._read_for_server_maintenance(a, n)


sm._resolve_secret_inputs = _genuine  # stands in for the real function: the check compares code objects
call_right = _genuine
sm.SECRET_INPUTS_ENABLED = False
try:
    call_right("sigmod.cert", "dns-token")
    raise AssertionError("the real caller read with the switch off")
except ss.SecretStoreError as exc:
    must(exc.code == "caller_not_allowed", exc.code)
sm.SECRET_INPUTS_ENABLED = True
must(call_right("sigmod.cert", "dns-token").reveal_for_core() == VALUE.encode(), "the real caller's code object works with the switch on")
for action_id, name in (("sigmod.cert", "other-name"), ("sigmod.cert", "api-key.extra"), ("sigmod.plain", "dns-token"), ("sigmod.hand", "dns-token"),
                        ("sigmod.crossowner", "dns-token"), ("nope.cert", "dns-token"), ("sigmod.cert", None), ("sigmod.cert", "../x")):
    try:
        call_right(action_id, name)
        raise AssertionError(f"read {action_id} {name!r}")
    except ss.SecretStoreError as exc:
        must(exc.code in {"caller_not_allowed", "invalid_name"}, (action_id, name, exc.code))
configure("other", "dns-token", "OTHER-MODULE-VALUE")
ENABLED["other"] = True
must(call_right("sigmod.cert", "dns-token").reveal_for_core() == VALUE.encode(), "the owner is the action's own module: another module's same-named secret is never read")
for flag, key in ((ENABLED, "sigmod"), (LEGACY, "sigmod")):
    old = flag.get(key)
    flag[key] = (not old) if flag is ENABLED else True
    try:
        call_right("sigmod.cert", "dns-token")
        raise AssertionError("a disabled or legacy owner was read")
    except ss.SecretStoreError as exc:
        must(exc.code == "caller_not_allowed", exc.code)
    flag[key] = old
sm._resolve_secret_inputs = _orig_resolve
must([a for a in AUDITS if a.get("action") == "deny" and a.get("object_type") == "core_secret"], "a refused read writes a deny row")
must(VALUE not in repr(AUDITS) and "OTHER-MODULE-VALUE" not in repr(AUDITS), "no value in the deny rows")

# ================================================================================================ the helper: --dispatch
H_COMMANDS, H_BEHAVIOUR = [], {"fail": None}


def h_run(command, **kw):
    H_COMMANDS.append(list(command))
    if H_BEHAVIOUR["fail"]:
        raise OSError("systemd-run failed")
    return SimpleNamespace(returncode=0, stderr="", stdout="")


class FakeChild:
    CALLS = []
    EXIT = [0]
    HANG = [False]

    def __init__(self, argv, **kw):
        folder = (kw.get("env") or {}).get(h.ENV_SECRET_DIR)
        seen = {}
        if folder:
            for child in Path(folder).iterdir():
                seen[child.name] = child.read_bytes()
        FakeChild.CALLS.append({"argv": argv, "env": kw.get("env"), "seen": seen})
        for stream in ("stdout", "stderr"):
            kw[stream].write(f"program says {VALUE} on {stream}\n".encode())
            kw[stream].flush()
        self.terminated = False

    def poll(self):
        return None if (FakeChild.HANG[0] and not self.terminated) else FakeChild.EXIT[0]

    def wait(self, timeout=None):
        return -15 if self.terminated else FakeChild.EXIT[0]

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


import subprocess as real_subprocess  # noqa: E402

h.subprocess = SimpleNamespace(Popen=FakeChild, run=h_run, TimeoutExpired=real_subprocess.TimeoutExpired, DEVNULL=-3, PIPE=-1)
h.fcntl = SimpleNamespace(flock=lambda *a: None, LOCK_EX=2, LOCK_UN=8)
real_sys = h.sys


def stdin_of(data):
    raw = json.dumps(data).encode("utf-8") if not isinstance(data, bytes) else data
    stream = io.BytesIO(raw)
    h.sys = SimpleNamespace(stdin=SimpleNamespace(buffer=stream), stderr=real_sys.stderr, argv=real_sys.argv, exit=real_sys.exit)
    return stream


def b64(value):
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def hregister(action_id, **extra):
    import hashlib

    manifest = {"id": action_id, "revision": "1", "executable": str(EXE), "argv": [], "timeout_seconds": 600, "success_exit_codes": [0], "enabled": True,
                "owner_module": "sigmod", "registered_by": "module-manifest", "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest()}
    manifest.update(extra)
    (HREG / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


hregister("sigmod.cert", permission="sigmod.renew", secret_inputs=SECRET_LIST)
hregister("sigmod.plain", permission="sigmod.renew")
hregister("sigmod.hand", permission="sigmod.renew", registered_by=None, secret_inputs=SECRET_LIST)
hregister("sigmod.slow", permission="sigmod.renew", secret_inputs=SECRET_LIST, timeout_seconds=1)


def queued(action, **extra):
    job_id = str(uuid.uuid4())
    job = {"schema": 1, "id": job_id, "action": action, "action_revision": "1", "status": "queued", "stage": "queued", "context": ctx, "parameters": {},
           "public_parameters": {}, "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None}
    job.update(extra)
    h.job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    return job_id


def claimed_job(job_id):
    return json.loads(h.claimed_job_path(job_id).read_text(encoding="utf-8"))


def helper_state_text():
    out = []
    for root in (HSTATE, HREG):
        for path in root.rglob("*"):
            if path.is_file():
                out.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


def folder_of(job_id):
    return h.SECRETS_ROOT / job_id


# dispatched with a value, an extra name and nothing else
j1 = queued("sigmod.cert", secret_inputs=["from-the-job-file"])
stream = stdin_of({"dns-token": b64(VALUE), "extra": b64("EXTRA-VALUE-do-not-keep")})
h.dispatch(j1)
folder = folder_of(j1)
must(sorted(p.name for p in folder.iterdir()) == ["dns-token"], "the extra name is dropped")
must((folder / "dns-token").read_bytes() == VALUE.encode(), "the value is in the file")
if POSIX:
    must(stat.S_IMODE(folder.stat().st_mode) == 0o700 and stat.S_IMODE((folder / "dns-token").stat().st_mode) == 0o400 and stat.S_IMODE(h.SECRETS_ROOT.stat().st_mode) == 0o700, "0700 folders, 0400 files")
must(claimed_job(j1)["status"] == "dispatched", claimed_job(j1)["status"])
must(VALUE not in helper_state_text() and "EXTRA-VALUE" not in helper_state_text() and b64(VALUE) not in helper_state_text(), "no value in the job files, the registry or the helper audit file")
must(all(VALUE not in " ".join(c) for c in H_COMMANDS), "the systemd-run command carries no value")
h._remove_tree(folder)
# the folder is exclusive (O_EXCL): a second write for the same job is refused
h.write_secret_dir(j1, {"a": b"1"})
try:
    h.write_secret_dir(j1, {"a": b"2"})
    raise AssertionError("an existing folder was reused")
except FileExistsError:
    pass
must(not folder.exists(), "a failed write removes its folder")

# a job file that claims secrets for an action that has none: stdin is never read, no folder
j2 = queued("sigmod.plain", secret_inputs=["dns-token"])
stream = stdin_of({"dns-token": b64(VALUE)})
h.dispatch(j2)
must(stream.tell() == 0 and not folder_of(j2).exists(), "stdin untouched, no folder: the job file cannot ask for secrets")

# a required name is absent: the job fails secret_missing, nothing is left
for payload in ({}, {"api-key": b64("only-optional")}, {"dns-token": ""}, {"dns-token": "!!notbase64!!"}, {"dns-token": 5}, [1, 2]):
    j3 = queued("sigmod.cert")
    stdin_of(payload)
    try:
        h.dispatch(j3)
        raise AssertionError(f"accepted {payload!r}")
    except h.SecretInputError as exc:
        must(exc.classification == "secret_missing" and VALUE not in str(exc), str(exc))
    failed = claimed_job(j3)
    must(failed["status"] == "failed" and failed["failure"]["classification"] == "secret_missing" and not folder_of(j3).exists(), failed)
j3 = queued("sigmod.cert")
stdin_of(b"{not json")
try:
    h.dispatch(j3)
    raise AssertionError("invalid json accepted")
except h.SecretInputError as exc:
    must(exc.classification == "secret_missing", str(exc))
j3 = queued("sigmod.cert")
stdin_of({"dns-token": b64(b"x" * (h.SECRET_VALUE_MAX_BYTES + 1))})
try:
    h.dispatch(j3)
    raise AssertionError("an oversize value was accepted")
except h.SecretInputError:
    pass
must(not folder_of(j3).exists(), "no folder after a refusal")
j3 = queued("sigmod.cert")
stdin_of(b" " * (h.SECRET_STDIN_MAX_BYTES + 5))
try:
    h.dispatch(j3)
    raise AssertionError("an oversize input was accepted")
except h.SecretInputError:
    pass
# the total limit: four values of 16 KiB fit, five do not (the action lists at most 8 names)
hregister("sigmod.many", permission="sigmod.renew", secret_inputs=[{"name": f"s{i}", "required": True} for i in range(5)])
j3 = queued("sigmod.many")
stdin_of({f"s{i}": b64(b"y" * h.SECRET_VALUE_MAX_BYTES) for i in range(5)})
try:
    h.dispatch(j3)
    raise AssertionError("the total limit was not enforced")
except h.SecretInputError as exc:
    must("total" in str(exc), str(exc))
j3 = queued("sigmod.many")
stdin_of({f"s{i}": b64(b"y" * h.SECRET_VALUE_MAX_BYTES) for i in range(3)} | {"s3": b64(b"z"), "s4": b64(b"z")})
h.dispatch(j3)
must(len(list(folder_of(j3).iterdir())) == 5, "up to 64 KiB in all is accepted")

h.finish_secrets(j3)
# an optional name may be absent
j4 = queued("sigmod.cert")
stdin_of({"dns-token": b64(VALUE)})
h.dispatch(j4)
must(sorted(p.name for p in folder_of(j4).iterdir()) == ["dns-token"], "optional api-key absent: dispatch goes ahead")
h.finish_secrets(j4)

# a registration that is not a module manifest runs without secrets and fails secret_missing, stdin untouched
j5 = queued("sigmod.hand")
stream = stdin_of({"dns-token": b64(VALUE)})
try:
    h.dispatch(j5)
    raise AssertionError("a hand registration was given secrets")
except h.SecretInputError as exc:
    must(exc.classification == "secret_missing", str(exc))
must(stream.tell() == 0 and not folder_of(j5).exists() and claimed_job(j5)["failure"]["classification"] == "secret_missing", "no secrets for a hand registration")

# systemd-run failing removes the folder
H_BEHAVIOUR["fail"] = True
j6 = queued("sigmod.cert")
stdin_of({"dns-token": b64(VALUE)})
try:
    h.dispatch(j6)
    raise AssertionError("dispatch failure expected")
except OSError:
    pass
H_BEHAVIOUR["fail"] = None
must(not folder_of(j6).exists() and claimed_job(j6)["status"] == "dispatch_failed", "the folder is removed when the unit cannot start")

# ================================================================================================ the helper: run_job
def dispatched(action="sigmod.cert", value=VALUE, **extra):
    job_id = queued(action, **extra)
    stdin_of({"dns-token": b64(value)})
    h.dispatch(job_id)
    return job_id


def logs_of(job_id):
    return {suffix: (h.LOGS_ROOT / f"{job_id}{suffix}").read_bytes().decode("utf-8", "replace") for suffix in (".stdout.log", ".stderr.log", ".log")}


FakeChild.CALLS.clear()
FakeChild.EXIT[0] = 0
jr = dispatched()
h.run_job(jr)
call = FakeChild.CALLS[-1]
must(call["env"][h.ENV_SECRET_DIR] == str(folder_of(jr)) and call["seen"] == {"dns-token": VALUE.encode()}, "the child gets the PATH and can read the file")
must(VALUE not in json.dumps({k: v for k, v in call["env"].items() if k != h.ENV_SECRET_DIR}) and VALUE not in " ".join(call["argv"]), "no value in the environment or argv")
must(claimed_job(jr)["status"] == "succeeded", claimed_job(jr))
must(not folder_of(jr).exists(), "the folder is gone after success")
texts = logs_of(jr)
must(all(VALUE not in t for t in texts.values()) and "***" in texts[".stdout.log"] and "***" in texts[".stderr.log"], "the scrub replaced the value in stdout and stderr")
must("program says *** on stdout" in texts[".stdout.log"], texts[".stdout.log"])
must(VALUE not in helper_state_text(), "the value is nowhere under the helper state")

# the lifecycle log is scrubbed too
jl = dispatched()
(h.LOGS_ROOT / f"{jl}.log").write_text(f"[t] note {VALUE}\n", encoding="utf-8")
h.finish_secrets(jl)
must(VALUE not in (h.LOGS_ROOT / f"{jl}.log").read_text(encoding="utf-8") and "***" in (h.LOGS_ROOT / f"{jl}.log").read_text(encoding="utf-8"), "lifecycle log scrubbed")

# an action with no secret_inputs: the plain environment, no secret variable
FakeChild.CALLS.clear()
jp = queued("sigmod.plain")
h.dispatch(jp)
h.run_job(jp)
env = FakeChild.CALLS[-1]["env"]
must(env is None or h.ENV_SECRET_DIR not in env, "no secret variable for an action without secret_inputs")

# failure, worker error, timeout, cancelled before execution: the folder is gone each time
FakeChild.EXIT[0] = 3
jf = dispatched()
h.run_job(jf)
must(claimed_job(jf)["status"] == "failed" and not folder_of(jf).exists() and all(VALUE not in t for t in logs_of(jf).values()), "failure")
FakeChild.EXIT[0] = 0
real_popen = h.subprocess.Popen


def boom(*a, **k):
    raise OSError("cannot start")


h.subprocess.Popen = boom
jw = dispatched()
try:
    h.run_job(jw)
    raise AssertionError("worker error expected")
except OSError:
    pass
h.subprocess.Popen = real_popen
must(claimed_job(jw)["failure"]["classification"] == "worker_error" and not folder_of(jw).exists(), "worker error")
FakeChild.HANG[0] = True
jt = dispatched("sigmod.slow")
h.run_job(jt)
FakeChild.HANG[0] = False
must(claimed_job(jt)["failure"]["classification"] == "timeout" and not folder_of(jt).exists() and all(VALUE not in t for t in logs_of(jt).values()), "timeout")
jc = dispatched()
data = claimed_job(jc)
data["cancel_requested_at"] = "2026-11-10T10:00:00+00:00"
h.claimed_job_path(jc).write_text(json.dumps(data), encoding="utf-8")
FakeChild.CALLS.clear()
h.run_job(jc)
must(claimed_job(jc)["status"] == "cancelled" and not FakeChild.CALLS and not folder_of(jc).exists(), "cancelled before execution")

# cancel_job (the unit is stopped): the folder is removed
jk = dispatched()
h.subprocess.run = lambda command, **kw: SimpleNamespace(returncode=0, stderr="", stdout="")
h.cancel_job(jk)
must(claimed_job(jk)["status"] == "cancelled" and not folder_of(jk).exists(), "cancel")
h.subprocess.run = h_run

# the folder or a required file is gone at run time (swept, reboot): fail closed, the program never starts
for breaker in ("folder", "file"):
    jm = dispatched()
    if breaker == "folder":
        h._remove_tree(folder_of(jm))
    else:
        os.chmod(folder_of(jm) / "dns-token", 0o600)  # a 0400 file is read-only on Windows
        (folder_of(jm) / "dns-token").unlink()
    FakeChild.CALLS.clear()
    h.run_job(jm)
    done = claimed_job(jm)
    must(done["status"] == "failed" and done["failure"]["classification"] == "secret_missing" and not FakeChild.CALLS, (breaker, done))

# a hand registration or a symlinked folder is never given to a child
js = dispatched()
data = claimed_job(js)
(HREG / "sigmod.cert.json").write_text(json.dumps({**json.loads((HREG / "sigmod.cert.json").read_text(encoding="utf-8")), "registered_by": None}), encoding="utf-8")
FakeChild.CALLS.clear()
h.run_job(js)
must(claimed_job(js)["failure"]["classification"] == "secret_missing" and not FakeChild.CALLS, "run_job refuses secrets for a hand registration")
hregister("sigmod.cert", permission="sigmod.renew", secret_inputs=SECRET_LIST)

# ================================================================================================ the sweep
running_job = dispatched()
terminal_job = dispatched()
data = claimed_job(terminal_job)
data["status"] = "succeeded"
h.claimed_job_path(terminal_job).write_text(json.dumps(data), encoding="utf-8")
ghost = str(uuid.uuid4())
h.write_secret_dir(ghost, {"dns-token": b"GHOST"})
(h.SECRETS_ROOT / "not-a-job").mkdir()
h.sweep_secret_dirs()
must(folder_of(running_job).is_dir() and not folder_of(terminal_job).exists() and not folder_of(ghost).exists() and not (h.SECRETS_ROOT / "not-a-job").exists(), "the sweep keeps a running job's folder and removes the rest")
h.finish_secrets(running_job)
h.ensure_layout()  # ensure_layout sweeps too and never raises
leftover = dispatched()
terminal = claimed_job(leftover)
terminal["status"] = "failed"
h.claimed_job_path(leftover).write_text(json.dumps(terminal), encoding="utf-8")
h.ensure_layout()
must(not folder_of(leftover).exists(), "ensure_layout sweeps a terminal job's folder")
if hasattr(os, "symlink"):
    try:
        victim = BASE / "victim-dir"
        victim.mkdir()
        (victim / "keep.txt").write_text("keep", encoding="utf-8")
        os.symlink(victim, h.SECRETS_ROOT / str(uuid.uuid4()), target_is_directory=True)
        h.sweep_secret_dirs()
        must((victim / "keep.txt").read_text(encoding="utf-8") == "keep", "a symlink in the secrets root is removed, never followed")
    except (OSError, NotImplementedError):
        print("       symlink case skipped on this platform (the dev-server run covers it)")
h.sys = real_sys

# ================================================================================================ the pieces around it
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("_resolve_secret_inputs" in install and "(1,3,0)" in install, "install.sh verifies the provider carries secret_inputs")
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
for needle in ("now 1.3.0", "secret_inputs", "TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR", "secret_not_configured", ">=1.17.113"):
    must(needle in contracts, f"the contract text names {needle}")
docs = (ROOT / "docs" / "server-maintenance-capability.md").read_text(encoding="utf-8")
must("## Secret inputs" in docs and "never print it" in docs.replace("**", "") and "TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR" in docs, "the capability doc has the section")
must("server-maintenance-capability.md" in (ROOT / "docs" / "secret-store.md").read_text(encoding="utf-8"), "the secret-store doc points at it")
source_helper = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
must("stdin=subprocess.DEVNULL" in source_helper, "the program still runs with stdin closed")
must("sudo" not in (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8").split("def main")[1], "main is unchanged")

# ================================================================================================ precheck fixes
# 1. a forged call of the real _resolve_secret_inputs (a module-path caller, any action id) is refused and reads nothing
import inspect

must(list(inspect.signature(sm._resolve_secret_inputs).parameters) == ["action_id"], "the hand-over takes an id, never a caller-supplied action dict")
before_reads = len(RUNS)
forged = {"sm": sm, "__name__": "sigmod.views"}
exec(compile("def go(i):\n    return sm._resolve_secret_inputs(i)\n", str(BASE / "sigmod" / "views.py"), "exec"), forged)
for victim in ("sigmod.cert", "other.act", "nope.x"):
    try:
        forged["go"](victim)
        raise AssertionError("a forged call of _resolve_secret_inputs was accepted")
    except sm.ServerMaintenanceValidationError as exc:
        must(exc.classification == "secret_not_allowed" and VALUE not in str(exc), exc.classification)
try:  # a function named like the real caller in the real file is still not start()
    other = {"sm": sm, "__name__": "tec_tac.server_maintenance"}
    exec(compile("def start(i):\n    return sm._resolve_secret_inputs(i)\n", str(APP / "server_maintenance.py"), "exec"), other)
    other["start"]("sigmod.cert")
    raise AssertionError("a look-alike start() was accepted")
except sm.ServerMaintenanceValidationError as exc:
    must(exc.classification == "secret_not_allowed", exc.classification)
# the hand-over carries no readable value attribute
ho = sm._SecretHandOver(["x"], {"x": VALUE.encode()})
must(not hasattr(ho, "_values") and not hasattr(ho, "__dict__") and VALUE not in repr([getattr(ho, n) for n in ho.__slots__ if n != "stdin_text" and n != "scrub"]), "no attribute holds the bytes")
must(VALUE not in ho.scrub(VALUE) and json.loads(ho.stdin_text())["x"] == base64.b64encode(VALUE.encode()).decode(), "closures still work")

# 2. disabled: an action that lists secret_inputs refuses to start, nothing is read, no job, no hand-over row
sm.SECRET_INPUTS_ENABLED = False
RUNS.clear()
jobs_before = all_state_text()
try:
    provider.start(action="sigmod.cert", context=ctx, user=boss)
    raise AssertionError("started with secret inputs switched off")
except sm.ServerMaintenanceValidationError as exc:
    must(exc.classification == "secret_inputs_disabled" and VALUE not in str(exc), exc.classification)
must(not RUNS and all_state_text() == jobs_before, "no dispatch and no job file when the feature is off")
must(sm.get_server_maintenance_provider() is not None and "secret_inputs_enabled" in (APP / "server_maintenance.py").read_text(encoding="utf-8"), "metadata says it is off")
sm.SECRET_INPUTS_ENABLED = True

print("[TEST] PASS server maintenance secret inputs 1.17.113")
