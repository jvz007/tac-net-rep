#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def must(value, message):
    if not value:
        raise AssertionError(message)


class Log:
    def write(self, *_args):
        pass


# ---------------------------------------------------------------------------
# L10: every backup transport must make the sidecar visible before the final
# archive and remove the sidecar again if final archive publication fails.
# ---------------------------------------------------------------------------
h = load("backup161", "scripts/server-backup-helper.py")

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    archive = base / "local.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    dest = base / "dest"
    real_replace = h.os.replace
    events = []

    def failing_replace(src, dst):
        events.append(Path(dst).name)
        if Path(dst).name == archive.name:
            raise RuntimeError("simulated final archive publication failure")
        return real_replace(src, dst)

    h.os.replace = failing_replace
    try:
        try:
            h.store_local({"id": "local", "type": "local", "path": str(dest)}, archive, metadata)
        except RuntimeError:
            pass
        else:
            raise AssertionError("local final archive failure was not surfaced")
    finally:
        h.os.replace = real_replace

    must(events.index("local.tgz.tectac.json") < events.index("local.tgz"), "local archive was published before sidecar")
    must(not (dest / "local.tgz").exists(), "local archive remained visible after failed publish")


class FakeFTP:
    def __init__(self):
        self.objects = {}
        self.cwd_path = "/"

    def storbinary(self, command, fh, blocksize=0):
        name = command.split(" ", 1)[1]
        self.objects[name] = fh.read()

    def size(self, name):
        return len(self.objects[name])

    def retrbinary(self, command, callback, blocksize=0):
        callback(self.objects[command.split(" ", 1)[1]])

    def delete(self, name):
        self.objects.pop(name, None)

    def rename(self, src, dst):
        if dst == "ftp.tgz":
            raise RuntimeError("simulated archive rename failure")
        self.objects[dst] = self.objects.pop(src)

    def quit(self):
        pass

    def close(self):
        pass


with tempfile.TemporaryDirectory() as td:
    archive = Path(td) / "ftp.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    ftp = FakeFTP()
    old_connect, old_prepare = h.ftp_connect, h.ftp_prepare_path
    h.ftp_connect = lambda *_a, **_k: ftp
    h.ftp_prepare_path = lambda *_a, **_k: None
    try:
        try:
            h.ftp_store({}, {"id": "ftp", "type": "ftp", "host": "h", "port": 21, "username": "u", "remote_path": "/"}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("FTP final archive failure was not surfaced")
    finally:
        h.ftp_connect, h.ftp_prepare_path = old_connect, old_prepare
    must("ftp.tgz.tectac.json" not in ftp.objects, "FTP left published sidecar after archive failure")
    must("ftp.tgz" not in ftp.objects, "FTP exposed final archive after failed publish")


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    archive = base / "rclone.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    remote = {}
    old_cfg, old_run, old_subrun = h.make_rclone_config, h.run_logged, h.subprocess.run
    h.make_rclone_config = lambda *_a, **_k: base / "rclone.conf"

    def fake_run_logged(argv, _log, timeout=None):
        op = argv[1]
        if op == "copyto":
            source, target = argv[2], argv[3]
            remote[target] = Path(source).read_bytes()
            return None
        if op == "moveto":
            src, dst = argv[2], argv[3]
            if dst.endswith("/rclone.tgz"):
                raise RuntimeError("simulated archive moveto failure")
            remote[dst] = remote.pop(src)
            return None
        raise AssertionError(argv)

    def fake_subrun(argv, **kwargs):
        if argv[1] == "lsjson":
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Size": 3}]), stderr="")
        if argv[1] == "hash":
            return SimpleNamespace(returncode=0, stdout=metadata["sha256"] + "  rclone.tgz.partial\n", stderr="")
        if argv[1] == "deletefile":
            remote.pop(argv[2], None)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(argv)

    h.run_logged = fake_run_logged
    h.subprocess.run = fake_subrun
    try:
        try:
            h.store_rclone({}, {"id": "r", "type": "s3", "bucket": "bucket", "remote_path": "."}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("rclone final archive failure was not surfaced")
    finally:
        h.make_rclone_config, h.run_logged, h.subprocess.run = old_cfg, old_run, old_subrun
    must(not any(key.endswith("rclone.tgz.tectac.json") for key in remote), "rclone left published sidecar after archive failure")
    must(not any(key.endswith("/rclone.tgz") for key in remote), "rclone exposed final archive after failed publish")


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    staging = base / "staging"
    staging.mkdir()
    remote_dir = base / "remote"
    remote_dir.mkdir()
    archive = base / "scp.tgz"
    archive.write_bytes(b"abc")
    metadata = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    # Force the second mv in the real publish shell to fail.
    (remote_dir / "scp.tgz").mkdir()
    old_roots, old_args, old_run = h.roots, h.scp_args, h.run_logged
    h.roots = lambda _config=None: {"staging": staging}
    h.scp_args = lambda *_a, **_k: ([], [])

    def fake_scp_run(argv, _log, timeout=None):
        if argv[0] == "ssh" and argv[-3:-1] == ["mkdir", "-p"]:
            return None
        if argv[0] == "scp":
            src, dst = argv[-2], argv[-1]
            if ":" in dst:
                target = Path(dst.split(":", 1)[1])
                target.write_bytes(Path(src).read_bytes())
            elif ":" in src:
                source = Path(src.split(":", 1)[1])
                Path(dst).write_bytes(source.read_bytes())
            else:
                raise AssertionError(argv)
            return None
        if argv[0] == "ssh":
            proc = subprocess.run(["bash", "-c", argv[-1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode:
                raise RuntimeError(proc.stderr.strip() or "remote publish failed")
            return None
        raise AssertionError(argv)

    h.run_logged = fake_scp_run
    try:
        try:
            h.store_scp({}, {"id": "s", "type": "scp", "host": "host", "port": 22, "username": "u", "remote_path": str(remote_dir)}, archive, metadata, Log())
        except RuntimeError:
            pass
        else:
            raise AssertionError("SCP final archive failure was not surfaced")
    finally:
        h.roots, h.scp_args, h.run_logged = old_roots, old_args, old_run
    must(not (remote_dir / "scp.tgz.tectac.json").exists(), "SCP left published sidecar after archive failure")
    must((remote_dir / "scp.tgz").is_dir(), "SCP test did not preserve the forced failing final target")


# ---------------------------------------------------------------------------
# L15: measure real host snapshot source bytes and prove that those bytes alter
# the production preflight disk decision. No stub of _preflight_host_snapshot_bytes.
# ---------------------------------------------------------------------------
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    host_file = base / "large-host-state.bin"
    host_file.touch()
    os.truncate(host_file, 700 * 1024 * 1024)  # sparse; lstat size is what cp -a must preserve
    old_paths = h._tec_tac_restore_host_paths
    old_disk = h.shutil.disk_usage
    old_mut = h._mutation_active
    old_which = h.shutil.which
    h._tec_tac_restore_host_paths = lambda _cfg: [host_file]
    h.shutil.disk_usage = lambda _path: SimpleNamespace(total=10 * 1024**3, used=0, free=2100 * 1024**2)
    h._mutation_active = lambda _cfg: False
    h.shutil.which = lambda _name: "/bin/true"
    try:
        measured = h._preflight_host_snapshot_bytes({}, "tec_tac")
        must(measured >= 700 * 1024 * 1024, f"real host snapshot estimator undercounted sparse file: {measured}")
        report = h._vr_new({"restore_mode": "tec_tac"}, "bundle.tgz")
        h.validate_target_preflight({
            "TEC_TAC_SERVER_BACKUP_ROOT": str(base / "backup"),
            "TACTICAL_ROOT": str(base / "tactical"),
            "TEC_TAC_STATE_ROOT": str(base / "state"),
            "TEC_TAC_ROOT": str(base / "runtime"),
            "TEC_TAC_FRAMEWORK_SOURCE": str(base / "framework"),
            "TEC_TAC_UI_SOURCE": str(base / "ui"),
            "TEC_TAC_UI_DEPLOY_ROOT": str(base / "deploy"),
        }, report, "tec_tac", 500 * 1024 * 1024)
    finally:
        h._tec_tac_restore_host_paths = old_paths
        h.shutil.disk_usage = old_disk
        h._mutation_active = old_mut
        h.shutil.which = old_which
    disk = next(row for row in report["sections"]["target"]["checks"] if row["id"] == "target.disk")
    must(disk["status"] == "failed", "real host snapshot bytes did not affect preflight disk decision")
    must(f"host_snapshot_estimate={measured}" in disk["detail"], "preflight did not report measured host snapshot bytes")


# ---------------------------------------------------------------------------
# L24: execute migration 0015's production normalizer against representative
# legacy rows. Valid legacy forms must become runtime-valid canonical targets;
# generic id widening must fail closed; immutable run history must not be read.
# ---------------------------------------------------------------------------
mig_path = ROOT / "framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py"
mig_tree = ast.parse(mig_path.read_text(encoding="utf-8"))
keep_names = {
    "_values", "_ids", "_extract_native", "_legacy_normalize", "_endpoint_rows",
    "_canonical_endpoint_ids", "_canonicalize_endpoint_identity", "canonicalize_existing_targets",
}
body = []
for node in mig_tree.body:
    if isinstance(node, ast.Assign):
        names = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if names & {"_NATIVE", "_ALIASES"}:
            body.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in keep_names:
        body.append(node)
mig_ns = {}
exec(compile(ast.Module(body=body, type_ignores=[]), str(mig_path), "exec"), mig_ns)

targets = load("scheduler_targets161", "framwork/tec_tac/scheduler_targets.py")

class ScheduleRow:
    def __init__(self, value):
        self.targets = value
        self.enabled = True
        self.target_state = "valid"
        self.target_state_detail = ""
        self.saved = []

    def save(self, update_fields=None):
        self.saved.append(tuple(update_fields or ()))


rows = [
    ScheduleRow({"type": "client", "client_id": 7}),
    ScheduleRow({"type": "site", "site_ids": [3, 4]}),
    ScheduleRow({"type": "endpoint", "agent_id": "42"}),
    ScheduleRow({"type": "dynamic", "scope": {"site_id": 9}, "filter": {"name": "server"}}),
    ScheduleRow({"type": "client", "id": 99}),
]

class ScheduleObjects:
    def all(self): return self
    def iterator(self): return iter(rows)

class Schedule:
    objects = ScheduleObjects()

class RunObjects:
    def __getattr__(self, name):
        raise AssertionError(f"migration touched immutable run history via {name}")

class Run:
    objects = RunObjects()

class AgentValues:
    def values_list(self, *_args):
        return [(42, "agent-42")]

class AgentObjects:
    def all(self):
        return AgentValues()

class Agent:
    objects = AgentObjects()

class Apps:
    def get_model(self, app, model):
        if (app, model) == ("tec_tac", "TecTacSchedule"): return Schedule
        if (app, model) == ("tec_tac", "TecTacScheduleRun"): return Run
        if (app, model) == ("agents", "Agent"): return Agent
        raise AssertionError((app, model))

mig_ns["canonicalize_existing_targets"](Apps(), None)
expected = [
    {"type": "client", "ids": [7]},
    {"type": "site", "ids": [3, 4]},
    {"type": "endpoint", "ids": ["agent-42"]},
    {"type": "dynamic", "scope": {"type": "site", "ids": [9]}, "filter": {"name": "server"}},
]
for row, want in zip(rows[:4], expected):
    must(row.targets == want, f"legacy migration mismatch: {row.targets!r} != {want!r}")
    must(row.target_state == "valid" and row.enabled is True, "valid legacy row was quarantined")
    must(targets.normalize_scheduler_targets(row.targets) == want, "migration output disagrees with runtime normalizer")
invalid = rows[4]
must(invalid.enabled is False and invalid.target_state == "invalid", "generic id alias widened a client target instead of failing closed")
must(invalid.targets == {"type": "client", "id": 99}, "invalid legacy target was rewritten")


# ---------------------------------------------------------------------------
# L25: exercise canonical save identity, legacy authorization compatibility,
# ambiguous token rejection, and the history scope snapshot's dual aliases.
# ---------------------------------------------------------------------------
adapter_path = ROOT / "framwork/tec_tac/resources_adapter.py"
adapter_tree = ast.parse(adapter_path.read_text(encoding="utf-8"))
adapter_funcs = {
    "canonical_agent_target_ids_in_scope", "agent_target_identifiers_in_scope", "scheduler_scope_snapshot"
}
adapter_nodes = [n for n in adapter_tree.body if isinstance(n, ast.FunctionDef) and n.name in adapter_funcs]

class AdapterError(RuntimeError): pass
class Q:
    def __init__(self, *a, **kw): pass
    def __or__(self, other): return self
class QS:
    def __init__(self, rows): self.rows = list(rows)
    def filter(self, *a, **kw): return self
    def values_list(self, *fields, **kwargs):
        if fields == ("pk", "agent_id"): return list(self.rows)
        if fields == ("pk",) and kwargs.get("flat"): return [r[0] for r in self.rows]
        raise AssertionError((fields, kwargs))
class Manager:
    def __init__(self, rows): self.rows = rows
    def all(self): return QS(self.rows)
class Site: objects = Manager([])
class Agent: objects = Manager([(42, "agent-42"), (77, "agent-77"), (88, "77")])
class Relation:
    def values_list(self, *fields, **kwargs): return []
class Role:
    can_view_clients = Relation()
    can_view_sites = Relation()
role = Role()

adapter_ns = {
    "TacticalResourceAdapterError": AdapterError,
    "Q": Q,
    "_models": lambda: (None, Site, Agent),
    "_scope_queryset": lambda qs, **kw: qs,
    "_role_for_user": lambda user: role,
    "_role_scope_unrestricted": lambda **kw: False,
}
exec(compile(ast.Module(body=adapter_nodes, type_ignores=[]), str(adapter_path), "exec"), adapter_ns)

must(adapter_ns["canonical_agent_target_ids_in_scope"](user=object(), identifiers=["42"]) == ["agent-42"], "endpoint PK did not canonicalize to agent_id")
must(adapter_ns["canonical_agent_target_ids_in_scope"](user=object(), identifiers=["agent-42"]) == ["agent-42"], "canonical agent_id changed")
try:
    adapter_ns["canonical_agent_target_ids_in_scope"](user=object(), identifiers=["77"])
except AdapterError:
    pass
else:
    raise AssertionError("ambiguous endpoint token was accepted for persistence")
must(adapter_ns["agent_target_identifiers_in_scope"](user=object(), identifiers=["42"]) == {"42"}, "legacy endpoint PK was not authorized for existing schedule")
must(adapter_ns["agent_target_identifiers_in_scope"](user=object(), identifiers=["agent-42"]) == {"agent-42"}, "canonical endpoint id was not authorized")
snapshot = adapter_ns["scheduler_scope_snapshot"](user=object())
must({"42", "agent-42"}.issubset(snapshot["endpoint_ids"]), "history scope snapshot does not preserve both PK and agent_id aliases")

views_path = ROOT / "framwork/tec_tac/scheduler_views.py"
views_tree = ast.parse(views_path.read_text(encoding="utf-8"))
view_nodes = [n for n in views_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_canonicalize_endpoint_targets_for_user"]
resources_adapter = SimpleNamespace(canonical_agent_target_ids_in_scope=adapter_ns["canonical_agent_target_ids_in_scope"])
class PermissionDenied(RuntimeError): pass
view_ns = {"resources_adapter": resources_adapter, "PermissionDenied": PermissionDenied}
exec(compile(ast.Module(body=view_nodes, type_ignores=[]), str(views_path), "exec"), view_ns)
canonical = view_ns["_canonicalize_endpoint_targets_for_user"](object(), {"type": "endpoints", "ids": ["42"]})
must(canonical == {"type": "endpoints", "ids": ["agent-42"]}, "scheduler save path did not persist canonical agent_id")

print("tracker behavior closure 1.15.161: PASS")
