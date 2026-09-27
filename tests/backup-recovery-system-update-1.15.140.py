#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def must(value, message):
    if not value:
        raise AssertionError(message)


backup = load("sbh_115140", ROOT / "scripts" / "server-backup-helper.py")
update = load("suh_115140", ROOT / "scripts" / "system-update-helper.py")
recovery = load("recovery_key_115140", ROOT / "scripts" / "recovery-key-cli.py")

# L17: the configured Module Manager state root, not TEC_TAC_STATE_ROOT/module-manager,
# is authoritative for backup, restore allow-listing and host rollback coverage.
cfg = {
    "TEC_TAC_ROOT": "/opt/tec-tac",
    "TEC_TAC_FRAMEWORK_SOURCE": "/opt/tec-tac-src/framework",
    "TEC_TAC_UI_SOURCE": "/opt/tec-tac-src/ui",
    "TEC_TAC_STATE_ROOT": "/var/lib/tec-tac-custom-state",
    "TEC_TAC_MODULE_STATE_ROOT": "/srv/tec-tac/module-state",
    "TEC_TAC_UI_DEPLOY_ROOT": "/var/lib/tec-tac/ui/tec-tac",
    "TACTICAL_ROOT": "/rmm",
}
paths = backup.tec_tac_paths(cfg)
must(str(paths["module_state"]) == "/srv/tec-tac/module-state/module-state.json", "backup ignored TEC_TAC_MODULE_STATE_ROOT")
must(str(paths["repository_config"]) == "/srv/tec-tac/module-state/repositories/repositories.json", "repository state did not follow module state root")
allowed = backup._tec_tac_restore_allowed_roots(cfg)
must("srv/tec-tac/module-state/module-state.json" in allowed, "restore allow-list ignored custom module state root")
host_paths = set(backup._tec_tac_restore_host_paths(cfg, Path("/etc/systemd/system")))
must("/srv/tec-tac/module-state/module-state.json" in host_paths, "rollback snapshot ignored custom module state root")
must("/srv/tec-tac/module-state/repositories/repositories.json" in host_paths, "repository rollback ignored custom module state root")

# L76: installed recovery-key command must use isolated Python and its trust root
# must be config-derived. Root-owned identity/key reads reject symlinks and writable files.
first_line = (ROOT / "scripts" / "recovery-key-cli.py").read_text(encoding="utf-8").splitlines()[0]
must(first_line == "#!/usr/bin/python3 -I", "recovery-key command is not using isolated Python")
must(recovery._absolute_layout_path({"TEC_TAC_RECOVERY_TRUST_ROOT": "/srv/tectac/trust"}, "TEC_TAC_RECOVERY_TRUST_ROOT", "/etc/tec-tac/recovery-trust") == Path("/srv/tectac/trust"), "recovery trust root is still hard-coded")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    safe = root / "safe"
    safe.write_bytes(b"identity\n")
    os.chmod(safe, 0o600)
    must(recovery._read_root_regular(safe) == b"identity\n", "safe root-owned recovery file was rejected")
    link = root / "link"
    link.symlink_to(safe)
    try:
        recovery._read_root_regular(link)
    except RuntimeError:
        pass
    else:
        raise AssertionError("recovery identity read followed a symlink")
    writable = root / "writable"
    writable.write_bytes(b"bad")
    os.chmod(writable, 0o666)
    try:
        recovery._read_root_regular(writable)
    except RuntimeError:
        pass
    else:
        raise AssertionError("group/world-writable recovery identity file was accepted")

# L77: recovery-key is part of the same host rollback inventory as the other
# privileged helpers, and the installer-discovery regression no longer exempts it.
must("/usr/local/sbin/tec-tac-recovery-key" in backup.TEC_TAC_PRIVILEGED_INSTALL_PATHS, "recovery-key helper is absent from rollback inventory")
must("/usr/local/sbin/tec-tac-recovery-key" in host_paths, "recovery-key helper is absent from rollback snapshot targets")
rollback_test = (ROOT / "tests" / "server-backup-host-rollback.py").read_text(encoding="utf-8")
must('known_uncovered_installer_paths = set()' in rollback_test, "rollback regression still exempts recovery-key")

# L78: an update failure must still be finalized when config becomes unreadable
# after startup. run_job may load config/tactical gid once, never again in finally.
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    target = tmp / "framework"
    target.mkdir()
    (target / "VERSION").write_text("1.15.139\n", encoding="utf-8")
    package = tmp / "package.zip"
    package.write_bytes(b"not-a-real-package")
    job_path = tmp / "job.json"
    log_root = tmp / "logs"
    history_root = tmp / "history"
    running_root = tmp / "running"
    for p in (log_root, history_root, running_root):
        p.mkdir()
    lock_path = tmp / "update.lock"
    job_id = "11111111-1111-1111-1111-111111111111"
    status = {"status": "dispatched", "stage": "queued", "created_at": "now"}
    immutable = {
        "id": job_id,
        "action": "install",
        "component": "framework",
        "package_path": str(package),
        "version": "1.15.140",
        "source": "test",
    }
    calls = {"config": 0, "gid": 0}
    cfg2 = {
        "TEC_TAC_FRAMEWORK_SOURCE": str(target),
        "TEC_TAC_ROOT": str(tmp / "runtime"),
        "TACTICAL_USER": "tactical",
    }

    old = {
        "load_job": update.load_job,
        "load_running_request": update.load_running_request,
        "load_config": update.load_config,
        "tactical_gid": update.tactical_gid,
        "acquire_lifecycle_lock": update.acquire_lifecycle_lock,
        "extract_archive": update.extract_archive,
        "atomic_json": update.atomic_json,
        "private_update_work_dir": update.private_update_work_dir,
        "running_request_path": update.running_request_path,
        "LOGS_ROOT": update.LOGS_ROOT,
        "HISTORY_ROOT": update.HISTORY_ROOT,
        "LOCK_PATH": update.LOCK_PATH,
    }
    writes = []
    try:
        update.load_job = lambda _job_id: (job_path, dict(status))
        update.load_running_request = lambda _job_id: (tmp / "request.json", dict(immutable))
        def one_config():
            calls["config"] += 1
            if calls["config"] > 1:
                raise RuntimeError("config disappeared during update")
            return dict(cfg2)
        update.load_config = one_config
        def one_gid(_cfg):
            calls["gid"] += 1
            if calls["gid"] > 1:
                raise RuntimeError("tactical identity disappeared during update")
            return 4242
        update.tactical_gid = one_gid
        update.acquire_lifecycle_lock = lambda: None
        update.extract_archive = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("forced extraction failure"))
        def fake_atomic(path, payload, *args, **kwargs):
            writes.append((Path(path), json.loads(json.dumps(payload)), dict(kwargs)))
        update.atomic_json = fake_atomic
        @contextlib.contextmanager
        def work(_job_id):
            d = tmp / "work"
            d.mkdir(exist_ok=True)
            yield d
        update.private_update_work_dir = work
        update.running_request_path = lambda _job_id: tmp / "request.json"
        update.LOGS_ROOT = log_root
        update.HISTORY_ROOT = history_root
        update.LOCK_PATH = lock_path
        update.run_job(job_id)
    finally:
        for key, value in old.items():
            setattr(update, key, value)
    must(calls == {"config": 1, "gid": 1}, f"run_job re-read config/tactical gid during finalization: {calls}")
    terminal = [payload for path, payload, _kw in writes if path == job_path and payload.get("status") == "failed"]
    must(terminal, "failed system update was not persisted to a terminal state")
    must(terminal[-1].get("stage") == "failed-pre-mutation", f"unexpected final failed stage: {terminal[-1].get('stage')}")
    final_write = [row for row in writes if row[0] == job_path][-1]
    must(final_write[2].get("gid") == 4242, "final system update write did not reuse captured Tactical gid")

print("backup/recovery/system-update 1.15.140 regression: OK")
