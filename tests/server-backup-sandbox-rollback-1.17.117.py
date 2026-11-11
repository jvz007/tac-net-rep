#!/usr/bin/env python3
"""1.17.117 regression: the server-backup rollback list covers the core.sandbox installer targets (held finding on 1.17.116).

Covered: /usr/local/sbin/tec-tac-sandbox and /etc/sudoers.d/tec-tac-sandbox are in TEC_TAC_PRIVILEGED_INSTALL_PATHS; with an empty systemd
root, _tec_tac_systemd_unit_paths lists the slice, the drop-in file, the sweep service and the sweep timer (so rollback records their
absence); _tec_tac_restore_host_paths includes all of them; every sandbox literal install.sh writes (the SANDBOX_* assignments) is
covered by a rollback path or by a snapshotted parent. /var/lib/tec-tac/sandbox (the helper's own audit log) is intentionally not rolled
back, like the other persistent records.

server-backup-helper.py imports fcntl, grp and pwd, which Windows lacks. They are stubbed in sys.modules before the import so this test
runs on a development PC; on Linux the real modules are used.
"""
from __future__ import annotations

import importlib.util
import os
import re
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
for name in ("fcntl", "grp", "pwd"):
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tt_server_backup_sandbox_rollback", ROOT / "scripts" / "server-backup-helper.py")
mod = importlib.util.module_from_spec(spec)
if os.name == "nt":
    # The helper resolves a root-owned bash at import. Windows has none: answer that one question while the module loads, nothing else.
    _real_open, _real_fstat = os.open, os.fstat

    def _fake_open(path, flags, *a, **k):
        return _real_open(__file__, os.O_RDONLY | getattr(os, "O_BINARY", 0)) if str(path) in ("/bin/bash", "/usr/bin/bash") else _real_open(path, flags, *a, **k)

    def _fake_fstat(fd):
        info = list(_real_fstat(fd))
        info[0], info[4] = stat.S_IFREG | 0o755, 0
        return os.stat_result(info)

    os.open, os.fstat = _fake_open, _fake_fstat
    try:
        spec.loader.exec_module(mod)
    finally:
        os.open, os.fstat = _real_open, _real_fstat
else:
    spec.loader.exec_module(mod)


def must(condition, message):
    if not condition:
        raise AssertionError(message)


privileged = {Path(p) for p in mod.TEC_TAC_PRIVILEGED_INSTALL_PATHS}
must(Path("/usr/local/sbin/tec-tac-sandbox") in privileged, "the sandbox helper link is not in the rollback list")
must(Path("/etc/sudoers.d/tec-tac-sandbox") in privileged, "the sandbox sudoers file is not in the rollback list")

with tempfile.TemporaryDirectory(prefix="tectac-sandbox-rollback-") as td:
    systemd = Path(td) / "system"  # does not exist: only the fixed inventory can name the units
    units = {Path(p) for p in mod._tec_tac_systemd_unit_paths(systemd)}
    wanted = {
        systemd / "tec-tac-sandbox.slice",
        systemd / "tec-tac-sandbox.slice.d" / "limits.conf",
        systemd / "tec-tac-sandbox-sweep.service",
        systemd / "tec-tac-sandbox-sweep.timer",
    }
    must(wanted <= units, f"missing from the unit inventory: {sorted(map(str, wanted - units))}")
    systemd.mkdir()
    must(wanted <= {Path(p) for p in mod._tec_tac_systemd_unit_paths(systemd)}, "units are still listed when the folder exists and is empty")
    config = {
        "TEC_TAC_STATE_ROOT": str(Path(td) / "state"), "TACTICAL_ROOT": str(Path(td) / "rmm"), "TEC_TAC_ROOT": str(Path(td) / "tt"),
        "TEC_TAC_FRAMEWORK_SOURCE": str(Path(td) / "fw"), "TEC_TAC_UI_SOURCE": str(Path(td) / "ui"), "TEC_TAC_UI_DEPLOY_ROOT": str(Path(td) / "uid"),
    }
    restore = {Path(p) for p in mod._tec_tac_restore_host_paths(config, systemd)}
    must(wanted <= restore, "the restore path set does not include the sandbox units")
    must({Path("/usr/local/sbin/tec-tac-sandbox"), Path("/etc/sudoers.d/tec-tac-sandbox")} <= restore, "the restore path set does not include the sandbox helper and sudoers")

# every sandbox literal install.sh writes is covered: by a path in the set, or by a parent that is snapshotted
install_text = (ROOT / "install.sh").read_text(encoding="utf-8")
values = dict(re.findall(r'^(SANDBOX_[A-Z_]+)="([^"$]+)"$', install_text, re.MULTILINE))
must({"SANDBOX_HELPER", "SANDBOX_LIB", "SANDBOX_STATE", "SANDBOX_SUDOERS", "SANDBOX_SLICE", "SANDBOX_SLICE_DROPIN_DIR", "SANDBOX_SWEEP_SERVICE", "SANDBOX_SWEEP_TIMER"} <= set(values), sorted(values))
systemd_root = Path("/etc/systemd/system")
covered = privileged | {Path(p) for p in mod._tec_tac_systemd_unit_paths(systemd_root)} | {systemd_root / "tec-tac-sandbox.slice.d"}
# the drop-in directory is covered through the limits.conf file it holds; the state folder is the helper's own audit log, kept on purpose
kept_on_purpose = {Path(values["SANDBOX_STATE"])}
for key, raw in sorted(values.items()):
    if key == "SANDBOX_SELFTEST_TIMEOUT_SECONDS":
        continue
    path = Path(raw)
    if path in kept_on_purpose:
        continue
    must(any(path == root or root in path.parents for root in covered), f"install.sh target {key}={raw} is not covered by rollback")
# the drop-in file itself
must(Path(values["SANDBOX_SLICE_DROPIN_DIR"]) / "limits.conf" in covered, "the limits.conf drop-in is not covered")

print("[TEST] PASS server backup sandbox rollback 1.17.117")
