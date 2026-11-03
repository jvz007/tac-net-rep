#!/usr/bin/env python3
"""1.17.110: Core works on Tactical 1.5.2 and 1.6.1.

Covers the two compatibility items of docs/planning/tactical-1.6.1/IMPACT-TACTICAL-1.6.1.md:

1. Server backup and restore. backup.sh v34 (1.5.2) works under TMPDIR, Core's job staging folder; backup.sh v35 (1.6.1)
   always works in /var/tmp. The privileged helper accepts exactly the job's own new /var/tmp/tacticalrmm-* folder,
   checked without following links, and Core removes it afterwards. restore.sh v67 and v68 each have a profile (OS
   gate and supported systems); any other version is refused.
2. Schedule runs set an explicit soft and hard Celery time limit, so Tactical 1.6.1's worker default soft limit
   (14 100 seconds) never cuts a run.

The backup helper imports fcntl, pwd and grp, so its part runs on Linux only (root gives the fullest coverage: the
wrong-owner case needs chown). The scheduler, docs and release parts run everywhere.
"""
from __future__ import annotations

import ast
import datetime as dt
import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
VERSION = "1.17.110"
results = []


def ok(name):
    results.append(name)


# ---------------------------------------------------------------- scheduler (runs everywhere)

sched_src = (ROOT / "framwork/tec_tac/scheduler.py").read_text(encoding="utf-8")
sched_tree = ast.parse(sched_src)
fn = next(n for n in sched_tree.body if isinstance(n, ast.FunctionDef) and n.name == "schedule_run_time_limits")
ns = {
    "MAX_ACTION_TIMEOUT_SECONDS": 604800,
    "DEFAULT_RUNNING_STALE_GRACE": dt.timedelta(minutes=5),
    "SCHEDULE_RUN_SOFT_LIMIT_MARGIN_SECONDS": 60,
}
mod = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(mod)
exec(compile(mod, "scheduler.py", "exec"), ns)
limits = ns["schedule_run_time_limits"]
assert limits(3600) == (3900, 3840), limits(3600)
assert limits(604800) == (605100, 605040)
assert limits(10 ** 9) == (605100, 605040), "timeout above the seven-day maximum must be clamped"
for timeout in (60, 900, 7200, 14100, 14400, 86400, 604800):
    hard, soft = limits(timeout)
    assert timeout < soft < hard, (timeout, soft, hard)
assert limits(14100)[1] > 14100 and limits(86400)[1] > 14100, "soft limit must not fall back to the worker's 14 100 s"
assert "SCHEDULE_RUN_SOFT_LIMIT_MARGIN_SECONDS = 60" in sched_src
ok("schedule_run_time_limits: hard = timeout + 300, soft = hard - 60, clamped to seven days")

queue_fn = next(n for n in sched_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_queue_run")
calls = [n for n in ast.walk(queue_fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "apply_async"]
assert len(calls) == 1
kws = {k.arg for k in calls[0].keywords}
assert {"time_limit", "soft_time_limit"} <= kws, kws
ok("_queue_run sends time_limit and soft_time_limit")

tasks_tree = ast.parse((ROOT / "framwork/tec_tac/tasks.py").read_text(encoding="utf-8"))
task = next(n for n in tasks_tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute_schedule_run")
deco = next(d for d in task.decorator_list if isinstance(d, ast.Call))
dk = {k.arg: k.value for k in deco.keywords}
assert isinstance(dk.get("time_limit"), ast.Constant) and dk["time_limit"].value == 605100
assert isinstance(dk.get("soft_time_limit"), ast.Constant) and dk["soft_time_limit"].value == 605040
assert dk["soft_time_limit"].value > 14100
ok("execute_schedule_run declares time_limit=605100 and soft_time_limit=605040")

sched_doc = (ROOT / "docs/scheduler.md").read_text(encoding="utf-8")
for needle in ("Core 1.17.110", "--soft-time-limit=14100", "2 000-endpoint", "10 Celery workers", "schedule_run_time_limits", "PendingCompletion"):
    assert needle in sched_doc, needle
ok("docs/scheduler.md documents the limits and 2 000-endpoint expectations against the 10-worker cap")

# ---------------------------------------------------------------- release files (runs everywhere)

assert (ROOT / "VERSION").read_text().strip() == VERSION
assert json.loads((ROOT / "tec_tac_package.json").read_text())["version"] == VERSION
notes = (ROOT / f"RELEASE_NOTES_{VERSION}.md").read_text(encoding="utf-8")
assert "works on Tactical 1.5.2 and 1.6.1" in notes
assert (ROOT / "docs/releases/RELEASE_NOTES_1.17.109.md").is_file()
for rel in ("install.sh", "scripts/server-backup-helper.py", "scripts/tactical-backup-sudo.py", "framwork/tec_tac/tasks.py", "docs/server-backup-capability.md"):
    assert b"\r" not in (ROOT / rel).read_bytes(), f"{rel} must stay LF"
raw = (ROOT / "framwork/tec_tac/scheduler.py").read_bytes()
assert raw.count(b"\n") == raw.count(b"\r\n"), "scheduler.py must stay CRLF throughout"
raw = (ROOT / "docs/scheduler.md").read_bytes()
assert raw.count(b"\n") == raw.count(b"\r\n"), "docs/scheduler.md must stay CRLF throughout"
backup_doc = (ROOT / "docs/server-backup-capability.md").read_text(encoding="utf-8")
assert "## Tactical 1.5.2 and 1.6.1 (1.17.110)" in backup_doc and "target.restore_script" in backup_doc
ok("version, notes, docs and line endings")

# ---------------------------------------------------------------- backup helper (Linux only)

if os.name != "posix":
    for name in results:
        print(f"[TEST] PASS {name}")
    print("[TEST] SKIP backup/restore helper part: it needs Linux (fcntl, pwd, grp). Run this file on Linux for full coverage.")
    sys.exit(0)

spec = importlib.util.spec_from_file_location("server_backup_helper_1_17_110", ROOT / "scripts/server-backup-helper.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
spec2 = importlib.util.spec_from_file_location("tactical_backup_sudo_1_17_110", ROOT / "scripts/tactical-backup-sudo.py")
shim = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(shim)

V34_HEAD = '#!/usr/bin/env bash\n\nSCRIPT_VERSION="34"\n\ntmp_dir=$(mktemp -d -t tacticalrmm-XXXXXXXXXXXXXXXXXXXXX)\n'
V35_HEAD = '#!/usr/bin/env bash\n\nSCRIPT_VERSION="35"\n\ntmp_dir=$(mktemp -d -p /var/tmp tacticalrmm-XXXXXXXXXXXXXXXXXXXXX)\n'
JOB = "11111111-2222-4333-8444-555555555110"
NAME_A = "tacticalrmm-" + "A1b2C3d4E5f6G7h8I9j0K"
NAME_B = "tacticalrmm-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3"
NAME_OLD = "tacticalrmm-" + "OldOldOldOldOldOldOld"
assert h.TACTICAL_WORKSPACE_NAME_RE.fullmatch(NAME_A) and h.TACTICAL_WORKSPACE_NAME_RE.fullmatch(NAME_OLD)


class Log:
    def __init__(self):
        self.lines = []

    def write(self, value):
        self.lines.append(str(value))


def expect_exit(fn, *args, contains=""):
    try:
        fn(*args)
    except SystemExit as exc:
        assert contains in str(exc), (contains, str(exc))
        return str(exc)
    raise AssertionError(f"expected refusal containing {contains!r}")


with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    me = os.geteuid()
    state = td / "state"
    var_tmp = td / "var-tmp"
    tactical_root = td / "rmm"
    for p in (state / "staging", var_tmp, tactical_root):
        p.mkdir(parents=True)
    os.chmod(var_tmp, 0o1777)
    cfg = {"TEC_TAC_SERVER_BACKUP_ROOT": str(state), "TACTICAL_ROOT": str(tactical_root), "TACTICAL_USER": "tactical"}
    h.TACTICAL_VAR_TMP = var_tmp
    h.TACTICAL_VAR_TMP_OWNER_UID = os.stat(var_tmp).st_uid
    h.tactical_identity = lambda _cfg: (me, os.getegid(), "tactical", str(td))

    # Script versions are read without following links.
    (tactical_root / "backup.sh").write_text(V34_HEAD)
    assert h._tactical_script_version(tactical_root / "backup.sh") == "34"
    (tactical_root / "backup.sh").write_text(V35_HEAD)
    assert h._tactical_script_version(tactical_root / "backup.sh") == "35"
    (td / "link.sh").symlink_to(tactical_root / "backup.sh")
    assert h._tactical_script_version(td / "link.sh") is None
    assert h.TACTICAL_BACKUP_WORKSPACE_MODES == {"34": "staging", "35": "var-tmp"}
    ok("backup.sh v34 maps to staging, v35 to /var/tmp; a linked script is not read")

    # An unchecked backup.sh is refused before anything is created.
    (tactical_root / "backup.sh").write_text(V35_HEAD.replace('"35"', '"36"'))
    try:
        h.create_tactical_component(cfg, Log(), JOB)
    except RuntimeError as exc:
        assert "v36" in str(exc) and "v34 or v35" in str(exc), str(exc)
    else:
        raise AssertionError("backup.sh v36 was not refused")
    assert not (state / "staging" / f"tactical-native-{JOB}").exists()
    ok("backup.sh v36 is refused before any folder is created")

    # /var/tmp itself must be a real, sticky directory owned by root.
    assert h._var_tmp_root_problem(var_tmp) is None
    os.chmod(var_tmp, 0o777)
    assert "sticky" in h._var_tmp_root_problem(var_tmp)
    os.chmod(var_tmp, 0o1777)
    (td / "var-tmp-link").symlink_to(var_tmp)
    assert "real directory" in h._var_tmp_root_problem(td / "var-tmp-link")
    ok("/var/tmp must be a real sticky root-owned directory")

    # The v35 binding: root-only file, pre-existing folders listed.
    old = var_tmp / NAME_OLD
    old.mkdir(mode=0o700)
    binding_path = h._tactical_workspace_binding_path(cfg, JOB)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(var_tmp / NAME_A), contains="binding is missing")
    binding = {"job_id": JOB, "backup_script_version": "35", "mode": "var-tmp", "preexisting": h._var_tmp_workspace_names(var_tmp), "claimed": None}
    assert binding["preexisting"] == [NAME_OLD]
    h.atomic_json(binding_path, binding, mode=0o644)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(var_tmp / NAME_A), contains="binding is unsafe")
    h.atomic_json(binding_path, binding, mode=0o600)
    ok("a missing or group/world-readable binding is refused")

    ws = var_tmp / NAME_A
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(ws), contains="invalid Tactical backup privileged workspace")  # not created yet
    ws.mkdir(mode=0o700)
    for sub in ("nginx", "systemd", "certs", "opt", "confd"):
        (ws / sub).mkdir()
    os.chmod(ws, 0o755)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(ws), contains="not private")
    os.chmod(ws, 0o700)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(old), contains="existed before")
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(var_tmp / "tacticalrmm-short"), contains="not a backup.sh work folder")
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(td / NAME_A), contains="not a backup.sh work folder")
    expect_exit(h._validate_tactical_workspace, cfg, JOB, f"{var_tmp}/../var-tmp/{NAME_A}", contains="not a backup.sh work folder")
    expect_exit(h._validate_tactical_workspace, cfg, JOB, NAME_A, contains="not a backup.sh work folder")
    link_target = td / "elsewhere"
    link_target.mkdir(mode=0o700)
    link = var_tmp / ("tacticalrmm-" + "L" * 21)
    link.symlink_to(link_target)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(link), contains="invalid Tactical backup privileged workspace")
    ok("wrong mode, pre-existing, misnamed, outside, traversal, relative and linked folders are refused")

    accepted = h._validate_tactical_workspace(cfg, JOB, str(ws))
    assert accepted == ws
    assert json.loads(binding_path.read_text())["claimed"] == NAME_A
    assert stat.S_IMODE(binding_path.stat().st_mode) == 0o600
    assert h._validate_tactical_workspace(cfg, JOB, str(ws)) == ws
    other = var_tmp / NAME_B
    other.mkdir(mode=0o700)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(other), contains="already uses")
    ok("the first new folder is claimed; a second folder is refused for the rest of the job")

    # Files written through the claimed workspace stay private and never follow a link.
    src = td / "rmm.conf"
    src.write_text("server {}\n")
    h._write_workspace_file(ws, "nginx", "rmm.conf", src, me, os.getegid())
    assert (ws / "nginx/rmm.conf").read_text() == "server {}\n"
    assert stat.S_IMODE((ws / "nginx/rmm.conf").stat().st_mode) == 0o600
    (ws / "systemd").rmdir()
    (ws / "systemd").symlink_to(link_target)
    try:
        h._write_workspace_file(ws, "systemd", "rmm.service", src, me, os.getegid())
    except OSError:
        pass
    else:
        raise AssertionError("a linked sub-folder inside the /var/tmp workspace was followed")
    assert not (link_target / "rmm.service").exists()
    ok("writes into the /var/tmp workspace stay 0600 and never follow a linked sub-folder")

    # The sudo shim derives the /var/tmp workspace from backup.sh's own argument shapes.
    assert shim.workspace_from_output(f"{ws}/certs/etc-letsencrypt.tar.gz", "etc-letsencrypt.tar.gz") == str(ws)
    assert str(pathlib.Path(f"{ws}/nginx/").parent) == str(ws)
    ok("the sudo shim maps v35 /var/tmp output paths to the workspace")

    if me == 0:
        foreign = var_tmp / ("tacticalrmm-" + "F" * 21)
        foreign.mkdir(mode=0o700)
        os.chown(foreign, 54321, 54321)
        b2 = dict(binding, claimed=None)
        h.atomic_json(binding_path, b2, mode=0o600)
        expect_exit(h._validate_tactical_workspace, cfg, JOB, str(foreign), contains="not owned by the Tactical service user")
        h.atomic_json(binding_path, dict(binding, claimed=NAME_A), mode=0o600)
        ok("a folder owned by another account is refused")
    else:
        print("[TEST] NOTE wrong-owner case skipped: needs root for chown")

    # Cleanup removes only the claimed folder; pre-existing and unclaimed folders stay.
    log = Log()
    h._cleanup_var_tmp_workspace(cfg, JOB, log)
    assert not ws.exists() and old.exists() and other.exists() and link_target.exists()
    assert any("removed backup.sh work folder" in line for line in log.lines)
    h.atomic_json(binding_path, dict(binding, claimed=None), mode=0o600)
    log = Log()
    h._cleanup_var_tmp_workspace(cfg, JOB, log)
    assert other.exists() and any("left in place" in line for line in log.lines)
    ok("cleanup removes only the claimed folder and logs unclaimed ones")

    # v34 staging mode keeps the 1.5.2 behaviour and refuses /var/tmp.
    stage_parent = state / "staging" / f"tactical-native-{JOB}"
    stage_parent.mkdir()
    stage_ws = stage_parent / ("tacticalrmm-" + "S" * 21)
    stage_ws.mkdir(mode=0o700)
    h.atomic_json(binding_path, {"job_id": JOB, "backup_script_version": "34", "mode": "staging", "preexisting": [], "claimed": None}, mode=0o600)
    assert h._validate_tactical_workspace(cfg, JOB, str(stage_ws)) == stage_ws
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(other), contains="outside the active job staging root")
    ok("v34 staging workspace still accepted; /var/tmp refused in v34 mode")
    h.atomic_json(binding_path, {"job_id": "00000000-0000-4000-8000-000000000000", "mode": "var-tmp", "preexisting": []}, mode=0o600)
    expect_exit(h._validate_tactical_workspace, cfg, JOB, str(other), contains="binding is invalid")
    ok("a binding for another job is refused")

    # ------------------------------------------------------------ restore profiles
    assert set(h.TACTICAL_RESTORE_PROFILES) == {"67", "68"}
    assert h.TACTICAL_RESTORE_PROFILES["67"]["debian"] == ("11", "12") and h.TACTICAL_RESTORE_PROFILES["67"]["ubuntu"] == ("22.04",)
    assert h.TACTICAL_RESTORE_PROFILES["68"]["debian"] == ("13",) and h.TACTICAL_RESTORE_PROFILES["68"]["ubuntu"] == ("26.04",)
    for version, rel in (("67", "reference/tacticalrmm/restore.sh"), ("68", "reference-1.6.1/tacticalrmm/restore.sh")):
        upstream = PROJECT / rel
        if upstream.is_file():
            text = upstream.read_text(encoding="utf-8").replace("\r\n", "\n")
            assert f'SCRIPT_VERSION="{version}"' in text
            assert text.count(h.TACTICAL_RESTORE_PROFILES[version]["os_gate"]) == 1, f"v{version} gate drifted from {rel}"
            ok(f"restore.sh v{version} OS gate matches the upstream reference exactly")
        else:
            print(f"[TEST] NOTE {rel} not present; v{version} gate checked against the inline baseline only")

    def script(version):
        return (f'#!/usr/bin/env bash\nSCRIPT_VERSION="{version}"\nosname=$(lsb_release -si)\ncodename=$(lsb_release -sc)\n'
                + h.TACTICAL_RESTORE_PROFILES.get(version, h.TACTICAL_RESTORE_PROFILES["68"])["os_gate"] + 'echo "$osname $codename"\n')

    rlog = Log()
    for version in ("67", "68"):
        src = td / f"restore-{version}.sh"
        src.write_text(script(version))
        copy = td / f"copy-{version}.sh"
        assert h._prepare_tactical_restore_script(src, copy, os_override_audit_id=None, log=rlog) == {"adjusted": False, "baseline": None, "audit_id": None}
        assert copy.read_bytes() == src.read_bytes()
        patched = td / f"patched-{version}.sh"
        res = h._prepare_tactical_restore_script(src, patched, os_override_audit_id="audit-110", log=rlog)
        assert res == {"adjusted": True, "baseline": version, "audit_id": "audit-110"}, res
        body = patched.read_text()
        assert h.TACTICAL_RESTORE_PROFILES[version]["os_gate"] not in body
        assert "osname=$(lsb_release -si)" in body and "codename=$(lsb_release -sc)" in body
    ok("restore.sh v67 and v68: exact copy without override, only the OS gate removed with one")

    mixed = td / "restore-68-with-67-gate.sh"
    mixed.write_text(script("67").replace('SCRIPT_VERSION="67"', 'SCRIPT_VERSION="68"'))
    try:
        h._prepare_tactical_restore_script(mixed, td / "bad.sh", os_override_audit_id="audit-110", log=rlog)
    except RuntimeError as exc:
        assert "v68 OS-support gate did not match" in str(exc)
    else:
        raise AssertionError("v68 with a v67 gate was patched")
    v69 = td / "restore-69.sh"
    v69.write_text(script("68").replace('SCRIPT_VERSION="68"', 'SCRIPT_VERSION="69"'))
    for audit in (None, "audit-110"):
        try:
            h._prepare_tactical_restore_script(v69, td / "bad69.sh", os_override_audit_id=audit, log=rlog)
        except RuntimeError as exc:
            assert "v69" in str(exc) and "v67 (Tactical 1.5.2) or v68 (Tactical 1.6.1)" in str(exc), str(exc)
        else:
            raise AssertionError(f"restore.sh v69 was accepted (override={audit})")
        assert not (td / "bad69.sh").exists()
    ok("a gate that does not match its version, and restore.sh v69, are refused with or without an override")

    # Preflight: target.restore_script and target.os follow the installed restore.sh.
    h._mutation_active = lambda _cfg: False
    h._preflight_host_snapshot_bytes = lambda *_a, **_k: 0
    h._preflight_database_snapshot_bytes = lambda *_a, **_k: 0

    def preflight(version, os_id, ver):
        (tactical_root / "restore.sh").write_text(script(version) if version != "69" else script("68").replace('"68"', '"69"'))
        h._os_release = lambda: {"ID": os_id, "VERSION_ID": ver}
        report = {"sections": {k: {"status": "pending", "checks": []} for k in ("source", "bundle", "tactical", "tec_tac", "target")}, "warnings": [], "errors": []}
        h.validate_target_preflight(cfg, report, "tactical", 0)
        checks = {c["id"]: c for c in report["sections"]["target"]["checks"]}
        return checks

    cases = [
        ("67", "debian", "12", "passed", "passed"),
        ("67", "ubuntu", "22.04", "passed", "passed"),
        ("67", "debian", "13", "passed", "failed"),
        ("68", "debian", "13", "passed", "passed"),
        ("68", "ubuntu", "26.04", "passed", "passed"),
        ("68", "debian", "12", "passed", "failed"),
        ("68", "ubuntu", "22.04", "passed", "failed"),
        ("69", "debian", "13", "failed", "failed"),
    ]
    for version, os_id, ver, want_script, want_os in cases:
        checks = preflight(version, os_id, ver)
        assert checks["target.restore_script"]["status"] == want_script, (version, checks["target.restore_script"])
        assert checks["target.os"]["status"] == want_os, (version, os_id, ver, checks["target.os"])
    assert "target.restore_script" not in h.OVERRIDEABLE_RESTORE_CHECKS and h.OVERRIDEABLE_RESTORE_CHECKS == {"target.os"}
    ok("preflight: OS support follows restore.sh v67/v68; an unchecked restore.sh fails a check no override can accept")

helper_src = (ROOT / "scripts/server-backup-helper.py").read_text(encoding="utf-8")
assert '"compatibility_baseline": {"tactical_backup_script": "34, 35", "tactical_restore_script": "67, 68"}' in helper_src
assert "TACTICAL_RESTORE_OVERRIDE_BASELINE" not in helper_src
ok("compatibility baseline reports both Tactical versions")

for name in results:
    print(f"[TEST] PASS {name}")
print(f"[TEST] PASS Tactical 1.5.2 and 1.6.1 compatibility {VERSION}")
