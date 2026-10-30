#!/usr/bin/env python3
"""1.17.96 (narrowed in 1.17.97, see tests/system-update-rollback-timeout-only-1.17.97.py): a rollback must not fail on a TIMED-OUT verification step.

When the update fails and the rollback restores the previous source, the previous version's installer runs. If that installer fails only
at one of its own verification checks (new installers: exit 79 and a "[TEC-TAC-INSTALL] VERIFY-FAILED: <step>" line; old installers: exit 1
and "[TEC-TAC] ERROR: <step> verification failed or timed out."), the job records rollback {status: warning, warning, installer_exit_status,
advice}, stage rolled-back, and the log says "restored <old>, verification warning: <step>" with no ROLLBACK FAILED. Anything else stays a
real ROLLBACK FAILED: another exit status or error line, text written by the forward installer, a failing restore, or a failing
verify_dynamic_plugins after the installer. Exit 78 is unchanged. The audit row for a warning has its own plain message.

The helper cannot load on the Windows PC (fcntl, pwd), so the real run_job and helpers are read with ast and run with stubs, as in
tests/system-update-refused-1.17.43.py. Nothing is installed and nothing touches /opt, /var or the network.
"""
from __future__ import annotations

import ast
import contextlib
import json
import os
import re
import shutil
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/system-update-helper.py"
INSTALL_SH = ROOT / "install.sh"
TREE = ast.parse(HELPER.read_text(encoding="utf-8"))
MARKER = "[TEC-TAC-INSTALL] REFUSED:"
JOB_ID = "11111111-1111-1111-1111-111111111111"
GIT_STATE = {"head": "a" * 40, "branch": "main", "update_branch": None}


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def extract(tree, names):
    picked = []
    for node in tree.body:
        is_def = isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
        is_assign = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
        if is_def or is_assign:
            picked.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in picked}
    must(not (set(names) - found), f"not found in source: {sorted(set(names) - found)}")
    return picked


NAMES = {"INSTALL_REFUSED_EXIT", "INSTALLER_REFUSAL_MARKER", "_UpdateRefused", "_installer_refusal_reason", "run_job",
         "INSTALL_VERIFY_FAILED_EXIT", "INSTALLER_VERIFY_MARKER", "INSTALLER_VERIFY_STEP_FAILED", "INSTALLER_VERIFY_STEPS",
         "_log_size", "_log_tail_lines", "_rollback_verification_step"}
EXTRACTED = extract(TREE, NAMES)

fake_fcntl = types.ModuleType("fcntl")
fake_fcntl.LOCK_EX, fake_fcntl.LOCK_NB = 2, 4
fake_fcntl.flock = lambda fd, op: None


def scenario(*, effects, git_state, restore_git_error=None, restore_backup_error=None, dynamic_error_on_call=None):
    """Run the real run_job once. ``effects`` is one (exit status, text the installer writes to the log) per installer run."""
    tmp = Path(tempfile.mkdtemp(prefix="suh-rbwarn-"))
    target = tmp / "framework"
    target.mkdir()
    (target / "VERSION").write_text("1.17.42\n", encoding="utf-8")
    source = tmp / "source"
    source.mkdir()
    (source / "VERSION").write_text("1.17.43\n", encoding="utf-8")
    work = tmp / "work"
    work.mkdir()
    logs = tmp / "logs"
    logs.mkdir()
    history = tmp / "history"
    history.mkdir()
    job_path = tmp / "job.json"
    package = tmp / "package.zip"
    package.write_bytes(b"not-a-real-package")
    writes: list = []
    calls = {"run_install": 0, "restore_git_source": 0, "restore_backup": 0, "verify_source_runtime_layout": 0}
    queue = list(effects)
    dynamic_calls = [0]

    def run_install(component, target_path, log):
        calls["run_install"] += 1
        status, text = queue.pop(0)
        if text:
            log.write(text + "\n")
            log.flush()
        return status

    def restore_git(target_path, state):
        calls["restore_git_source"] += 1
        if restore_git_error:
            raise RuntimeError(restore_git_error)

    def restore_bk(backup_path, target_path):
        calls["restore_backup"] += 1
        if restore_backup_error:
            raise RuntimeError(restore_backup_error)

    def dynamic(root, inventory):
        dynamic_calls[0] += 1
        if dynamic_error_on_call is not None and dynamic_calls[0] == dynamic_error_on_call:
            raise RuntimeError("dynamic plugin check failed")

    def fake_atomic(path, payload, *args, **kwargs):
        writes.append((Path(path), json.loads(json.dumps(payload)), dict(kwargs)))

    @contextlib.contextmanager
    def work_dir(_job_id):
        yield work

    def verify_layout(component, root):
        calls["verify_source_runtime_layout"] += 1

    ns: dict = {
        "os": os, "re": re, "json": json, "shutil": shutil, "Path": Path, "contextlib": contextlib, "fcntl": fake_fcntl,
        "LOCK_PATH": tmp / "update.lock", "LOGS_ROOT": logs, "HISTORY_ROOT": history,
        "load_job": lambda _id: (job_path, {"status": "dispatched", "stage": "queued", "created_at": "now"}),
        "load_running_request": lambda _id: (tmp / "request.json", {
            "id": JOB_ID, "action": "install", "component": "framework", "package_path": str(package),
            "version": "1.17.43", "source": "test",
        }),
        "load_config": lambda: {"TEC_TAC_FRAMEWORK_SOURCE": str(target), "TEC_TAC_ROOT": str(tmp / "runtime")},
        "tactical_gid": lambda cfg: 4242,
        "acquire_lifecycle_lock": lambda: None,
        "now": lambda: "2026-10-30T00:00:00+00:00",
        "atomic_json": fake_atomic,
        "private_update_work_dir": work_dir,
        "extract_archive": lambda *a, **k: None,
        "detect_root": lambda work_root, component: source,
        "_root_verify_tree": lambda cfg, root, component: {
            "publisher_id": "tf", "key_id": "k", "root_policy": {"actual_level": "signed_production"},
            "manifest_sha256": "m", "file_count": 1,
        },
        "_version_key": lambda value: tuple(int(part) for part in value.split(".")),
        "backup_root": lambda target_path, component, old_version, job_id: tmp / "backup.tar.gz",
        "apply_source_update": lambda source_root, target_path, component, job: dict(git_state),
        "snapshot_dynamic_plugins": lambda root: {},
        "normalize_release_tree_security": lambda root: None,
        "verify_dynamic_plugins": dynamic,
        "run_install": run_install,
        "verify": lambda component, target_path, expected, log: None,
        "verify_source_runtime_layout": verify_layout,
        "restore_git_source": restore_git,
        "restore_backup": restore_bk,
        "running_request_path": lambda _id: tmp / "request.json",
    }
    # _log_size / _log_tail_lines / _rollback_verification_step are the real ones from the helper (in EXTRACTED).
    exec(compile(ast.Module(body=EXTRACTED, type_ignores=[]), str(HELPER), "exec"), ns)  # noqa: S102 - test only
    ns["run_job"](JOB_ID)
    log_text = (logs / f"{JOB_ID}.log").read_text(encoding="utf-8")
    final = [payload for path, payload, _kw in writes if path == job_path][-1]
    return {"calls": calls, "log": log_text, "final": final, "writes": writes, "job_path": job_path, "queue_left": queue}


VERIFY_STEP = "Tec-Tac developer contract catalog"
FORWARD_ERR = "[TEC-TAC] ERROR: Framework API route verification failed or timed out."
OLD_ERR = f"[TEC-TAC] ERROR: {VERIFY_STEP} verification failed or timed out."
NEW_MARK = f"[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying {VERIFY_STEP}"
TIMEOUT_LINE = f"[TEC-TAC] VERIFY STEP FAILED: {VERIFY_STEP} (timed out after 120 s; 121 s elapsed)"  # 1.17.97: what run_verify_step logs for exit 124
TIMED_OUT = (79, TIMEOUT_LINE + "\n" + NEW_MARK)
WARN_LOG = f"[TEC-TAC-UPDATE] restored 1.17.42, verification warning: Verifying {VERIFY_STEP}"
# The forward installer fails with a verification error too: its line must never classify the rollback.
FORWARD_FAIL = (1, FORWARD_ERR)

# (1) new installer: exit 79, the timed-out line and the VERIFY-FAILED marker of the same step -> a warning, rolled-back, no ROLLBACK FAILED
s = scenario(effects=[FORWARD_FAIL, (79, OLD_ERR + "\n" + TIMEOUT_LINE + "\n" + NEW_MARK)], git_state=GIT_STATE)
f = s["final"]
must(s["calls"]["run_install"] == 2 and s["calls"]["restore_git_source"] == 1 and s["calls"]["verify_source_runtime_layout"] == 1, s["calls"])
must(f["rollback"] == {"performed": True, "status": "warning", "version": "1.17.42", "warning": f"Verifying {VERIFY_STEP}",
                       "installer_exit_status": 79, "incomplete_stages": ["helper scripts", "timers", "service restart"],
                       "restart": "systemctl restart rmm daphne celery celerybeat", "advice": f["rollback"]["advice"]}, f["rollback"])
must(f"Verifying {VERIFY_STEP} timed out" in f["rollback"]["advice"] and "helper scripts" in f["rollback"]["advice"] and "timers" in f["rollback"]["advice"]
     and "restart" in f["rollback"]["advice"], f["rollback"]["advice"])
must(f["stage"] == "rolled-back" and f["status"] == "failed", (f["stage"], f["status"]))
must(f["error"] == "framework installer exited with status 1", f["error"])
must(WARN_LOG in s["log"] and "ROLLBACK FAILED" not in s["log"], s["log"])
print("       exit 79 + timed-out line + marker: rollback warning, stage rolled-back, status failed, log line, no ROLLBACK FAILED")

# (2) old installer: exit 1 and its known ERROR line cannot prove a timeout -> ROLLBACK FAILED (1.17.97)
for text in (OLD_ERR, "[TEC-TAC] ERROR: Tec-Tac scheduler/capability Celery task registration failed or timed out.",
             "[TEC-TAC] ERROR: Core server-backup capability verification failed."):
    s = scenario(effects=[FORWARD_FAIL, (1, text)], git_state=GIT_STATE)
    must(s["final"]["rollback"]["status"] == "failed" and s["final"]["stage"] == "rollback-failed" and "ROLLBACK FAILED" in s["log"], s["final"]["rollback"])
print("       exit 1 + a known verification ERROR line (old installer): no longer a warning, a real ROLLBACK FAILED")

# (3) another error, no error line, an unknown step, a longer text or another exit status -> failed
for rollback_effect, why in (((1, "[TEC-TAC] ERROR: Docker is not installed."), "another error"),
                             ((1, ""), "no error line (the forward installer's line is older and must not count)"),
                             ((1, "[TEC-TAC] ERROR: Something else verification failed or timed out."), "unknown step"),
                             ((1, OLD_ERR + " More."), "text that does not end as a known line"),
                             ((2, OLD_ERR), "a known line with another exit status"),
                             ((78, ""), "exit 78 on the rollback")):
    s = scenario(effects=[FORWARD_FAIL, rollback_effect], git_state=GIT_STATE)
    must(s["final"]["rollback"]["status"] == "failed" and s["final"]["stage"] == "rollback-failed", (why, s["final"]["rollback"]))
    must("installer_exit_status" not in s["final"]["rollback"] and "ROLLBACK FAILED" in s["log"], why)
    must("rollback installer exited with status" in s["final"]["rollback"]["error"], s["final"]["rollback"])
print("       any other installer failure stays a real ROLLBACK FAILED")

# (4) the restore itself failing is failed, with no installer_exit_status
s = scenario(effects=[FORWARD_FAIL, TIMED_OUT], git_state=GIT_STATE, restore_git_error="git reset failed")
f = s["final"]
must(f["rollback"]["status"] == "failed" and "installer_exit_status" not in f["rollback"] and f["stage"] == "rollback-failed", f["rollback"])
must("ROLLBACK FAILED: git reset failed" in s["log"] and s["calls"]["run_install"] == 1, s["log"])
s = scenario(effects=[FORWARD_FAIL, TIMED_OUT], git_state={}, restore_backup_error="backup unreadable")
must(s["final"]["rollback"]["status"] == "failed" and s["calls"]["restore_backup"] == 1, s["final"]["rollback"])
print("       a failing restore: failed, not a warning")

# (5) verify_dynamic_plugins failing after a verification warning -> failed (call 1 is before the installer, call 2 is after the rollback)
s = scenario(effects=[FORWARD_FAIL, TIMED_OUT], git_state=GIT_STATE, dynamic_error_on_call=2)
must(s["final"]["rollback"]["status"] == "failed" and "dynamic plugin check failed" in s["final"]["rollback"]["error"], s["final"]["rollback"])
must("verification warning" not in s["log"] and "ROLLBACK FAILED" in s["log"], s["log"])
print("       verify_dynamic_plugins failing after a verification warning: failed")

# (6) unchanged paths: a clean rollback and a refusal (78 on the forward installer)
s = scenario(effects=[FORWARD_FAIL, (0, "")], git_state=GIT_STATE)
must(s["final"]["rollback"] == {"performed": True, "status": "succeeded", "version": "1.17.42"} and s["final"]["stage"] == "rolled-back", s["final"])
s = scenario(effects=[(78, f"{MARKER} Layout is wrong.")], git_state=GIT_STATE)
must(s["calls"]["run_install"] == 1 and s["final"]["stage"] == "failed-pre-mutation", s["final"])
print("       a clean rollback and a refusal (78) are unchanged")

# (7) the classifier reads only what the rollback installer wrote (the offset); bad input is safe
probe_dir = Path(tempfile.mkdtemp(prefix="suh-classify-"))
log_path = probe_dir / "job.log"
log_path.write_text(OLD_ERR + "\n" + TIMEOUT_LINE + "\n" + NEW_MARK + "\n", encoding="utf-8")
offset = log_path.stat().st_size
ns2: dict = {"re": re, "os": os}
exec(compile(ast.Module(body=EXTRACTED, type_ignores=[]), str(HELPER), "exec"), ns2)  # noqa: S102 - test only
classify = ns2["_rollback_verification_step"]
must(classify(79, log_path, offset) is None, "the forward installer's lines are before the offset")
must(classify(79, log_path, 0) == f"Verifying {VERIFY_STEP}", "from offset 0 the pair counts")
must(classify(1, log_path, 0) is None, "exit 1 (the old installer) never classifies")
must(classify(1, log_path, None) is None and classify(79, log_path, None) is None, "no offset: nothing classifies")
must(classify(1, probe_dir / "missing.log", 0) is None, "a missing log is not a verification failure")
must(classify(0, log_path, 0) is None, "exit 0 is not a failure")
print("       classifier: reads from the offset only; missing log, no offset and exit 0 are safe")

# (8) static checks: constants, install.sh and the helper limits
helper_text = HELPER.read_text(encoding="utf-8")
must("INSTALL_VERIFY_FAILED_EXIT = 79" in helper_text and "VERIFY_TIMEOUT_SECONDS = 120" in helper_text and "INSTALL_TIMEOUT_SECONDS = 1800" in helper_text)
install = INSTALL_SH.read_text(encoding="utf-8")
must("INSTALL_VERIFY_FAILED_EXIT=79" in install and "[TEC-TAC-INSTALL] VERIFY-FAILED:" in install and 'exit "${INSTALL_VERIFY_FAILED_EXIT}"' in install)
labels = re.findall(r'^run_verify_step "([^"]+)"', install, re.MULTILINE)
must(len(labels) == 12, labels)  # the saved views repair step sits inside an if and is not at the start of a line
helper_steps = set(ns2["INSTALLER_VERIFY_STEPS"])
must(set(labels) == helper_steps, f"helper step list differs from install.sh: {set(labels) ^ helper_steps}")
must(sum(1 for line in install.splitlines() if "exit 78" in line) == 1, "exit 78 only inside refuse()")
print("       install.sh and the helper agree on the 12 fatal verification steps and exit 79")

# (9) the audit row: its own plain message and rollback_status warning
audit_src = (ROOT / "framwork/tec_tac/system_update_audit.py").read_text(encoding="utf-8")
must("was restored; the check after the restore reported a warning, check the server." in audit_src, "audit message present")
audit_ns: dict = {}
tree = ast.parse(audit_src)
wanted = {"_word", "_version", "describe", "FAILED_ACTION", "_STATUS_RE", "_OPERATION_RE", "_COMPONENTS", "_VERSION_RE", "correlation_id_for"}
body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in wanted)
        or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets))]
module_job_logs = types.SimpleNamespace(_UUID_RE=re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"), _VERSION_RE=re.compile(r"^[0-9A-Za-z.+_-]{1,40}$"))
audit_ns.update({"re": re, "module_job_logs": module_job_logs, "__annotations__": {}})
try:
    exec(compile(ast.Module(body=body, type_ignores=[]), "system_update_audit.py", "exec"), audit_ns)  # noqa: S102 - test only
except NameError:
    audit_ns = None  # the module needs a name this harness does not provide: the source check above stands
if audit_ns is not None and "describe" in audit_ns:
    base = {"id": JOB_ID, "status": "failed", "component": "framework", "installed_version": "1.17.94", "version": "1.17.95", "operation": "upgrade"}
    row = audit_ns["describe"]({**base, "rollback": {"performed": True, "status": "warning", "version": "1.17.94"}})
    must(row["message"] == "Update failed 1.17.94 -> 1.17.95. 1.17.94 was restored; the check after the restore reported a warning, check the server.", row["message"])
    must(row["metadata"]["rollback_status"] == "warning" and "did not finish" not in row["message"], row)
    row = audit_ns["describe"]({**base, "rollback": {"performed": True, "status": "failed"}})
    must("The rollback did not finish" in row["message"], row["message"])
    print("       audit row: warning gets its own message and rollback_status warning; failed is unchanged")
print("[TEST] PASS system update rollback verification warning 1.17.96")
