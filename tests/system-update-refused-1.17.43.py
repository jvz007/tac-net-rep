#!/usr/bin/env python3
"""1.17.43 (system update helper item 3): a refused update does not roll back, reinstall the old component, or log ROLLBACK FAILED.

An installer that returns status 78 (INSTALL_REFUSED_EXIT) refused in its pre-flight before it changed anything. Covered: the
installer is not run a second time; only the source checkout is restored (git, or the backup when there is no git state); the job
ends failed at stage failed-pre-mutation with rollback {performed false, status not-required, reason installer-refused} and the
refusal text in the error; a failed source restore logs SOURCE RESTORE FAILED and still ends as a failed job with a terminal write;
any other non-zero status keeps the full rollback (restore, second install, verify), and a failing rollback still logs ROLLBACK
FAILED; the refusal reason is read from the installer's own marker line, capped and without a trailing full stop. A static check
pins install.sh: refuse() exits 78, is used only for the two pre-flight checks before the first mutation, and every later failure
keeps fail() and exit 1.

scripts/system-update-helper.py imports fcntl and pwd and reads the trusted bash at import, so it cannot load on the Windows PC. The
real run_job and its helpers are read with ast and run with stubs (the method of tests/online-catalog-availability-1.17.41.py).
Nothing is installed and nothing touches /opt, /var or the network.
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


NAMES = {"INSTALL_REFUSED_EXIT", "INSTALLER_REFUSAL_MARKER", "_UpdateRefused", "_installer_refusal_reason", "run_job"}
EXTRACTED = extract(TREE, NAMES)
must(next(n for n in EXTRACTED if getattr(n, "name", "") == "run_job") is not None, "run_job extracted")

fake_fcntl = types.ModuleType("fcntl")
fake_fcntl.LOCK_EX, fake_fcntl.LOCK_NB = 2, 4
fake_fcntl.flock = lambda fd, op: None


def scenario(*, rcs, git_state, refusal_text=None, restore_git_error=None, restore_backup_error=None):
    """Run the real run_job once with the given installer statuses and return what it wrote and did."""
    tmp = Path(tempfile.mkdtemp(prefix="suh-refused-"))
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
    queue = list(rcs)

    def run_install(component, target_path, log):
        calls["run_install"] += 1
        status = queue.pop(0)
        if status == 78 and refusal_text is not None:
            log.write(f"{MARKER} {refusal_text}\n")
            log.flush()
        return status

    def restore_git(target_path, state):
        calls["restore_git_source"] += 1
        must(state == git_state or not git_state, f"restore got the wrong state: {state}")
        if restore_git_error:
            raise RuntimeError(restore_git_error)

    def restore_bk(backup_path, target_path):
        calls["restore_backup"] += 1
        if restore_backup_error:
            raise RuntimeError(restore_backup_error)

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
        "now": lambda: "2026-10-16T00:00:00+00:00",
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
        "verify_dynamic_plugins": lambda root, inventory: None,
        "run_install": run_install,
        "verify": lambda component, target_path, expected, log: None,
        "verify_source_runtime_layout": verify_layout,
        "restore_git_source": restore_git,
        "restore_backup": restore_bk,
        "running_request_path": lambda _id: tmp / "request.json",
    }
    exec(compile(ast.Module(body=EXTRACTED, type_ignores=[]), str(HELPER), "exec"), ns)  # noqa: S102 - test only
    ns["run_job"](JOB_ID)
    log_text = (logs / f"{JOB_ID}.log").read_text(encoding="utf-8")
    final = [payload for path, payload, _kw in writes if path == job_path][-1]
    final_kwargs = [kw for path, _p, kw in writes if path == job_path][-1]
    return {"calls": calls, "log": log_text, "final": final, "final_kwargs": final_kwargs, "writes": writes, "job_path": job_path,
            "queue_left": queue}


# (1) a refusal: no second installer run, the source checkout is restored, the job says so, no ROLLBACK FAILED
s = scenario(rcs=[78], git_state=GIT_STATE, refusal_text="System Python cryptography support is required.")
must(s["calls"]["run_install"] == 1, f"the installer ran again: {s['calls']}")
must(s["calls"]["restore_git_source"] == 1 and s["calls"]["restore_backup"] == 0, s["calls"])
must("ROLLBACK FAILED" not in s["log"], "a refusal logs ROLLBACK FAILED")
must("[TEC-TAC-UPDATE] update refused by the installer pre-flight; nothing was installed; restoring the source checkout only" in s["log"],
     s["log"])
f = s["final"]
must(f["stage"] == "failed-pre-mutation" and f["status"] == "failed", (f["stage"], f["status"]))
must(f["rollback"] == {"performed": False, "status": "not-required", "reason": "installer-refused"}, f["rollback"])
must(f["error"] == ("The installer refused the update before changing anything: System Python cryptography support is required. "
                    "The installed version is unchanged."), f["error"])
must(f["error_type"] == "InstallerRefused", f["error_type"])
must(s["final_kwargs"].get("gid") == 4242, "the terminal write reuses the captured Tactical gid")
must(s["queue_left"] == [], "no further installer status was used")
print("       refusal (78): installer not re-run, source restored, failed-pre-mutation, not-required, reason in the error, no ROLLBACK FAILED")

# (2) a refusal whose source restore fails: SOURCE RESTORE FAILED, still a failed job with a terminal write
s = scenario(rcs=[78], git_state=GIT_STATE, refusal_text="Tactical frontend env-config.js is missing.", restore_git_error="git reset failed")
must(s["calls"]["run_install"] == 1, s["calls"])
must("SOURCE RESTORE FAILED: git reset failed" in s["log"], s["log"])
must("ROLLBACK FAILED" not in s["log"], "a source restore failure is not logged as ROLLBACK FAILED")
f = s["final"]
must(f["status"] == "failed" and f["stage"] == "rollback-failed", (f["status"], f["stage"]))
must(f["rollback"]["status"] == "failed" and f["rollback"]["reason"] == "installer-refused", f["rollback"])
must(f["error"].endswith("The installed version is unchanged."), f["error"])
must(any(p.get("status") == "failed" for _path, p, _kw in s["writes"] if _path == s["job_path"]), "a terminal write was made")
print("       refusal, source restore fails: SOURCE RESTORE FAILED logged, failed job with a terminal write")

# (3) a refusal with no git state restores the backup, not git
s = scenario(rcs=[78], git_state={}, refusal_text="Layout is wrong.")
must(s["calls"]["restore_backup"] == 1 and s["calls"]["restore_git_source"] == 0, s["calls"])
must(s["calls"]["run_install"] == 1, s["calls"])
must(s["final"]["stage"] == "failed-pre-mutation", s["final"])
print("       refusal without git state: the backup is restored, the installer is not re-run")

# (4) a refusal that gives no reason says so
s = scenario(rcs=[78], git_state=GIT_STATE, refusal_text=None)
must("the installer gave no reason" in s["final"]["error"], s["final"]["error"])
print("       refusal with no marker line: the error says the installer gave no reason")

# (5) any other non-zero status keeps the full rollback: restore, a second install, verify
s = scenario(rcs=[1, 0], git_state=GIT_STATE)
must(s["calls"]["run_install"] == 2, f"the rollback installer did not run: {s['calls']}")
must(s["calls"]["restore_git_source"] == 1 and s["calls"]["verify_source_runtime_layout"] == 1, s["calls"])
must(s["final"]["rollback"]["status"] == "succeeded" and s["final"]["stage"] == "rolled-back", s["final"])
must("ROLLBACK FAILED" not in s["log"], s["log"])
print("       status 1: full rollback (restore, second install, verify) as before")

# (6) a failing rollback still logs ROLLBACK FAILED (the old behaviour is pinned)
s = scenario(rcs=[1, 1], git_state=GIT_STATE)
must("ROLLBACK FAILED" in s["log"], s["log"])
must(s["final"]["stage"] == "rollback-failed" and s["final"]["rollback"]["status"] == "failed", s["final"])
print("       status 1 and a failing rollback: ROLLBACK FAILED still logged")

# (7) the reason is read from the marker line: the last one, capped, no trailing full stop
probe = Path(tempfile.mkdtemp(prefix="suh-reason-")) / "job.log"
probe.write_text("noise\n" + f"{MARKER} first thing.\n" + f"{MARKER} the last thing  is   long.\n", encoding="utf-8")
ns_reason: dict = {"re": re, "os": os, "INSTALLER_REFUSAL_MARKER": MARKER}
exec(compile(ast.Module(body=[n for n in EXTRACTED if getattr(n, "name", "") == "_installer_refusal_reason"], type_ignores=[]),
             str(HELPER), "exec"), ns_reason)  # noqa: S102 - test only
must(ns_reason["_installer_refusal_reason"](probe) == "the last thing is long", ns_reason["_installer_refusal_reason"](probe))
probe.write_text(f"{MARKER} " + "x" * 500 + "\n", encoding="utf-8")
must(len(ns_reason["_installer_refusal_reason"](probe)) == 300, "the reason is capped at 300 characters")
must(ns_reason["_installer_refusal_reason"](probe.with_name("missing.log")) == "the installer gave no reason", "a missing log is handled")
print("       refusal reason: last marker line, whitespace collapsed, trailing full stop removed, capped at 300")

# (8) the constant matches install.sh, and install.sh pins the ordering of refuse() against the first mutation
helper_text = HELPER.read_text(encoding="utf-8")
must("INSTALL_REFUSED_EXIT = 78" in helper_text, "the helper defines status 78")
install = INSTALL_SH.read_text(encoding="utf-8").splitlines()
refuse_def = next(i for i, line in enumerate(install) if line.startswith("refuse() {"))
fail_def = next(i for i, line in enumerate(install) if line.startswith("fail() {"))
must("exit 78" in install[refuse_def] and "exit 1" in install[fail_def], "refuse exits 78, fail exits 1")
refuse_calls = [i for i, line in enumerate(install) if re.match(r'^\s*(\[\[.*\]\]\s*\|\|\s*)?refuse "', line)]
must(len(refuse_calls) == 2, f"refuse is used for exactly the two pre-flight checks: {refuse_calls}")
mutation = re.compile(r"^(mkdir|cp|chown|chmod|install_root_script|rm|mv|ln|run_as_tactical|systemctl|visudo)\b")
first_mutation = next(i for i, line in enumerate(install) if i > refuse_def and mutation.match(line) and "() {" not in line)
must(all(i < first_mutation for i in refuse_calls), f"refuse follows a mutation (first at line {first_mutation + 1})")
must(not any("refuse " in line for line in install[first_mutation:] if not line.lstrip().startswith("#")),
     "refuse is not used after the first mutation")
must(any("fail " in line for line in install[first_mutation:]), "later failures keep fail()")
must(sum(1 for line in install if "exit 78" in line) == 1, "exit 78 only inside refuse()")
print("       install.sh: refuse() exits 78 and is used only for the two pre-flight checks before the first mutation (line "
      f"{first_mutation + 1}); later failures keep fail()")

print("[TEST] PASS system update refused 1.17.43")
