#!/usr/bin/env python3
"""Regression: Core 1.18.42 module helper dispatch starts the root worker as a transient systemd unit, so a Celery restart inside the job no longer
kills it. Django-free and Linux-free: dispatch() is taken from scripts/module-v2-job-helper.py with ast and run with fake claim_job, subprocess,
sys and privileged_env. The real systemd-run runs only on dev02."""
import ast
import re
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "module-v2-job-helper.py"
JOB_ID = "11111111-2222-4333-8444-555555555555"


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


text = HELPER.read_bytes().decode("utf-8")
tree = ast.parse(text)
source = next(ast.get_source_segment(text, n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "dispatch")


class Done(Exception):
    pass


class World:
    def __init__(self, returncode=0, stderr=""):
        self.calls, self.saved, self.cleaned, self.claimed = [], [], [], []
        self.returncode, self.stderr = returncode, stderr
        self.job = {"id": JOB_ID, "status": "dispatched", "stage": "dispatched", "action": "batch_install"}
        ns = {
            "claim_job": lambda job_id: self.claimed.append(job_id),
            "subprocess": types.SimpleNamespace(run=self.run, PIPE=-1, DEVNULL=-3),
            "sys": types.SimpleNamespace(executable="/usr/bin/python3"),
            "Path": Path, "__file__": "/opt/tec-tac/scripts/module-v2-job-helper.py",
            "privileged_env": lambda: {"PATH": "/usr/bin"},
            "load_job": lambda job_id: ("/jobs/x.json", self.job),
            "now": lambda: "2026-11-22T10:00:00+00:00",
            "atomic_json": lambda path, payload, *a, **k: self.saved.append((path, dict(payload), a, k)),
            "tactical_gid": lambda: 995,
            "_cleanup_claimed_job_inputs": lambda job_id: self.cleaned.append(job_id),
        }
        exec(source, ns)  # noqa: S102 - the repo's own source
        self.dispatch = ns["dispatch"]

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return types.SimpleNamespace(returncode=self.returncode, stderr=self.stderr, stdout="")


# the command: systemd-run, --collect, the unit name, Type=exec, then the interpreter, the helper path and --run <job id>
w = World()
w.dispatch(JOB_ID)
must(w.claimed == [JOB_ID] and len(w.calls) == 1, "claim once, start once")
command, kwargs = w.calls[0]
must(command[0] == "systemd-run" and "--collect" in command and "--quiet" in command, command)
must(f"--unit=tec-tac-module-v2-job-{JOB_ID}" in command and "--property=Type=exec" in command, command)
rest = command[command.index("/usr/bin/python3"):]
must(rest[1].endswith("module-v2-job-helper.py") and rest[2:] == ["--run", JOB_ID], rest)
must(all(item.startswith("--") for item in command[1:command.index("/usr/bin/python3")]), "only options sit between systemd-run and the interpreter")
must(kwargs.get("env") == {"PATH": "/usr/bin"} and kwargs.get("text") is True, kwargs)
must(not w.saved and not w.cleaned, "a good start changes nothing in the job file")
must(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", JOB_ID), "the unit name takes a uuid")

# Popen and start_new_session are gone from dispatch
func = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef))
code = " ".join(ast.unparse(statement) for statement in func.body[1:])  # without the docstring
must("Popen" not in code and "start_new_session" not in code, "dispatch no longer uses Popen")
must("except" not in code and "try:" not in code, "no silent fallback")

# a failed systemd-run marks the job failed (stage dispatch, DispatchError) and exits with the message
w = World(returncode=1, stderr="Failed to start transient service unit\n")
try:
    w.dispatch(JOB_ID)
except SystemExit as exc:
    must(str(exc) == "Failed to start transient service unit", str(exc))
else:
    raise AssertionError("dispatch must exit when systemd-run fails")
must(len(w.saved) == 1, w.saved)
path, job, args, kw = w.saved[0]
must(job["status"] == "failed" and job["stage"] == "dispatch" and job["error_type"] == "DispatchError" and job["error"] == "Failed to start transient service unit", job)
must(job["finished_at"] == "2026-11-22T10:00:00+00:00", job)
must(kw.get("uid") == 0 and kw.get("gid") == 995, "the file stays readable by Core, as claim_job wrote it")
must(w.cleaned == [JOB_ID], "the claimed inputs are removed")
w = World(returncode=1, stderr="")
try:
    w.dispatch(JOB_ID)
except SystemExit as exc:
    must("module job worker unit" in str(exc), str(exc))

# source level: the sudoers line and install.sh are unchanged for this item
install = (ROOT / "install.sh").read_bytes().decode("utf-8").replace("\r\n", "\n")
lines = [line for line in install.split("\n") if "MODULE_V2_HELPER" in line and "--dispatch" in line]
must(lines and all("--dispatch *" in line and "--run" not in line for line in lines), lines)
must("systemd-run" in (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8"), "the precedent is still there")
print("module dispatch unit 1.18.42 regression: PASS")
