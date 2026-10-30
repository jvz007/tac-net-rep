#!/usr/bin/env python3
"""1.17.96: every install.sh verification step runs through run_verify_step with a 120 s limit and a clear failure log.

dev02, 30 October 2026: the contract-catalog check takes 46.1 s and the old 'timeout 45s' stopped the install. Checked: no 'timeout 45s'
is left; the 13 manage.py shell steps (12 fatal, the saved views repair non-fatal) all go through run_verify_step with one constant
VERIFY_STEP_TIMEOUT_SECONDS=120 and keep their messages; the helper's VERIFY_TIMEOUT_SECONDS is 120 and INSTALL_TIMEOUT_SECONDS is
unchanged. The real function is cut out of install.sh and run under bash with a stub runner: a slow step (limit lowered to 1 s) logs
the label, elapsed seconds, 'timed out after' and the last lines and exits 79 after the old ERROR line; a failing step logs its last 20
lines and its exit status; passwords, tokens, keys, authorization text and URI passwords are masked; a passing step logs nothing
extra; the warn mode (saved views repair) returns instead of exiting. The real 120 s timeout run needs the dev server and is not run here.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
HELPER = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


# (1) static: constants, no 45 s, 13 steps through the function, messages kept --------------------------------------------------------
must("timeout 45s" not in INSTALL, "a 'timeout 45s' is left in install.sh")
must(len(re.findall(r"^VERIFY_STEP_TIMEOUT_SECONDS=120$", INSTALL, re.MULTILINE)) == 1, "one constant, 120")
must(len(re.findall(r"shell -c ", INSTALL)) == 1, "the manage.py shell command exists once, inside run_verify_step")
steps = re.findall(r'run_verify_step "([^"]+)" "\$\{(VERIFY_\w+_CODE)\}"(?: (fatal|warn))?(?: "(\w+)")?', INSTALL)
must(len(steps) == 13, steps)
codes = re.findall(r"^(VERIFY_\w+_CODE)=", INSTALL, re.MULTILINE)
must(sorted(c for _, c, _, _ in steps) == sorted(codes), "every VERIFY_*_CODE has a step")
must(sum(1 for _, _, mode, _ in steps if mode == "warn") == 1 and any(label == "Saved views repair" and mode == "warn" for label, _, mode, _ in steps), steps)
wanted_messages = {
    "Framework model/RBAC": "Framework model/RBAC verification failed or timed out.",
    "Framework API route": "Framework API route verification failed or timed out.",
    "Tec-Tac developer contract catalog": "Tec-Tac developer contract catalog verification failed or timed out.",
    "Tec-Tac Tactical Report Manager bridge": "Tec-Tac Tactical Report Manager bridge verification failed or timed out.",
    "Tec-Tac scheduler/capability Celery task": "Tec-Tac scheduler/capability Celery task registration failed or timed out.",
    "Tec-Tac capability registry": "Tec-Tac capability registry verification failed or timed out.",
    "Tec-Tac session-security capability": "Tec-Tac session-security capability verification failed or timed out.",
    "Tec-Tac Core Resource Directory capability": "Tec-Tac Core Resource Directory capability verification failed or timed out.",
    "Core server-backup capability": "Core server-backup capability verification failed or timed out.",
    "Core server-maintenance capability": "Core server-maintenance capability verification failed or timed out.",
    "Core Tactical operations capability": "Core Tactical operations capability verification failed or timed out.",
    "Core Tactical websocket ticket capability": "Core Tactical websocket ticket capability verification failed or timed out.",
}
for label, _code, mode, noun in steps:
    if mode == "warn":
        continue
    message = f"{label} {noun or 'verification'} failed or timed out."
    must(wanted_messages.get(label) == message, (label, message))
must("WARNING: The saved views repair step failed or timed out; installation will continue." in INSTALL, "the repair step stays non-fatal")
must("INSTALL_TIMEOUT_SECONDS = 1800" in HELPER and "VERIFY_TIMEOUT_SECONDS = 120" in HELPER, "helper limits")
must("INSTALL_VERIFY_FAILED_EXIT=79" in INSTALL, "exit 79 defined")
print("       install.sh: no 'timeout 45s', 13 steps through run_verify_step (12 fatal, saved views repair warn), 120 s, helper 120 s")

# (2) run the real function under bash --------------------------------------------------------------------------------------------------
start = INSTALL.index("VERIFY_STEP_TIMEOUT_SECONDS=120")
end = INSTALL.index('log "Verifying framework models and RBAC."')
function_text = INSTALL[start:end]
bash = shutil.which("bash")
if bash is None:
    print("[TEST] PASS installer verify timeout 1.17.96 (static checks only: no bash on this machine)")
    raise SystemExit(0)

work = Path(tempfile.mkdtemp(prefix="installer-verify-"))
(work / "fn.sh").write_text(function_text, encoding="utf-8", newline="\n")
(work / "fakepy").write_text('#!/bin/bash\neval "${FAKE_CMD}"\n', encoding="utf-8", newline="\n")
os.chmod(work / "fakepy", 0o755)
(work / "driver.sh").write_text(
    """set -uo pipefail
fail() { printf '[TEC-TAC] ERROR: %s\\n' "$*" >&2; exit 1; }
log() { printf '[TEC-TAC] %s\\n' "$*"; }
run_as_tactical() { "$@"; }
BACKEND_DIR="$PWD"; VENV_PYTHON="$PWD/fakepy"; MANAGE_PY=manage.py
source ./fn.sh
VERIFY_STEP_TIMEOUT_SECONDS="${LIMIT:-120}"
case "${MODE:-fatal}" in
  fatal) run_verify_step "Tec-Tac developer contract catalog" "print('x')"; echo "AFTER-FATAL" ;;
  warn) if ! run_verify_step "Saved views repair" "print('x')" warn; then echo "AFTER-WARN"; fi ;;
esac
""", encoding="utf-8", newline="\n")


def run(fake_cmd, *, limit=120, mode="fatal"):
    env = dict(os.environ, FAKE_CMD=fake_cmd, LIMIT=str(limit), MODE=mode, CHERE_INVOKING="1")
    done = subprocess.run([bash, "driver.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=60, check=False)
    return done.returncode, done.stdout, done.stderr


# passing step: nothing extra
rc, out, err = run("echo hello-from-step")
must(rc == 0 and "hello-from-step" in out and "AFTER-FATAL" in out, (rc, out, err))
must("VERIFY STEP FAILED" not in out + err and "VERIFY-FAILED" not in err, (out, err))
print("       passing step: exit 0, output kept, nothing extra logged")

# slow step, limit lowered to 1 s: label, elapsed, 124 reported as a time out, last lines, exit 79 after the old ERROR text
rc, out, err = run("echo before-the-wait; sleep 6; echo never", limit=1)
must(rc == 79, (rc, out, err))
must("VERIFY STEP FAILED: Tec-Tac developer contract catalog (timed out after 1 s;" in out, out)
must(re.search(r"\(timed out after 1 s; [1-9]\d* s elapsed\)", out), out)
must("AFTER-FATAL" not in out and "Last 20 lines of the Tec-Tac developer contract catalog output" in out, out)  # a slow login shell may not reach the echo in 1 s
must("[TEC-TAC] ERROR: Tec-Tac developer contract catalog verification failed or timed out." in err, err)
must("[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying Tec-Tac developer contract catalog" in err, err)
print("       slow step (limit 1 s): label, elapsed seconds, 'timed out after', last lines, exit 79, old ERROR line and the marker")

# failing step: last 20 lines only, exit status, secrets masked
lines = [f"line {n:02d}" for n in range(1, 8)]
secret_lines = [
    "password=abc123", "DB_PASSWORD: 'hunter two'", "Authorization: Bearer abc.def-ghi", "got Bearer zzTOKENzz now",
    "postgres://tactical:s3cretpw@127.0.0.1:5432/tacticalrmm", "api_key = KEY-12345", '"secret": "top-secret-value"',
    "token=tok_live_999 and more", "SECRET_KEY=abcdefghijkl",
]
all_lines = lines + secret_lines + [f"tail {n:02d}" for n in range(1, 8)]  # 23 lines
script = "; ".join(f"printf '%s\\n' \"{line}\"" for line in all_lines) + "; exit 3"
rc, out, err = run(script)
must(rc == 79, (rc, out, err))
must("exit status 3" in out, out)
shown = out.split("Last 20 lines", 1)[1]
must("line 01" not in shown.split("\n", 1)[1] and "line 02" not in shown.split("\n", 1)[1] and "line 03" not in shown.split("\n", 1)[1], "only the last 20 lines are shown")
must("tail 07" in shown and "line 04" in shown, shown)
for secret in ("abc123", "hunter two", "abc.def-ghi", "zzTOKENzz", "s3cretpw", "KEY-12345", "top-secret-value", "tok_live_999", "abcdefghijkl"):
    must(secret not in shown, f"{secret} was not masked:\n{shown}")
must("password=***" in shown and "postgres://tactical:***@127.0.0.1" in shown and "Authorization: ***" in shown, shown)
print("       failing step: exit status and the last 20 lines logged; passwords, tokens, keys, authorization and URI passwords masked")

# warn mode (saved views repair): returns the status, never exits, never writes the VERIFY-FAILED marker
rc, out, err = run("echo oops; exit 5", mode="warn")
must(rc == 0 and "AFTER-WARN" in out and "VERIFY STEP FAILED: Saved views repair" in out and "VERIFY-FAILED" not in err, (rc, out, err))
print("       warn mode: the step is logged and the install continues")

shutil.rmtree(work, ignore_errors=True)
print("[TEST] PASS installer verify timeout 1.17.96")
