#!/usr/bin/env python3
"""1.17.97 (held Low of the 1.17.96 review): install.sh run_verify_step never logs a step's unmasked output.

Before 1.17.97 the function ran `cat "${out}"` for every step, so a failing step's FULL output (a password, token, bearer header or URI password on
line 1) reached the update log and its log_tail before the masked last 20 lines. Now a passing step prints its output through scrub_verify_output
(its OK line is still shown, masked) and a failing step prints only the masked last 20 lines. Exit codes, the 'VERIFY STEP FAILED' line, the
'ERROR:' line and the VERIFY-FAILED marker are unchanged (the update helper reads them: tests/system-update-rollback-timeout-only-1.17.97.py).
The real function is cut out of install.sh and run under bash with a stub runner, as tests/installer-verify-timeout-1.17.96.py does."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


# (1) static: no unconditional cat of the step output is left inside run_verify_step
start = INSTALL.index("run_verify_step() {")
body = INSTALL[start: INSTALL.index("\n}\n", start)]
must('cat "${out}"' not in body, "an unmasked cat of the step output is left in run_verify_step")
must('scrub_verify_output < "${out}"' in body, "a passing step is printed through scrub_verify_output")
must(body.count("scrub_verify_output") == 2, "one masked print for a pass, one for the failing tail")
print("       install.sh: run_verify_step has no unmasked cat; a pass prints through scrub_verify_output")

bash = shutil.which("bash")
if bash is None:
    print("[TEST] PASS installer verify masked 1.17.97 (static checks only: no bash on this machine)")
    raise SystemExit(0)

# (2) run the real function under bash
begin = INSTALL.index("VERIFY_STEP_TIMEOUT_SECONDS=120")
finish = INSTALL.index('log "Verifying framework models and RBAC."')
work = Path(tempfile.mkdtemp(prefix="installer-masked-"))
(work / "fn.sh").write_text(INSTALL[begin:finish], encoding="utf-8", newline="\n")
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
run_verify_step "Tec-Tac developer contract catalog" "print('x')"; echo "AFTER-FATAL"
""", encoding="utf-8", newline="\n")


def run(fake_cmd, *, limit=120):
    env = dict(os.environ, FAKE_CMD=fake_cmd, LIMIT=str(limit), CHERE_INVOKING="1")
    done = subprocess.run([bash, "driver.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=60, check=False)
    return done.returncode, done.stdout, done.stderr


SECRETS = ("hunter2pw", "tok_live_abc999", "abc.def-ghi", "s3cretpw", "KEY-12345")
FIRST = "password=hunter2pw token=tok_live_abc999 Authorization: Bearer abc.def-ghi postgres://tactical:s3cretpw@127.0.0.1:5432/db api_key=KEY-12345"


def printer(lines, code):
    return "; ".join(f"printf '%s\\n' \"{line}\"" for line in lines) + f"; exit {code}"


# a failing step: every secret on line 1, then 30 filler lines (so line 1 is NOT in the last 20)
rc, out, err = run(printer([FIRST] + [f"filler {n:02d}" for n in range(1, 31)], 3))
must(rc == 79, (rc, out, err))
for secret in SECRETS:
    must(secret not in out and secret not in err, f"{secret} reached the log:\n{out}\n{err}")
must("filler 30" in out and "filler 11" in out and "filler 10" not in out, "only the last 20 lines are shown")
must("VERIFY STEP FAILED: Tec-Tac developer contract catalog (exit status 3;" in out, out)
must("[TEC-TAC] ERROR: Tec-Tac developer contract catalog verification failed or timed out." in err, err)
must("[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying Tec-Tac developer contract catalog" in err and "AFTER-FATAL" not in out, err)
print("       failing step (secrets on line 1, 30 filler lines): no secret anywhere, only the masked tail, exit 79 and the messages unchanged")

# a failing step with the secrets INSIDE the last 20 lines: shown masked
rc, out, err = run(printer(["start"] + [FIRST] + [f"filler {n:02d}" for n in range(1, 6)], 3))
must(rc == 79 and "password=***" in out and "postgres://tactical:***@127.0.0.1" in out, (rc, out))
for secret in SECRETS:
    must(secret not in out and secret not in err, f"{secret} reached the log:\n{out}\n{err}")
print("       failing step with secrets inside the tail: shown masked")

# a timed-out step: the same, and the message the update helper reads is unchanged
rc, out, err = run("echo " + "'password=hunter2pw'" + "; sleep 6", limit=1)
must(rc == 79 and "hunter2pw" not in out + err, (rc, out, err))
must("VERIFY STEP FAILED: Tec-Tac developer contract catalog (timed out after 1 s;" in out, out)
print("       timed-out step: masked, 'timed out after' line unchanged")

# a passing step: its OK line is shown, masked
rc, out, err = run(printer(["TEC-TAC contract catalog OK: version=1.17.97", FIRST], 0))
must(rc == 0 and "AFTER-FATAL" in out and "TEC-TAC contract catalog OK: version=1.17.97" in out, (rc, out, err))
for secret in SECRETS:
    must(secret not in out and secret not in err, f"{secret} reached the log:\n{out}\n{err}")
must("password=***" in out, out)
print("       passing step: the OK line is still shown, secrets masked")

shutil.rmtree(work, ignore_errors=True)
print("[TEST] PASS installer verify masked 1.17.97")
