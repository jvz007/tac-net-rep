#!/usr/bin/env python3
"""1.18.29 regression (from 1.17.116; 1.18.28 assertions kept, the canary block added): install.sh and uninstall.sh carry the core.sandbox layout (core.sandbox Patch 1, part 4). Static text checks,
like the other installer tests. Not runnable here: a real install (root, systemd, visudo); tests/sandbox-selftest-runtime-1.17.116.sh
does that on dev02.

* the sudoers file has exactly three commands (--start, --stop, --status), no ``*``, and none of --register-module, --unregister-module,
  --selftest, --sweep; it is validated with visudo -cf;
* the helper goes in through install_root_script (the CR strip), never directly, and is symlinked into /usr/local/sbin;
* a failed or not-ready selftest never calls fail() and never exits: it prints the plain warning;
* the slice has a drop-in with MemoryMax and TasksMax, the sweep service runs --sweep as root, the timer runs at boot and daily;
* a VERIFY step for core.sandbox sits with the other capability checks;
* nothing in install.sh grants the publisher permission sandbox.register;
* uninstall.sh removes every new path (the helper's audit log folder is kept on purpose);
* 1.18.29: the install-time canary block (``sandbox_canary_step``) sits after the runtime ownership check and before "Installation complete.", runs
  ``--selftest --canary`` through ``SANDBOX_SELFTEST_PY``, cannot fail the install, has the 900 s bound and the ``1700 - SECONDS`` cap, logs exactly the
  two forms ``Sandbox: active`` and ``Sandbox: not active: ``, adds nothing to sudoers and touches no Tactical service;
* the existing sudoers rules and helper installs are untouched; both scripts are LF only and pass ``bash -n``.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
UNINSTALL = (ROOT / "uninstall.sh").read_text(encoding="utf-8")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def between(text, start, end, *, after=0):
    i = text.index(start, after)
    return text[i:text.index(end, i + len(start))]


# ---- the sudoers file
heredoc = between(INSTALL, 'cat > "${SANDBOX_SUDOERS}" <<EOF', "\nEOF\n")
lines = heredoc.splitlines()[1:]
must(len(lines) == 1, lines)
rule = lines[0]
must(rule == "${TACTICAL_USER} ALL=(root) NOPASSWD: ${SANDBOX_HELPER} --start, ${SANDBOX_HELPER} --stop, ${SANDBOX_HELPER} --status", rule)
must("*" not in heredoc, "no wildcard")
commands = [part.strip() for part in rule.split("NOPASSWD:")[1].split(",")]
must(commands == ["${SANDBOX_HELPER} --start", "${SANDBOX_HELPER} --stop", "${SANDBOX_HELPER} --status"], commands)
for forbidden in ("--register-module", "--unregister-module", "--selftest", "--sweep", "--finish", "ALL ", "NOPASSWD: ALL"):
    must(forbidden not in rule.replace("ALL=(root)", ""), forbidden)
must(re.fullmatch(r"\$\{TACTICAL_USER\} ALL=\(root\) NOPASSWD: [^*]+", rule), "one user, root only")
must('SANDBOX_HELPER="/usr/local/sbin/tec-tac-sandbox"' in INSTALL and 'SANDBOX_SUDOERS="/etc/sudoers.d/tec-tac-sandbox"' in INSTALL, "paths")
after_sudoers = INSTALL[INSTALL.index('cat > "${SANDBOX_SUDOERS}"'):]
must(after_sudoers.index('chown root:root "${SANDBOX_SUDOERS}"') < after_sudoers.index('chmod 0440 "${SANDBOX_SUDOERS}"') < after_sudoers.index('visudo -cf "${SANDBOX_SUDOERS}"'), "owner, mode, then visudo")
must('visudo -cf "${SANDBOX_SUDOERS}" >/dev/null || fail "Sandbox sudoers validation failed."' in INSTALL, "visudo guard")
must('if command -v visudo >/dev/null 2>&1; then\n    visudo -cf "${SANDBOX_SUDOERS}"' in INSTALL, "the guard is the same shape as the others")

# ---- the helper goes in through the CR strip
must('install_root_script "${REPO_ROOT}/scripts/sandbox-helper.py" "${SANDBOX_LIB}/sandbox-helper.py"' in INSTALL, "install_root_script")
must('ln -sfn "${SANDBOX_LIB}/sandbox-helper.py" "${SANDBOX_HELPER}"' in INSTALL and 'chown -h root:root "${SANDBOX_HELPER}"' in INSTALL, "symlink")
must(not re.search(r'install[^\n]*scripts/sandbox-helper\.py', INSTALL.replace('install_root_script "${REPO_ROOT}/scripts/sandbox-helper.py"', "")), "no direct install of the helper")
must(not re.search(r"\bcp\b[^\n]*sandbox-helper", INSTALL), "no cp of the helper")
must('mkdir -p "${SANDBOX_LIB}/runners" "${SANDBOX_LIB}/registry" "${SANDBOX_STATE}"' in INSTALL, "layout")
must('chmod 0755 "${SANDBOX_LIB}" "${SANDBOX_LIB}/runners" "${SANDBOX_LIB}/registry" "${SANDBOX_STATE}"' in INSTALL and 'chown root:root "${SANDBOX_LIB}"' in INSTALL, "root 0755")
must('SANDBOX_LIB="/usr/local/lib/tec-tac/sandbox"' in INSTALL and 'SANDBOX_STATE="/var/lib/tec-tac/sandbox"' in INSTALL, "plan paths")
must(INSTALL.index("Installed durable Core server-maintenance helper") < INSTALL.index("SANDBOX_HELPER=") < INSTALL.index("SCHEDULER_SERVICE="), "the block sits after the server-maintenance helper and before the scheduler timer")

# ---- the selftest never fails the install
selftest_block = between(INSTALL, 'if timeout "${SANDBOX_SELFTEST_TIMEOUT_SECONDS}s" /usr/bin/python3 -I "${SANDBOX_LIB}/sandbox-selftest.py" --selftest', "\nfi\n")
must("fail " not in selftest_block and "exit " not in selftest_block and "refuse " not in selftest_block and "verify_fail" not in selftest_block, selftest_block)
must('log "WARNING: Sandbox is off: ${SANDBOX_OFF_REASON}. ai ChatGPT stays off."' in selftest_block, "the plain warning")
must("else" in selftest_block and "|| true" in selftest_block, "an else branch and a reason lookup that cannot fail")
must(selftest_block.lstrip().startswith("if timeout"), "inside an if, so a non-zero status is a branch and not an exit")
must("--selftest" in INSTALL and INSTALL.count('"${SANDBOX_LIB}/sandbox-selftest.py" --selftest') == 1, "the selftest is run once")
must(INSTALL.index('"${SANDBOX_LIB}/sandbox-selftest.py" --selftest') > INSTALL.index('systemctl enable --now tec-tac-sandbox-sweep.timer'), "the selftest runs after the layout and timer")

# ---- slice, sweep service and timer
must('MemoryMax=' in INSTALL and 'TasksMax=' in INSTALL and "${SANDBOX_SLICE_DROPIN_DIR}/limits.conf" in INSTALL, "slice drop-in")
drop = between(INSTALL, 'cat > "${SANDBOX_SLICE_DROPIN_DIR}/limits.conf" <<EOF', "\nEOF\n")
must("[Slice]" in drop and "MemoryMax=6G" in drop and "TasksMax=2048" in drop and "MemorySwapMax=0" in drop, drop)
must('cat > "${SANDBOX_SLICE}" <<EOF' in INSTALL, "slice unit")
service = between(INSTALL, 'cat > "${SANDBOX_SWEEP_SERVICE}" <<EOF', "\nEOF\n")
must("Type=oneshot" in service and "User=root" in service and "ExecStart=${SANDBOX_HELPER} --sweep" in service, service)
timer = between(INSTALL, 'cat > "${SANDBOX_SWEEP_TIMER}" <<EOF', "\nEOF\n")
must("OnBootSec=" in timer and "OnCalendar=daily" in timer and "Persistent=true" in timer and "Unit=tec-tac-sandbox-sweep.service" in timer and "WantedBy=timers.target" in timer, timer)
must('systemctl enable --now tec-tac-sandbox-sweep.timer' in INSTALL, "timer enabled")
must(INSTALL.index('systemctl daemon-reload', INSTALL.index('SANDBOX_SWEEP_TIMER}"')) < INSTALL.index('systemctl enable --now tec-tac-sandbox-sweep.timer'), "daemon-reload first")

# ---- the VERIFY step
verify = between(INSTALL, "VERIFY_SANDBOX_CODE=", '"\nrun_verify_step "Core sandbox capability"')
must("capability_status('core.sandbox'" in verify and "p.status()" in verify and "p.start()" in verify and "not_owner" in verify and "sandbox_disabled" in verify and "SANDBOX_ENABLED" in verify, verify)  # 1.18.27
must('run_verify_step "Core sandbox capability" "${VERIFY_SANDBOX_CODE}"' in INSTALL, "run_verify_step")
must(INSTALL.index('run_verify_step "Core Tactical websocket ticket capability"') < INSTALL.index('run_verify_step "Core sandbox capability"') < INSTALL.index("SCHEDULER_SERVICE="), "beside the other capability checks")
compile(verify.split('VERIFY_SANDBOX_CODE="')[1], "verify", "exec")  # the Python is valid (bash keeps a backslash-n in double quotes as it is)

# ---- nothing grants sandbox.register
for text in (INSTALL, UNINSTALL):
    for line in text.splitlines():
        if "sandbox.register" in line:
            must(line.lstrip().startswith("#"), "only a comment may name it: " + line)
must('"permissions"' not in between(INSTALL, 'SANDBOX_HELPER="/usr/local/sbin/tec-tac-sandbox"', "SCHEDULER_SERVICE="), "no publisher policy is written in the sandbox block")

# ---- uninstall removes every new path
for name in ("SANDBOX_SUDOERS", "SANDBOX_HELPER", "SANDBOX_SWEEP_TIMER", "SANDBOX_SWEEP_SERVICE", "SANDBOX_SLICE"):
    must(re.search(r'^rm -f [^\n]*"\$\{' + name + r'\}"', UNINSTALL, re.MULTILINE), name)
for name in ("SANDBOX_LIB", "SANDBOX_SLICE_DROPIN_DIR", "SANDBOX_RUN"):
    must(re.search(r'^rm -rf [^\n]*"\$\{' + name + r'\}"', UNINSTALL, re.MULTILINE), name)
for paths, folder in (
    (('"/usr/local/sbin/tec-tac-sandbox"', '"/usr/local/lib/tec-tac/sandbox"', '"/etc/sudoers.d/tec-tac-sandbox"', '"/etc/systemd/system/tec-tac-sandbox.slice"',
      '"/etc/systemd/system/tec-tac-sandbox.slice.d"', '"/etc/systemd/system/tec-tac-sandbox-sweep.service"', '"/etc/systemd/system/tec-tac-sandbox-sweep.timer"', '"/run/tec-tac/sandbox"'), UNINSTALL),
):
    for path in paths:
        must(path in folder, path)
must('systemctl disable --now tec-tac-sandbox-sweep.timer' in UNINSTALL and UNINSTALL.index("tec-tac-sandbox-sweep.timer") < UNINSTALL.index('rm -f "${SANDBOX_SUDOERS}"'), "the timer is stopped first")
must(UNINSTALL.index('rm -rf "${SANDBOX_LIB}"') < UNINSTALL.index("systemctl daemon-reload", UNINSTALL.index('rm -rf "${SANDBOX_LIB}"')), "daemon-reload after the removal")
must('rm -rf "${SANDBOX_STATE}"' not in UNINSTALL and "/var/lib/tec-tac/sandbox" in UNINSTALL, "the helper's audit log folder is kept, and the comment says so")
# every path the installer creates appears in the uninstaller (except the kept state folder)
for path in ("/usr/local/sbin/tec-tac-sandbox", "/usr/local/lib/tec-tac/sandbox", "/etc/sudoers.d/tec-tac-sandbox", "/etc/systemd/system/tec-tac-sandbox.slice",
             "/etc/systemd/system/tec-tac-sandbox.slice.d", "/etc/systemd/system/tec-tac-sandbox-sweep.service", "/etc/systemd/system/tec-tac-sandbox-sweep.timer"):
    must(path in INSTALL and path in UNINSTALL, path)

# ---- existing rules and helper installs are untouched
for line in (
    '${TACTICAL_USER} ALL=(root) NOPASSWD: ${SERVER_MAINTENANCE_HELPER} --dispatch *, ${SERVER_MAINTENANCE_HELPER} --cancel *, ${SERVER_MAINTENANCE_HELPER} --signal *',
    '${TACTICAL_USER} ALL=(root) NOPASSWD: ${SERVER_BACKUP_HELPER} --dispatch *',
    'install_root_script "${REPO_ROOT}/scripts/server-maintenance-helper.py" "${SERVER_MAINTENANCE_LIB}/server-maintenance-helper.py"',
    'install_root_script "${REPO_ROOT}/scripts/module-job-helper.py" "${MODULE_HELPER}"',
):
    must(line in INSTALL, line)
must("sandbox" not in between(INSTALL, 'cat > "${SERVER_MAINTENANCE_SUDOERS}"', "\nEOF\n"), "the server-maintenance sudoers file is unchanged")

# ---- 1.17.118: the launcher and the canary program go in root-owned through the CR strip, and the sudo rule did not change
must('install_root_script "${REPO_ROOT}/scripts/sandbox-launcher.py" "${SANDBOX_LIB}/sandbox-launcher.py"' in INSTALL, "launcher via install_root_script")
must('install_root_script "${REPO_ROOT}/scripts/sandbox-canary-runner.py" "${SANDBOX_LIB}/canary/sandbox-canary-runner.py"' in INSTALL, "canary runner via install_root_script")
must('mkdir -p "${SANDBOX_LIB}/canary"' in INSTALL and 'chown root:root "${SANDBOX_LIB}/canary"' in INSTALL and 'chmod 0755 "${SANDBOX_LIB}/canary"' in INSTALL, "canary folder root 0755")
helper_at = INSTALL.index('"${SANDBOX_LIB}/sandbox-helper.py"')
launcher_at = INSTALL.index('"${SANDBOX_LIB}/sandbox-launcher.py"')
must(helper_at < launcher_at < INSTALL.index('cat > "${SANDBOX_SUDOERS}"'), "after the helper, before the sudoers file")
must(not re.search(r"\bcp\b[^\n]*sandbox-(launcher|canary)", INSTALL), "no cp of the new programs")
direct = INSTALL.replace('install_root_script "${REPO_ROOT}/scripts/sandbox-launcher.py"', "").replace('install_root_script "${REPO_ROOT}/scripts/sandbox-canary-runner.py"', "")
must(not re.search(r"install[^\n]*scripts/sandbox-(launcher|canary-runner)\.py", direct), "no direct install of the new programs")
must("--canary" not in rule and "--finish" not in rule and "--canary-launch" not in rule, "the root-only modes are not in the sudo rule")
for name in ("scripts/sandbox-launcher.py", "scripts/sandbox-canary-runner.py", "tests/sandbox-canary-1.17.118.sh"):
    must(b"\r" not in (ROOT / name).read_bytes(), f"{name} has a carriage return")
must("/usr/local/lib/tec-tac/sandbox" in INSTALL and 'rm -rf "${SANDBOX_LIB}"' in UNINSTALL, "uninstall removes the lib folder, which holds the new programs")
# every new install path sits under an existing SANDBOX_* literal, so the 1.17.116 review lesson (the rollback list) needs no new entry
literals = set(re.findall(r'^(SANDBOX_[A-Z_]+)="', INSTALL, re.MULTILINE))
# 1.18.8 (updated in place): SANDBOX_ROOT_DIR is the allow-list root, "${SANDBOX_LIB}/root", so the uninstall of the lib folder removes it too
# 1.18.24 (updated in place): the two egress template units are written under /etc/systemd/system like the slice and the sweep units, and uninstall.sh removes them
must(literals == {"SANDBOX_HELPER", "SANDBOX_LIB", "SANDBOX_STATE", "SANDBOX_SUDOERS", "SANDBOX_SLICE", "SANDBOX_SLICE_DROPIN_DIR", "SANDBOX_SWEEP_SERVICE", "SANDBOX_SWEEP_TIMER",
                   "SANDBOX_ROOT_DIR", "SANDBOX_EGRESS_SOCKET", "SANDBOX_EGRESS_SERVICE", "SANDBOX_SELFTEST_PY"}, literals)  # 1.18.29: the canary block names the selftest file once
must("tec-tac-sandbox-egress@.socket" in UNINSTALL and "tec-tac-sandbox-egress@.service" in UNINSTALL, "uninstall removes the egress units")
must('SANDBOX_ROOT_DIR="${SANDBOX_LIB}/root"' in INSTALL, "the root sits inside the lib folder")

# ---- 1.18.29: the install-time canary block
begin, end = "# --- sandbox canary begin (1.18.29) ---\n", "# --- sandbox canary end ---\n"
must(INSTALL.count(begin) == 1 and INSTALL.count(end) == 1, "one canary block")
canary = INSTALL[INSTALL.index(begin):INSTALL.index(end) + len(end)]
must(INSTALL.index('runtime_ownership_rule verify || fail') < INSTALL.index(begin) < INSTALL.index(end) < INSTALL.index('log "Installation complete."'), "after the ownership check, before the completion lines")
must(INSTALL.index('systemctl restart rmm daphne celery celerybeat') < INSTALL.index(begin), "after the services restarted")
tail = INSTALL[INSTALL.index(end) + len(end):]
must(tail.count("trap - EXIT") == 1 and tail.rstrip().endswith("exit 0") and 'rm -f "${TMP_SETTINGS}" || true' in tail, "the final clean-up and exit 0 stay last")
must('SANDBOX_SELFTEST_PY="${SANDBOX_LIB}/sandbox-selftest.py"' in canary, "the variable")
must('timeout "${budget}s" /usr/bin/python3 -I "${SANDBOX_SELFTEST_PY}" --selftest --canary' in canary, "the canary runs through the variable with the same command as the script's step 4")
must(INSTALL.count('"${SANDBOX_LIB}/sandbox-selftest.py" --selftest') == 1, "the literal selftest call count stays 1")
must("sandbox-selftest.py" not in canary.replace('SANDBOX_SELFTEST_PY="${SANDBOX_LIB}/sandbox-selftest.py"', ""), "the file is named once, in the variable")
must("SANDBOX_CANARY_TIMEOUT_SECONDS=900" in canary and "SANDBOX_CANARY_INSTALL_BUDGET_SECONDS=1700" in canary and "SANDBOX_CANARY_INSTALL_BUDGET_SECONDS - SECONDS" in canary, "900 s bound and the 1700 - SECONDS cap")
must("SANDBOX_CANARY_MIN_SECONDS=120" in canary and "not enough install time left to run the canary" in canary, "the 120 s floor and its reason")
must(canary.rstrip().splitlines()[-2].strip() == "sandbox_canary_step || true", "the call cannot fail the install")
body = between(canary, "sandbox_canary_step() {", "\n}\n")
must(not re.search(r"\bfail\b|\bexit\b|return 1", body), "no fail, exit or return 1 in the step")
must("the canary did not finish in" in body and "the canary failed: " in body, "the reasons")
logs = re.findall(r'log "(Sandbox:[^"]*)"', canary)
must(logs and all(item == "Sandbox: active" or item.startswith("Sandbox: not active: ") for item in logs), logs)
must(logs.count("Sandbox: active") == 1, "one success line")
# every command that can fail in the step is guarded by ||, a condition or a here-string read with || true
for line in body.splitlines():
    stripped = line.strip()
    if stripped.startswith(("timeout ", "rm ", "read ", "line=")):
        must("||" in stripped, "unguarded command in the canary step: " + stripped)
code_only = "\n".join(line for line in canary.splitlines() if not line.lstrip().startswith("#"))
for word in ("chmod", "chown", "sudoers", "visudo", "systemctl", "nginx", "daphne", "celery", "rmm"):
    must(word not in code_only, word + " is named in the canary block code")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh keeps LF")

# ---- line endings and syntax
for name in ("install.sh", "uninstall.sh", "scripts/sandbox-helper.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), f"{name} has a carriage return")
bash = shutil.which("bash")
if bash:
    for name in ("install.sh", "uninstall.sh"):
        result = subprocess.run([bash, "-n", str(ROOT / name)], capture_output=True, text=True, check=False)
        must(result.returncode == 0, f"bash -n {name}: {result.stderr}")
else:
    print("       bash not found: bash -n skipped")

# 1.18.28: the log line and the comments describe the switched-on state; the selftest result still decides whether a run can start
must("The sandbox switch is on; a run can start only after the canary has passed for this Core build and this selftest run." in selftest_block, "the pass line says on")
must("stays switched off in this Core release" not in INSTALL and "stays off in this release" not in INSTALL, "no text says the switch is off")
must("and is on since 1.18.28" in INSTALL, "the comment says on")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh keeps its LF line endings")
print("[TEST] PASS sandbox installer 1.18.29")
