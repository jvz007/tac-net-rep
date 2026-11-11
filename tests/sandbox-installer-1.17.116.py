#!/usr/bin/env python3
"""1.17.116 regression: install.sh and uninstall.sh carry the core.sandbox layout (core.sandbox Patch 1, part 4). Static text checks,
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
selftest_block = between(INSTALL, 'if timeout "${SANDBOX_SELFTEST_TIMEOUT_SECONDS}s" "${SANDBOX_HELPER}" --selftest', "\nfi\n")
must("fail " not in selftest_block and "exit " not in selftest_block and "refuse " not in selftest_block and "verify_fail" not in selftest_block, selftest_block)
must('log "WARNING: Sandbox is off: ${SANDBOX_OFF_REASON}. ai ChatGPT stays off."' in selftest_block, "the plain warning")
must("else" in selftest_block and "|| true" in selftest_block, "an else branch and a reason lookup that cannot fail")
must(selftest_block.lstrip().startswith("if timeout"), "inside an if, so a non-zero status is a branch and not an exit")
must("--selftest" in INSTALL and INSTALL.count('"${SANDBOX_HELPER}" --selftest') == 1, "the selftest is run once")
must(INSTALL.index('"${SANDBOX_HELPER}" --selftest') > INSTALL.index('systemctl enable --now tec-tac-sandbox-sweep.timer'), "the selftest runs after the layout and timer")

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
must("capability_status('core.sandbox'" in verify and "p.status()" in verify and "p.start()" in verify and "sandbox_disabled" in verify and "st['enabled'] is False" in verify, verify)
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

print("[TEST] PASS sandbox installer 1.17.116")
