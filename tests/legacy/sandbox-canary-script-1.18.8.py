#!/usr/bin/env python3
"""1.18.8 regression: static checks of tests/sandbox-canary-1.18.8.sh and tests/sandbox-canary-1.18.8-before.py (core.sandbox Patch A, canary first).

The scripts need root, systemd and Linux, so they did NOT run here. This test reads them as text and runs their own grep, awk and guard lines in bash:

* every step and check of the 1.17.124 script is kept (that script stays in tests/ untouched) and the verdict line is the same;
* the installed-helper guard needs RootDirectory=, view_plan, rootview, run.started, CgroupWatch and SANDBOX_ROOT, refuses a helper without them,
  and every marker really exists in the helper;
* step 4 needs the rootview rows (one per folder, and the unit's own / row), the stand-in folder marker row, the three credential rows and a memory
  row that shows the kernel's oom_kills or a refused allocation; each row, dropped or turned ATTACK SUCCEEDED, NOT RUN or SKIPPED in a table made by the
  real format_table, fails its step;
* step 5 checks the root audit rows of the canary runs and that no /tectac-canary-* folder is left (the audit checker is run on good and bad logs);
* the ``before`` mode exists, is bash -n clean, needs root, never enables the kill switch and never calls --start; the before program builds a
  runner command with no '$' or '%' that runs the 1.18.8 runner through ``python3 -I -c`` (run here with the same Python).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NEW = (ROOT / "tests" / "sandbox-canary-1.18.8.sh").read_text(encoding="utf-8")
PREV = (ROOT / "tests" / "sandbox-canary-1.17.124.sh").read_text(encoding="utf-8")
BEFORE = (ROOT / "tests" / "sandbox-canary-1.18.8-before.py").read_text(encoding="utf-8")
HELPER = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


# ---- the old script is kept, and the new one holds all its steps
must("Runtime check for Core 1.17.124" in PREV and "rootview" not in PREV and "CANARYEND" in PREV, "the 1.17.124 script is untouched")
for marker in ("== step 1:", "== step 2:", "== step 2c", "== step 3:", "== step 4:", "== step 5:", "== step 6:"):
    must(marker in NEW, marker)
OLD_CHECKS = ("1a", "1b", "1c", "1d", "2a", "2b", "2c", "3a", "3b", "3c", "3d", "3e", "3f", "4a", "4b", "4c", "4d", "4e", "4f", "4g", "4h", "4i", "4j", "4k", "4l", "4m", "4n", "4o", "4p",
              "5a", "5b", "5c", "5d", "5e", "5f", "5g", "5h", "5i", "5j", "5k", "5l", "5m")
for check in OLD_CHECKS:
    must(f'"{check} ' in NEW, check)
NEW_CHECKS = ("1e", "4q", "4r", "4s", "4t", "4u", "5n", "5o")
for check in NEW_CHECKS:
    must(f'"{check} ' in NEW and f'"{check} ' not in PREV, check)
must(NEW.rstrip().endswith('if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi'), "the verdict line")
must(NEW[NEW.index("== step 2c"):NEW.index("== step 4:")] == PREV[PREV.index("== step 2c"):PREV.index("== step 4:")], "steps 2c and 3 are word for word the 1.17.124 lines")
must(all(b"\r" not in (ROOT / "tests" / name).read_bytes() for name in ("sandbox-canary-1.18.8.sh", "sandbox-canary-1.18.8-before.py")), "LF line endings")
header = NEW[:NEW.index("set -u")]
must("1.18.8 changes from the 1.17.124 script" in header and "SEND BACK THE WHOLE OUTPUT" in header and "before" in header, "the header lists the changes and asks for the whole output")
must("sudo bash tests/sandbox-canary-1.18.8.sh before" in header and "sudo bash tests/sandbox-canary-1.18.8.sh   " in header, "both commands are named in the header")

# ---- the kill switch is never touched, no real secret
for text in (NEW, BEFORE):
    must("SANDBOX_ENABLED = True" not in text and "sed -i" not in text, "never enables the sandbox")
must("--start" not in BEFORE and "--canary-launch" not in BEFORE and "SANDBOX_ENABLED" not in BEFORE, "the before program never starts a run through --start")
must("SANDBOX_ENABLED = False" in HELPER and "SANDBOX_ENABLED = False" in NEW, "the guard still needs the off switch")

# ---- the guard
before_step_1 = NEW[:NEW.index("== step 1:")]
for marker in ("RootDirectory=", "view_plan", "rootview", "run.started", "CgroupWatch", "SANDBOX_ROOT"):
    must(marker in HELPER, f"the helper holds {marker}, so a correct install passes the guard")
    must(marker not in PREV, f"{marker} is new: a 1.18.7 helper fails the guard")
must("for marker in 'RootDirectory=' view_plan rootview run.started CgroupWatch SANDBOX_ROOT; do" in before_step_1 and "older than Core 1.18.8 (no $marker)" in before_step_1, "the new guard")
for old in ("grep -q '127.0.0.0/8' \"$HELPER\"", "_credential_file_ready", "for marker in MemoryZSwapMax local_deny parse_abstract_sockets resolv_conf_bind; do",
            "for marker in CANARYEND oom_kills fit_abstract_names; do", "grep -q 'AF_INET AF_UNIX' \"$HELPER\""):
    must(old in before_step_1, old)
bash = shutil.which("bash")


def guard(helper_text, mode="full"):
    start = NEW.index('if [ "$(id -u)" -ne 0 ]')
    end = NEW.index("TACTICAL_USER=$(")
    block = NEW[start:end].replace('if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi', "")
    with tempfile.TemporaryDirectory() as folder:
        helper = Path(folder) / "tec-tac-sandbox"
        helper.write_text("#!/usr/bin/env python3\n" + helper_text, encoding="utf-8")
        helper.chmod(helper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        source = Path(folder) / "src"
        (source / "scripts").mkdir(parents=True)
        (source / "tests").mkdir()
        done = subprocess.run([bash, "-c", f'HELPER="{helper.as_posix()}"\nMODE={mode}\nSCRIPT_DIR="{(source / "tests").as_posix()}"\nSOURCE_DIR="{source.as_posix()}"\n{block}\necho GUARD-PASSED'],
                              capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


OLDER = ("SANDBOX_ENABLED = False", "--canary", "127.0.0.0/8", "_credential_file_ready", "MISSING", "_PROBE_ACL", "MemoryZSwapMax", "local_deny", "parse_abstract_sockets",
         "resolv_conf_bind", "CANARYEND", "oom_kills", "fit_abstract_names", "RestrictAddressFamilies=AF_INET")
NEWER = ("RootDirectory=", "view_plan", "rootview", "run.started", "CgroupWatch", "SANDBOX_ROOT")
if bash:
    rc, out = guard("\n".join(OLDER))
    if "the root helper is missing" in out:
        print("[NOTE] this bash cannot see a file as executable: the guard cases were skipped")
    else:
        must(rc == 1 and "older than Core 1.18.8 (no RootDirectory=)" in out and "GUARD-PASSED" not in out, (rc, out))  # a 1.18.7 helper is refused
        for missing in NEWER:
            rc, out = guard("\n".join(OLDER + tuple(m for m in NEWER if m != missing)))
            must(rc == 1 and f"(no {missing})" in out, (missing, rc, out))
        rc, out = guard("\n".join(OLDER + NEWER))
        must(rc == 0 and "GUARD-PASSED" in out, (rc, out))
        rc, out = guard(HELPER)
        must(rc == 0 and "GUARD-PASSED" in out, "the real helper passes the guard: " + out)
        rc, out = guard("\n".join(OLDER), mode="bogus")
        must(rc == 1 and "unknown mode" in out, (rc, out))
        # the before mode: refuses a missing source tree, and refuses an installed helper that is already 1.18.8
        rc, out = guard("\n".join(OLDER), mode="before")
        must(rc == 1 and "the 1.18.8 files are not next to this script" in out, (rc, out))
        # as non-root the whole script stops at its first line
        done = subprocess.run([bash, str(ROOT / "tests" / "sandbox-canary-1.18.8.sh")], capture_output=True, text=True, check=False)
        if shutil.which("id") and subprocess.run(["id", "-u"], capture_output=True, text=True, check=False).stdout.strip() != "0":
            must(done.returncode == 1 and "must run as root" in done.stdout, (done.returncode, done.stdout))
    done = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.18.8.sh")], capture_output=True, text=True, check=False)
    must(done.returncode == 0, done.stderr)

# ---- before mode in the script
must('if [ "$MODE" = "before" ]; then' in NEW and "sandbox-canary-1.18.8-before.py" in NEW and "PASS before run" in NEW and "FAIL before run" in NEW, "before mode")
must('grep -q \'RootDirectory=\' "$HELPER" && { echo "FAIL the installed helper is already Core 1.18.8 or newer' in NEW, "before only makes sense on 1.18.7")
must("copy tests/sandbox-canary-1.18.8.sh, tests/sandbox-canary-1.18.8-before.py, scripts/sandbox-canary-runner.py and scripts/sandbox-helper.py" in NEW, "the copy hint")

# ---- step 1 and 2 additions
must('"$LIB/root"' in NEW and "1e the sandbox root folder is root-owned 0755" in NEW, "the root folder check")
must('"sandbox_root", "filesystem_view"' in NEW, "step 2 prints the new selftest rows")

# ---- the rows and counters of step 4
spec = importlib.util.spec_from_file_location("sandbox_helper_188s", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)
exact, _prefixes = sh.CANARY_REQUIRED["rootview"]
must(sorted(exact) == sorted(["view " + f for f in sh.CANARY_VIEW_FOLDERS] + ["/ lists only the allowed set"]), "the helper requires every row the script asks for")


def row(attack, verdict="OK", actual="x", wall="W"):
    return {"wall": wall, "attack": attack, "expected": "e", "actual": actual, "verdict": verdict}


STANDIN = "read /tectac-canary-0123456789ab/.tectac-canary-ba9876543210"


def good_table(extra=()):
    rows = [row(f"own address 129.232.197.50 tcp {p}", "OK", "timeout", "LAN") for p in (22, 80, 443)] + [row("own address 129.232.197.50 udp", "OK", "eperm", "LAN")]
    rows += [row(f"gateway 129.232.197.1 tcp {p}", "OK", "timeout", "LAN") for p in (80, 443)] + [row("gateway 129.232.197.1 udp", "OK", "eperm", "LAN")]
    rows += [row(f"loopback 127.0.0.53:{p}", "OK", "timeout", "Loopback") for p in (22, 80, 443, 1024, 4430, 4433)]
    rows += [row(f"unix socket creation refused ({k})", "OK", "EAFNOSUPPORT", "Sockets") for k in ("stream", "dgram", "seqpacket")]
    rows += [row("unix pathname socket refused", "OK", "EAFNOSUPPORT", "Sockets"), row("socketpair round trip", "OK", "worked", "Sockets"),
             row("pipe round trip", "OK", "worked", "Sockets"), row("child process with stdio pipes", "OK", "worked", "Sockets")]
    rows += [row("memory beyond MemoryMax", "OK", "allocated 112 MiB, ended exited (exit 1), oom_kills 1, peak 127.9 MiB, evidence poll", "Limits"),
             row("abstract sockets (3 listed)", "OK", "all refused: EAFNOSUPPORT (3 listed, 0 left out)", "Abstract sockets"),
             row("credential frame stripped from output", "OK", "stripped", "Credential"), row("public tcp 443", "OK", "x", "Public"),
             row("another dynamic user reads the credential file", "OK", "denied", "Credential")]
    rows += [row("view " + f, "OK", "5 entries, none of the host's unlisted names", "Files") for f in sh.CANARY_VIEW_FOLDERS]
    rows += [row("/ lists only the allowed set", "OK", "14 entries, all allowed", "Files"), row(STANDIN, "OK", "ENOENT", "Files")]
    rows += [row(n, "OK", "arrived", "Credential") for n in ("credential arrives", "credential mode", "credential not in environment")]
    return rows + list(extra)


def run_checks(table):
    start = NEW.index("# 1.17.123: the table must hold the new rows.")
    end = NEW.index("echo \"information: the host's abstract unix listeners as root sees them (names only, never any content), and what", start)
    block = NEW[start:end]
    with tempfile.TemporaryDirectory() as folder:
        table_file = Path(folder) / "table.txt"
        table_file.write_text(sh.format_table(table) + "\n", encoding="utf-8")
        script = ("pass() { echo \"PASS $1\"; }\nfail() { echo \"FAIL $1\"; }\nCANARY_OUT=" + table_file.as_posix() + "\n"
                  "ip() { echo 'default via 129.232.197.1 dev eth0'; }\n" + block)
        done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
    return done.stdout


if bash:
    out = run_checks(good_table())
    must("FAIL" not in out and out.count("PASS") >= 40, out)
    steps = {"view /": "4q", "view /etc": "4q", "view /run": "4q", "view /opt/tec-tac/runtimes": "4q", "view /usr/local/lib/tec-tac/sandbox": "4q",
             "/ lists only the allowed set": "4r", STANDIN: "4s", "credential arrives": "4t", "credential mode": "4t", "credential not in environment": "4t",
             "memory beyond MemoryMax": "4h", "unix pathname socket refused": "4o"}  # the memory row's verdict is step 4h; 4u (below) reads its text
    for name, step in steps.items():
        out = run_checks([r for r in good_table() if r["attack"] != name])
        must(f"FAIL {step}" in out, ("dropped", name, out))
        for verdict, counter in (("ATTACK SUCCEEDED", "4k"), ("NOT RUN", "4l")):
            out = run_checks([dict(r, verdict=verdict) if r["attack"] == name else r for r in good_table()])
            must(f"FAIL {step}" in out and f"FAIL {counter}" in out, (verdict, name, step, out))
    # the memory row must show evidence: a kill count of zero, no probe word, is not enough
    out = run_checks([dict(r, actual="allocated 112 MiB, ended exited (exit 1), oom_kills 0, peak 100.0 MiB") if r["attack"] == "memory beyond MemoryMax" else r for r in good_table()])
    must("FAIL 4u" in out, out)
    out = run_checks([dict(r, actual="allocated 112 MiB, ended exited (exit 1), oom_kills unknown, probe memoryerror, peak 100.0 MiB") if r["attack"] == "memory beyond MemoryMax" else r for r in good_table()])
    must("FAIL 4u" not in out and "PASS 4u" in out, "a refused allocation is evidence too: " + out)
    # a row of one view folder must not be satisfied by another folder's row
    out = run_checks([dict(r, verdict="ATTACK SUCCEEDED") if r["attack"] == "view /etc" else r for r in good_table()])
    must("FAIL 4q the view of /etc " in out and "PASS 4q the view of / " in out and "PASS 4q the view of /var " in out, out)
    # the older checks still bite
    out = run_checks([r for r in good_table() if r["attack"] != "own address 129.232.197.50 udp"])
    must("FAIL 4e" in out, out)
    out = run_checks(good_table(extra=[row("public tcp 443", "SKIPPED")]))
    must("FAIL 4m" not in out, "a skipped 'public tcp 443' is allowed")
    out = run_checks(good_table(extra=[row("abstract sockets (0 listed)", "SKIPPED")]))
    must("FAIL 4m" in out, "another skipped row is not")

# ---- step 5: the audit checker, run on good and bad logs
start = NEW.index("AUDIT_REPORT=$(python3 -")
end = NEW.index('echo "information: root audit rows of the canary runs')
audit_block = NEW[start:end]
person = "a" * 32


def started(run_id, **kw):
    return {"event": "run.started", "detail": {"runner": "core.canary", "run_id": run_id, "person": person, "canary": True, **kw}}


def ended(run_id, **kw):
    detail = {"runner": "core.canary", "run_id": run_id, "person": person, "canary": True, "reason": "exited", "exit": 0, "ms": 5, "bytes_out": 1, "bytes_err": 0,
              "peak_mb": 1.0, "oom_kills": None, "evidence": None}
    detail.update(kw)
    return {"event": "run.ended", "detail": detail}


def audit_run(rows, skip=0, extra_lines=()):
    if not bash:
        return None
    with tempfile.TemporaryDirectory() as folder:
        log = Path(folder) / "audit.jsonl"
        log.write_text("\n".join([*extra_lines, *[json.dumps(r) for r in rows]]) + "\n", encoding="utf-8")
        done = subprocess.run([bash, "-c", f'python3() {{ "{sys.executable.replace(chr(92), "/")}" "$@"; }}\nSTATE="{Path(folder).as_posix()}"\nAUDIT_LINES_BEFORE={skip}\n' + audit_block.replace('"$STATE/audit.jsonl"', '"$STATE/audit.jsonl"') + "\necho \"$AUDIT_REPORT\""],
                              capture_output=True, text=True, check=False)
    return done.stdout


if bash:
    ids = [os.urandom(16).hex() for _ in range(12)]
    good_rows = [r for i in ids for r in (started(i), ended(i))]
    must("started=12 ended=12 problems=0" in audit_run(good_rows), audit_run(good_rows))
    must("started=12 ended=12 problems=0" in audit_run(good_rows, skip=1, extra_lines=['{"event":"selftest","detail":{}}']), "lines before the canary run are skipped")
    must("only 3 run.started" in audit_run([r for i in ids[:3] for r in (started(i), ended(i))]), "too few runs")
    must("has no run.ended" in audit_run(good_rows[:-1]), "a started run without an end")
    bad = [r for r in good_rows]
    bad[1] = ended(ids[0], note="x")
    must("unexpected keys" in audit_run(bad), "an extra key")
    bad = [r for r in good_rows]
    bad[1] = ended(ids[0], reason="refreshed-abcdef")
    must("holds a credential" in audit_run(bad), "a credential-like text")
    bad = [r for r in good_rows]
    bad[0] = started(ids[0], person="canary-cred")
    must("holds a credential, a path or a person text" in audit_run(bad) and "person is not a key" in audit_run(bad), "a person text instead of a key")
    bad = [r for r in good_rows]
    bad[0] = started(ids[0], runner="/work/x")
    must("a path" in audit_run(bad), "a path")
    bad = [r for r in good_rows]
    bad[0] = started(ids[0], canary=False)
    must("not marked canary" in audit_run(bad), "the canary flag")

# ---- step 5 additions
must("find / -maxdepth 1 -name 'tectac-canary-*'" in NEW and "5n no /tectac-canary-* stand-in folder is left" in NEW, "the stand-in folder is gone afterwards")

# ---- the before program
compile(BEFORE, "sandbox-canary-1.18.8-before.py", "exec", dont_inherit=True)  # syntax only; nothing is written to disk
for needed in ("INSTALLED_HELPER = \"/usr/local/lib/tec-tac/sandbox/sandbox-helper.py\"", "installed.canary_row()", "installed.build_properties(", "installed.build_environment(row)",
               "new.rootview_plan()", "new._plant_markers()", "new.parse_runner_rows", "new.group_table(", "new.format_table(", "new.remove_markers()",
               "BEFORE RUN: ", "credential_names=[]"):
    must(needed in BEFORE, needed)
must(BEFORE.index("new.remove_markers()") > BEFORE.index("new._plant_markers()") and "finally:" in BEFORE, "markers are removed in a finally block")
must("'-I', '-c'" not in BEFORE and '"-I", "-c"' in BEFORE, "python3 -I -c")
bspec = importlib.util.spec_from_file_location("sandbox_before_188", ROOT / "tests" / "sandbox-canary-1.18.8-before.py")
before = importlib.util.module_from_spec(bspec)
bspec.loader.exec_module(before)
command = before.runner_command(ROOT, "rootview")
must(command[:3] == ["/usr/bin/python3", "-I", "-c"] and command[4] == "rootview" and len(command) == 5, command[:3])
code = command[3]
must("$" not in code and "%" not in code and "\n" not in code and len(code) < 100000, "no '$' and no '%' in the argument")
for group, stdin, expect in (("noop", "{}", ""), ("rootview", "{}", "rootview plan\tNOTRUN"), ("files", json.dumps({"markers": []}), "")):
    done = subprocess.run([sys.executable, "-I", "-c", code, group], input=stdin, capture_output=True, text=True, timeout=60, check=False)
    must(done.returncode == 0 and expect in done.stdout, (group, done.returncode, done.stdout, done.stderr))
done = subprocess.run([sys.executable, "-I", "-c", code, "nonsense"], input="{}", capture_output=True, text=True, timeout=60, check=False)
must(done.returncode == 64, "an unknown group is refused by the runner as before")

print("[TEST] PASS sandbox canary script 1.18.8")
