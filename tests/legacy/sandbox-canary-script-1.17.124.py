#!/usr/bin/env python3
"""1.17.124 regression: static checks of tests/sandbox-canary-1.17.124.sh (core.sandbox canary: AF_UNIX gone, new rows, new guards).

The script needs root, systemd and Linux, so it did NOT run here. This test reads it as text and runs its own grep and awk lines in bash:

* it keeps every step of the 1.17.123 script (the old script stays in tests/ untouched) and ends with the same verdict line;
* the installed-helper guard needs CANARYEND, oom_kills and fit_abstract_names and refuses a helper that still says 'AF_INET AF_UNIX'; an
  older-helper stand-in is refused, the current helper passes; every marker really exists in the helper;
* step 2 prints the unit's RestrictAddressFamilies value and the host's abstract listener names (names only) as information;
* step 4 needs the new rows (unix socket creation refused x3, unix pathname socket refused, socketpair round trip, pipe round trip, child
  process with stdio pipes, the abstract row with listed and left-out counts, the memory row with allocated, ended, oom_kills and peak, loopback
  127.0.0.53 on all six ports) and 0 ATTACK SUCCEEDED, 0 NOT RUN, no security row SKIPPED;
* each new row, dropped or set to ATTACK SUCCEEDED, NOT RUN or SKIPPED in a table made by the real format_table, turns its step to FAIL;
* it never enables the kill switch, never holds a real secret, and the bash syntax is clean when bash is present.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NEW = (ROOT / "tests" / "sandbox-canary-1.17.124.sh").read_text(encoding="utf-8")
PREV = (ROOT / "tests" / "sandbox-canary-1.17.123.sh").read_text(encoding="utf-8")
HELPER = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def code(text):
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


# ---- the old script is kept, and the new one holds all its steps
must("Core 1.17.123" in PREV and "MemoryZSwapMax" in PREV and "CANARYEND" not in PREV, "the 1.17.123 script is untouched")
for marker in ("== step 1:", "== step 2:", "== step 2c", "== step 3:", "== step 4:", "== step 5:", "== step 6:"):
    must(marker in NEW, marker)
for check in ("1a", "2a", "2b", "2c", "3a", "3b", "3c", "3d", "3e", "3f", "4a", "4b", "4c", "4d", "4e", "4f", "4g", "4h", "4i", "4j", "4k", "4l", "4m",
              "4n", "4o", "4p", "5a", "5m"):
    must(f'"{check} ' in NEW, check)
must(NEW.rstrip().endswith('if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi'), "the verdict line")
must(NEW[NEW.index("== step 5:"):] == PREV[PREV.index("== step 5:"):], "step 5 and 6 are word for word the 1.17.123 lines")
must(NEW[NEW.index("== step 2c"):NEW.index("== step 4:")] == PREV[PREV.index("== step 2c"):PREV.index("== step 4:")], "steps 2c and 3 are word for word the 1.17.123 lines")
must("\r" not in NEW, "the shell script keeps LF line endings")
header = NEW[:NEW.index("set -u")]
must("1.17.124 changes from the 1.17.123 script" in header and "SEND BACK THE WHOLE OUTPUT" in header, "the header lists the 1.17.124 changes and asks for the whole output")

# ---- version strings
must("is Core 1.17.124 installed?" in NEW and "is it Core 1.17.124?" in NEW and "sudo bash tests/sandbox-canary-1.17.124.sh" in NEW, "messages name 1.17.124")
for old in ("is Core 1.17.123 installed?", "is it Core 1.17.123?", "sudo bash tests/sandbox-canary-1.17.123.sh"):
    must(old not in NEW, old)

# ---- guards (all before step 1)
before = NEW[:NEW.index("== step 1:")]
for old in ("grep -q '127.0.0.0/8' \"$HELPER\"", "_credential_file_ready", "grep -q '_PROBE_ACL' \"$HELPER\"",
            "for marker in MemoryZSwapMax local_deny parse_abstract_sockets resolv_conf_bind; do"):
    must(old in before, old)
must("for marker in CANARYEND oom_kills fit_abstract_names; do" in before and "older than Core 1.17.124 (no $marker)" in before, "the new guard")
must("grep -q 'AF_INET AF_UNIX' \"$HELPER\"" in before and "still allows AF_UNIX" in before, "the AF_UNIX guard")
for marker in ("CANARYEND", "oom_kills", "fit_abstract_names"):
    must(marker in HELPER, f"the helper holds {marker}, so a correct install passes the guard")
    must(marker not in PREV, f"{marker} is new: a 1.17.123 helper fails the guard")
must("AF_INET AF_UNIX" not in HELPER, "the current helper passes the AF_UNIX guard")

bash = shutil.which("bash")


def guard(helper_text):
    """Run the script's guard lines (from the helper-exists check to the Tactical user) against a stand-in helper file."""
    start = NEW.index('[ -x "$HELPER" ]')
    end = NEW.index("TACTICAL_USER=$(")
    block = NEW[start:end]
    with tempfile.TemporaryDirectory() as folder:
        helper = Path(folder) / "tec-tac-sandbox"
        helper.write_text("#!/usr/bin/env python3\n" + helper_text, encoding="utf-8")
        helper.chmod(helper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        done = subprocess.run([bash, "-c", f'HELPER="{helper.as_posix()}"\n{block}\necho GUARD-PASSED'], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout


OLDER_MARKERS = ("SANDBOX_ENABLED = False", "--canary", "127.0.0.0/8", "_credential_file_ready", "MISSING", "_PROBE_ACL", "MemoryZSwapMax",
                 "local_deny", "parse_abstract_sockets", "resolv_conf_bind")
NEWER_MARKERS = ("CANARYEND", "oom_kills", "fit_abstract_names")
if bash:
    rc, out = guard("\n".join(OLDER_MARKERS + ("RestrictAddressFamilies=AF_INET AF_UNIX",)))
    if "the root helper is missing" in out:
        print("[NOTE] this bash cannot see a file as executable: the guard cases were skipped")
    else:
        must(rc == 1 and "older than Core 1.17.124 (no CANARYEND)" in out and "GUARD-PASSED" not in out, (rc, out))  # a 1.17.123 helper is refused
        for missing in NEWER_MARKERS:
            rc, out = guard("\n".join(OLDER_MARKERS + tuple(m for m in NEWER_MARKERS if m != missing)))
            must(rc == 1 and f"(no {missing})" in out, (missing, rc, out))
        rc, out = guard("\n".join(OLDER_MARKERS + NEWER_MARKERS + ("RestrictAddressFamilies=AF_INET AF_UNIX",)))
        must(rc == 1 and "still allows AF_UNIX" in out, (rc, out))
        rc, out = guard("\n".join(OLDER_MARKERS + NEWER_MARKERS + ("RestrictAddressFamilies=AF_INET",)))
        must(rc == 0 and "GUARD-PASSED" in out, (rc, out))
        rc, out = guard(HELPER)
        must(rc == 0 and "GUARD-PASSED" in out, "the real helper passes the guard: " + out)

# ---- step 2: information
step2 = NEW[NEW.index("== step 2:"):NEW.index("== step 2c")]
for key in ("upstream_resolvers", "local_addresses", "address_filter_local", "memory_zswap"):
    must(f'"{key}"' in step2, key)
must("grep -o 'RestrictAddressFamilies=[A-Za-z_ ]*' \"$HELPER\"" in step2 and "AF_INET only" in step2, "the unit's address families are printed")
must("read_abstract_names" in step2 and "names only" in step2, "the host's abstract listener names are printed in step 2, names only")
must("ip -o addr show" in step2 and "ip route show default" in step2 and "/etc/resolv.conf" in step2, "the older information stays")

# ---- step 4: the new rows and counters
step4 = NEW[NEW.index("== step 4:"):NEW.index("== step 5:")]
must("unix socket creation refused ($kind)" in step4 and "for kind in stream dgram seqpacket; do" in step4, "the three creation rows")
must("unix pathname socket refused" in step4, "the pathname row")
for control in ("socketpair round trip", "pipe round trip", "child process with stdio pipes"):
    must(f"'{control}'" in step4, control)
must("oom_kills [0-9a-z]+.*peak" in step4 and "allocated [0-9]+ MiB, ended" in step4, "the memory row with its MiB, oom_kills and peak")
must("[0-9]+ listed, [0-9]+ left out" in step4, "the abstract row with its counts")
must("for port in 22 80 443 1024 4430 4433; do" in step4 and 'loopback 127.0.0.53:$port ' in step4, "the six stub ports")
for counter in ("ATTACK SUCCEEDED[[:space:]]*$", "NOT RUN[[:space:]]*$", "SKIPPED[[:space:]]*$/ && $0 !~ /public tcp 443/"):
    must(counter in step4, counter)
must(not [line for line in code(NEW) if "OK$" in line.replace("[[:space:]]*$", "")], "the literal OK$ is not used in a code line")
for line in [ln for ln in step4.splitlines() if '"4n ' in ln or '"4o ' in ln or '"4p ' in ln or '"4d ' in ln]:
    must("grep -Eq 'OK[[:space:]]*$'" in line, "the padding-safe pattern stays: " + line[:60])

# ---- the shell patterns against real tables: the names the script asks for are the names the helper requires
spec = importlib.util.spec_from_file_location("sandbox_helper_124s", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)
exact, prefixes = sh.CANARY_REQUIRED["sockets"]
NEW_SOCKET_ROWS = ["unix socket creation refused (stream)", "unix socket creation refused (dgram)", "unix socket creation refused (seqpacket)",
                   "unix pathname socket refused", "socketpair round trip", "pipe round trip", "child process with stdio pipes"]
must(set(NEW_SOCKET_ROWS) <= set(exact), "the helper requires every row the script asks for, so a missing row is NOT RUN in the table too")


def row(attack, verdict="OK", actual="x", wall="W"):
    return {"wall": wall, "attack": attack, "expected": "e", "actual": actual, "verdict": verdict}


def good_table(extra=()):
    rows = [row(f"own address 129.232.197.50 tcp {p}", "OK", "timeout", "LAN") for p in (22, 80, 443)] + [row("own address 129.232.197.50 udp", "OK", "eperm", "LAN")]
    rows += [row(f"gateway 129.232.197.1 tcp {p}", "OK", "timeout", "LAN") for p in (80, 443)] + [row("gateway 129.232.197.1 udp", "OK", "eperm", "LAN")]
    rows += [row(f"loopback 127.0.0.53:{p}", "OK", "timeout", "Loopback") for p in (22, 80, 443, 1024, 4430, 4433)]
    rows += [row(f"unix socket creation refused ({k})", "OK", "EAFNOSUPPORT", "Sockets") for k in ("stream", "dgram", "seqpacket")]
    rows += [row("unix pathname socket refused", "OK", "EAFNOSUPPORT", "Sockets"), row("socketpair round trip", "OK", "worked", "Sockets"),
             row("pipe round trip", "OK", "worked", "Sockets"), row("child process with stdio pipes", "OK", "worked", "Sockets")]
    rows += [row("memory beyond MemoryMax", "OK", "allocated 112 MiB, ended exited (exit 1), oom_kills 1, peak 127.9 MiB", "Limits"),
             row("abstract sockets (3 listed)", "OK", "all refused: EAFNOSUPPORT (3 listed, 0 left out)", "Abstract sockets"),
             row("abstract sockets left out (information)", "OK", "0 left out (covered by the unix socket creation rows)", "Abstract sockets"),
             row("credential frame stripped from output", "OK", "stripped (checked stdout, stderr and the end frame)", "Credential"),
             row("public tcp 443", "OK", "x", "Public")]
    return rows + list(extra)


def run_checks(table):
    """Run the script's own grep and awk lines (4e to 4p) on a table printed by the real format_table; returns the pass/fail words."""
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
    must("FAIL" not in out and out.count("PASS") >= 24, out)
    out = run_checks(good_table(extra=[row("public tcp 443", "SKIPPED")]))
    must("FAIL 4m" not in out, "a skipped 'public tcp 443' is allowed")
    steps = {"unix socket creation refused (stream)": "4n", "unix socket creation refused (dgram)": "4n", "unix socket creation refused (seqpacket)": "4n",
             "unix pathname socket refused": "4o", "socketpair round trip": "4p", "pipe round trip": "4p", "child process with stdio pipes": "4p",
             "memory beyond MemoryMax": "4h", "abstract sockets (3 listed)": "4i", "loopback 127.0.0.53:4433": "4g"}
    for name, step in steps.items():
        out = run_checks([r for r in good_table() if r["attack"] != name])
        must(f"FAIL {step}" in out, ("dropped", name, out))
        for verdict, counter in (("ATTACK SUCCEEDED", "4k"), ("NOT RUN", "4l"), ("SKIPPED", "4m")):
            out = run_checks([dict(r, verdict=verdict) if r["attack"] == name else r for r in good_table()])
            must(f"FAIL {step}" in out and f"FAIL {counter}" in out, (verdict, name, step, out))
    # the abstract row without its counts, the memory row without its evidence
    out = run_checks([dict(r, actual="none reachable") if r["attack"].startswith("abstract sockets (") else r for r in good_table()])
    must("FAIL 4i" in out, out)
    out = run_checks([dict(r, actual="allocated 112 MiB, ended exited (exit 1)") if r["attack"] == "memory beyond MemoryMax" else r for r in good_table()])
    must("FAIL 4h" in out, out)
    # the older checks still bite
    for label, mutate, failing in (
            ("a missing own-address udp row", lambda t: [r for r in t if r["attack"] != "own address 129.232.197.50 udp"], "4e"),
            ("a missing gateway row", lambda t: [r for r in t if r["attack"] != "gateway 129.232.197.1 tcp 443"], "4f"),
            ("a credential frame row that found something", lambda t: [dict(r, verdict="ATTACK SUCCEEDED") if r["attack"].startswith("credential frame") else r for r in t], "4j"),
            ("a skipped security row", lambda t: t + [row("abstract sockets (0 listed)", "SKIPPED")], "4m")):
        out = run_checks(mutate(good_table()))
        must(f"FAIL {failing}" in out, (label, failing, out))
else:
    print("[NOTE] bash is not available here: the shell patterns were not run against a real table")

# ---- safety
must("SANDBOX_ENABLED = False" in NEW and not re.search(r"sed[^\n]*SANDBOX_ENABLED", NEW), "the kill switch is checked, never changed")
must("SANDBOX_ENABLED = True" not in NEW, "never enables the switch")
must(not re.search(r"\b[0-9a-f]{40,}\b", NEW) and not re.search(r"(?i)(password|api[_-]?key|BEGIN [A-Z ]*PRIVATE)", NEW), "no real secret")

# ---- shell syntax through bash when it is present
if bash:
    run = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.17.124.sh")], capture_output=True, text=True, check=False)
    must(run.returncode == 0, run.stderr[-500:])
else:
    must(os.path.exists(ROOT / "tests" / "sandbox-canary-1.17.124.sh"), "")

print("[TEST] PASS sandbox canary script 1.17.124")
