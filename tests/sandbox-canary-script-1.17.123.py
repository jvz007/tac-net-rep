#!/usr/bin/env python3
"""1.17.123 regression: static checks of tests/sandbox-canary-1.17.123.sh (core.sandbox canary: new rows, new guards, no skipped security row).

The script needs root, systemd and Linux, so it did NOT run here. This test reads it as text:

* it keeps every step of the 1.17.122 script (the old script and its static test stay in tests/ untouched) and ends with the same verdict line;
* the installed-helper guard needs the new markers (MemoryZSwapMax, local_deny, parse_abstract_sockets, resolv_conf_bind) before any step, and
  each marker really exists in the helper, so a correct install passes the guard;
* step 2 prints the selftest rows for the resolvers, the own addresses and the gateway, and the memory choice, as information;
* step 4 checks the new rows (own address tcp 22/80/443 and udp, gateway tcp and udp, loopback 127.0.0.53 on the six ports, the memory row with
  its MiB, the abstract row with its count, the credential frame row), that 0 rows are ATTACK SUCCEEDED, 0 are NOT RUN and no security row is
  SKIPPED, and prints the abstract listener names and the upstream resolvers as information;
* the padding-safe patterns of 1.17.122 are kept; the shell patterns run against a table made by the real format_table and the real
  run_canary table, so a row the script asks for really exists under that name;
* it never enables the kill switch, never holds a real secret, and the bash syntax is clean when bash is present.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NEW = (ROOT / "tests" / "sandbox-canary-1.17.123.sh").read_text(encoding="utf-8")
PREV = (ROOT / "tests" / "sandbox-canary-1.17.122.sh").read_text(encoding="utf-8")
HELPER = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def code(text):
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


# ---- the old script is kept, and the new one holds all its steps
must("Core 1.17.122" in PREV and "_PROBE_ACL" in PREV and "MemoryZSwapMax" not in PREV, "the 1.17.122 script is untouched")
for marker in ("== step 1:", "== step 2:", "== step 2c", "== step 3:", "== step 4:", "== step 5:", "== step 6:"):
    must(marker in NEW, marker)
for check in ("1a", "2a", "2b", "2c", "3a", "3b", "3c", "3d", "3e", "3f", "4a", "4b", "4c", "4d", "4e", "4f", "4g", "4h", "4i", "4j", "4k", "4l", "4m", "5a", "5m"):
    must(f'"{check} ' in NEW, check)
must(NEW.rstrip().endswith('if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi'), "the verdict line")
must(NEW[NEW.index("== step 5:"):] == PREV[PREV.index("== step 5:"):], "step 5 and 6 are word for word the 1.17.122 lines")
must(NEW[NEW.index("== step 2c"):NEW.index("== step 4:")] == PREV[PREV.index("== step 2c"):PREV.index("== step 4:")], "steps 2c and 3 are word for word the 1.17.122 lines")
must("\r" not in NEW, "the shell script keeps LF line endings")

# ---- version strings
must("is Core 1.17.123 installed?" in NEW and "is it Core 1.17.123?" in NEW and "tests/sandbox-canary-1.17.123.sh" in NEW, "messages name 1.17.123")
must("is Core 1.17.122 installed?" not in NEW and "is it Core 1.17.122?" not in NEW and "sudo bash tests/sandbox-canary-1.17.122.sh" not in NEW, "no 1.17.122 install message")

# ---- guards (all before step 1): the older ones stay, the new markers exist in the helper
before = NEW[:NEW.index("== step 1:")]
for old in ("grep -q '127.0.0.0/8' \"$HELPER\"", "_credential_file_ready", "MISSING", "grep -q '_PROBE_ACL' \"$HELPER\""):
    must(old in before, old)
must("for marker in MemoryZSwapMax local_deny parse_abstract_sockets resolv_conf_bind; do" in before and "older than Core 1.17.123 (no $marker)" in before, "the new guard")
for marker in ("MemoryZSwapMax", "local_deny", "parse_abstract_sockets", "resolv_conf_bind"):
    must(marker in HELPER, f"the helper holds {marker}, so a correct install passes the guard")
must(before.index("_PROBE_ACL") < before.index("for marker in"), "")
for marker in ("MemoryZSwapMax", "local_deny", "parse_abstract_sockets", "resolv_conf_bind"):
    must(marker not in (ROOT / "tests" / "sandbox-canary-1.17.122.sh").read_text(encoding="utf-8"), f"{marker} is new: 1.17.122 helpers would fail the guard")

# ---- step 2: information rows
step2 = NEW[NEW.index("== step 2:"):NEW.index("== step 2c")]
for key in ("upstream_resolvers", "local_addresses", "address_filter_local", "memory_zswap"):
    must(f'"{key}"' in step2, key)
must("ip -o addr show" in step2 and "ip route show default" in step2 and "ip -6 route show default" in step2 and "/etc/resolv.conf" in step2, "own addresses, gateways and the host's resolv.conf are printed")
must("resolvers=%s dns_method=%s" in step2 and "bpf_framework" in step2 and "/run/systemd/resolve/resolv.conf" in step2 and "owner, group, mode, ACL" in step2, "the older information stays")

# ---- step 4: the new rows and counters
step4 = NEW[NEW.index("== step 4:"):NEW.index("== step 5:")]
must("own address [0-9.]+ (tcp 22|tcp 80|tcp 443|udp)" in step4 and 'for port in 22 80 443; do' in step4, "own-address rows")
must('gateway [0-9.]+ tcp $port' in step4 and 'gateway [0-9.]+ udp' in step4 and "ip -4 route show default" in step4, "gateway rows, only when the server has a next hop")
must("for port in 22 80 443 1024 4430 4433; do" in step4 and 'loopback 127.0.0.53:$port ' in step4, "the six stub ports")
must("memory beyond MemoryMax" in step4 and "allocated [0-9]+ MiB, ended" in step4, "the memory row with its MiB")
must("abstract sockets \\([0-9]+ listed\\)" in step4, "the abstract row with its count")
must("credential frame stripped from output" in step4, "the credential frame row")
for counter in ("ATTACK SUCCEEDED[[:space:]]*$", "NOT RUN[[:space:]]*$", "SKIPPED[[:space:]]*$/ && $0 !~ /public tcp 443/"):
    must(counter in step4, counter)
must('"4k 0 rows are ATTACK SUCCEEDED' in step4 and '"4l 0 rows are NOT RUN' in step4 and "no security row is SKIPPED (only 'public tcp 443' may be)" in step4, "the three zero counters")
must("read_abstract_names" in step4 and "names only" in step4, "the abstract listener names are printed, names only")
must('grep -E \'^nameserver\' "$RUN/resolv.conf"' in step4, "Core's own resolv.conf is printed")
for line in [l for l in step4.splitlines() if '"4d ' in l]:
    must("grep -Eq 'OK[[:space:]]*$'" in line, "the padding-safe pattern of 1.17.122 stays")
must(not [line for line in code(NEW) if "OK$" in line.replace("[[:space:]]*$", "")], "the literal OK$ is not used in a code line")
must(not re.search(r"(ATTACK SUCCEEDED|SKIPPED|WARN|NOT RUN)\$/", step4), "no unpadded counter pattern")
must("'^CANARY PASSED$'" in step4, "4a matches a print() line, which has no padding")

# ---- the shell patterns against real tables: the names the script asks for are the names the table has
spec = importlib.util.spec_from_file_location("sandbox_helper_123s", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)


def row(attack, verdict="OK", actual="x", wall="W"):
    return {"wall": wall, "attack": attack, "expected": "e", "actual": actual, "verdict": verdict}


def good_table(skip="public tcp 443", extra=()):
    rows = [row(f"own address 129.232.197.50 tcp {p}", "OK", "timeout", "LAN") for p in (22, 80, 443)] + [row("own address 129.232.197.50 udp", "OK", "eperm", "LAN")]
    rows += [row(f"gateway 129.232.197.1 tcp {p}", "OK", "timeout", "LAN") for p in (80, 443)] + [row("gateway 129.232.197.1 udp", "OK", "eperm", "LAN")]
    rows += [row(f"loopback 127.0.0.53:{p}", "OK", "EPERM", "Loopback") for p in (22, 80, 443, 1024, 4430, 4433)]
    rows += [row("memory beyond MemoryMax", "OK", "allocated 112 MiB, ended exited (exit 137), peak 127.9 MiB", "Limits"),
             row("abstract sockets (3 listed)", "OK", "none reachable", "Abstract sockets"),
             row("credential frame stripped from output", "OK", "stripped (checked stdout, stderr and the end frame for the nonce frame, the launcher header, the token and the refreshed token)", "Credential"),
             row("public tcp 443", skip if skip == "SKIPPED" else "OK", "x", "Public")]
    return rows + list(extra)


def run_checks(table):
    """Run the script's own grep and awk lines (4e to 4m) on a table printed by the real format_table; returns the pass/fail words."""
    bash = shutil.which("bash")
    start = NEW.index("# 1.17.123: the table must hold the new rows.")
    end = NEW.index("echo \"information: the host's abstract unix listeners")
    block = NEW[start:end]
    with tempfile.TemporaryDirectory() as folder:
        table_file = Path(folder) / "table.txt"
        table_file.write_text(sh.format_table(table) + "\n", encoding="utf-8")
        script = ("pass() { echo \"PASS $1\"; }\nfail() { echo \"FAIL $1\"; }\nCANARY_OUT=" + table_file.as_posix() + "\n"
                  "ip() { echo 'default via 129.232.197.1 dev eth0'; }\n" + block)
        done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
    return done.stdout


bash = shutil.which("bash")
if bash:
    out = run_checks(good_table())
    must("FAIL" not in out and out.count("PASS") >= 14, out)
    out = run_checks(good_table(skip="SKIPPED", extra=[row("public tcp 443", "SKIPPED")]))
    must("FAIL 4m" not in out, "a skipped 'public tcp 443' is allowed")
    for label, mutate, failing in (
            ("a missing own-address udp row", lambda t: [r for r in t if r["attack"] != "own address 129.232.197.50 udp"], "4e"),
            ("a missing gateway row", lambda t: [r for r in t if r["attack"] != "gateway 129.232.197.1 tcp 443"], "4f"),
            ("a missing stub port", lambda t: [r for r in t if r["attack"] != "loopback 127.0.0.53:4430"], "4g"),
            ("a stub port that connected", lambda t: [dict(r, verdict="ATTACK SUCCEEDED") if r["attack"] == "loopback 127.0.0.53:80" else r for r in t], "4g"),
            ("a memory row without MiB", lambda t: [dict(r, actual="exited") if r["attack"] == "memory beyond MemoryMax" else r for r in t], "4h"),
            ("an abstract row that was attacked", lambda t: [dict(r, verdict="ATTACK SUCCEEDED") if r["attack"].startswith("abstract sockets") else r for r in t], "4i"),
            ("a missing abstract row", lambda t: [r for r in t if not r["attack"].startswith("abstract sockets")], "4i"),
            ("a credential frame row that found something", lambda t: [dict(r, verdict="ATTACK SUCCEEDED", actual="found: stdout: the token") if r["attack"].startswith("credential frame") else r for r in t], "4j"),
            ("an attack that succeeded", lambda t: t + [row("ptrace attach to parent", "ATTACK SUCCEEDED")], "4k"),
            ("a probe that did not run", lambda t: t + [row("fork bomb", "NOT RUN")], "4l"),
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
    run = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.17.123.sh")], capture_output=True, text=True, check=False)
    must(run.returncode == 0, run.stderr[-500:])

print("[TEST] PASS sandbox canary script 1.17.123")
