#!/usr/bin/env python3
"""1.17.122 regression: the canary table has no trailing padding, and the script's patterns read it (Medium finding of 1.17.121).

format_table pads every cell to the column width, so a row whose verdict is shorter than the widest verdict (OK against ATTACK SUCCEEDED) ended in
spaces and the 1.17.121 check 4d, grep 'OK$', could never match it. Two layers now:

* format_table strips the trailing spaces of the header and of every row (the dashes line is left as it is);
* tests/sandbox-canary-1.17.122.sh matches 'OK[[:space:]]*$' on the row picked out by its exact attack text, and the awk counters end in
  [[:space:]]*$.

The test pulls the real 4d pipeline and the real awk counters out of the shell script and runs them with bash on a table made by format_table.
It skips the bash part with a clear message when bash is missing. Not runnable here: the real canary (root, systemd), which dev02 runs.
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


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_122t", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)
SCRIPT = (ROOT / "tests" / "sandbox-canary-1.17.122.sh").read_text(encoding="utf-8")
WALL = "another dynamic user reads the credential file"


def row(wall, attack, verdict, actual="x", expected="denied"):
    return {"wall": wall, "attack": attack, "expected": expected, "actual": actual, "verdict": verdict}


def table(cred_verdict):
    return [
        row("Network", "connect to the server itself", "OK", "blocked"),
        row("Credential", WALL, cred_verdict, "denied" if cred_verdict == "OK" else "read it"),
        row("Memory", "allocate more than the limit", "ATTACK SUCCEEDED", "allocated"),  # makes the verdict column 16 wide
        row("Process", "fork bomb", "SKIPPED", "no tool"),
        row("Latency", "50 no-op runs", "WARN", "p95 over target"),
        row("Process", "short", "OK"),
        row("Memory", "a very long attack text " * 5, "OK", "a very long actual text " * 5),
    ]


# ---- (c) no line of the output ends in a space, (e) a long cell truncated at 60 characters leaves no padding either
for verdict in ("OK", "NOT RUN", "ATTACK SUCCEEDED"):
    text = sh.format_table(table(verdict))
    must(text.splitlines()[0].startswith("WALL") and text.splitlines()[1] == "-" * len(text.splitlines()[1]), "header and dashes line keep their shape")
    for line in text.splitlines():
        must(line == line.rstrip(), ("trailing whitespace", repr(line)))
    long_line = [line for line in text.splitlines() if "a very long attack text" in line]
    must(len(long_line) == 1 and long_line[0] == long_line[0].rstrip() and long_line[0].endswith("OK"), long_line)
    must("a very long attack text " * 3 not in long_line[0], "the cell is cut at 60 characters")
    must(len(max(text.splitlines()[0:1], key=len)) == len(text.splitlines()[0].rstrip()), "header is stripped")
# the first row of the OK table is shorter than the widest verdict, which is what broke 1.17.121
padded_first = sh.format_table(table("OK")).splitlines()[2]
must(padded_first.endswith("OK"), padded_first)

# ---- (f) the static side: new patterns present, the old literal absent
CODE = chr(10).join(item for item in SCRIPT.splitlines() if not item.lstrip().startswith("#"))  # the header comment names the old pattern
must("grep -Eq 'OK[[:space:]]*$'" in CODE and "'OK$'" not in CODE, "4d pattern")
for word in ("ATTACK SUCCEEDED", "SKIPPED", "WARN"):
    must(f"/{word}[[:space:]]*$/" in CODE and f"/{word}$/" not in CODE, word)

# ---- (a), (b), (d): run the real pipeline and counters with bash
bash = shutil.which("bash")
if not bash:
    print("[TEST] SKIP the bash part of sandbox canary table 1.17.122: bash is not installed here")
else:
    line = next(item for item in SCRIPT.splitlines() if '"4d ' in item)
    pipeline = re.search(r"grep -F '[^']*' \"\$CANARY_OUT\" \| grep -Eq '[^']*'", line)
    must(pipeline is not None, line)
    counters = {}
    for word in ("ATTACK SUCCEEDED", "SKIPPED", "WARN"):
        found = re.search(r"awk '\$0 ~ /" + re.escape(word) + r"\[\[:space:\]\]\*\$/' \"\$CANARY_OUT\"", SCRIPT)
        must(found is not None, word)
        counters[word] = found.group(0)

    def sh_run(command, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "canary.out"
            path.write_text(text, encoding="utf-8", newline="\n")
            posix = path.as_posix()
            if len(posix) > 2 and posix[1] == ":":  # Git Bash on Windows
                posix = "/" + posix[0].lower() + posix[2:]
            result = subprocess.run([bash, "-c", f'CANARY_OUT="{posix}"; {command}'], capture_output=True, text=True, check=False)
            return result

    def verdict_of(cred_verdict, padded=True):
        body = sh.format_table(table(cred_verdict)) + "\n\n3 OK, 1 ATTACK SUCCEEDED, 0 NOT RUN, 1 SKIPPED, 1 WARN\nCANARY FAILED\n"
        return sh_run(pipeline.group(0), body).returncode

    must(verdict_of("OK") == 0, "(a) the OK row passes 4d")
    must(verdict_of("NOT RUN") != 0, "(b) a NOT RUN row fails 4d")
    must(verdict_of("ATTACK SUCCEEDED") != 0, "(b) an ATTACK SUCCEEDED row fails 4d")
    # the old padded shape, built by hand: 4d still passes (whitespace-safe), and the old pattern would have failed
    old_row = f"Credential  {WALL}  denied  denied  OK" + " " * 11 + "\n"
    must(sh_run(pipeline.group(0), old_row).returncode == 0, "a padded OK row passes the new pattern")
    must(sh_run(f"grep -F '{WALL}' \"$CANARY_OUT\" | grep -Eq 'OK$'", old_row).returncode != 0, "the 1.17.121 pattern failed on the same padded row")
    # a missing row never passes, a row for another attack never counts
    must(sh_run(pipeline.group(0), "Network  something else  OK\n").returncode != 0, "no row, no pass")
    must(sh_run(pipeline.group(0), f"Network  something else  OK\nCredential  {WALL}  x  y  NOT RUN\n").returncode != 0, "another row's OK does not count")

    # (d) the counters, on a padded table (hand-built: padding on purpose) and on format_table output
    padded = ("A  x  y  z  ATTACK SUCCEEDED\nB  x  y  z  SKIPPED   \nC  x  y  z  WARN    \nD  x  y  z  SKIPPED\nE  x  y  z  OK              \n"
              "F  x  y  z  ATTACK SUCCEEDED   \n")
    for word, want in (("ATTACK SUCCEEDED", 2), ("SKIPPED", 2), ("WARN", 1)):
        result = sh_run(counters[word] + " | wc -l", padded)
        must(result.stdout.strip() == str(want), (word, result.stdout, result.stderr))
    real = sh.format_table(table("OK"))
    for word, want in (("ATTACK SUCCEEDED", 1), ("SKIPPED", 1), ("WARN", 1)):
        result = sh_run(counters[word] + " | wc -l", real)
        must(result.stdout.strip() == str(want), (word, result.stdout, result.stderr))

print("[TEST] PASS sandbox canary table 1.17.122")
