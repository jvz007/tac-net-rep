#!/usr/bin/env python3
"""1.18.15 regression: canary rows are found by a stable id, never by a printed label (dev02 canary of 1.18.14, step 4t).

The label 'credential source folder is gone while the run is still active' is 62 characters; format_table cuts a column at 60, so
``grep -F`` of the full label found nothing although the row was OK. The helper now prints, after the table and before the totals, one line per
row, ``ROW <id> <verdict>``: the id is the row's own ``id`` or the slug of its label ([a-z0-9-], at most 40 characters, unique in the table). The
canary script reads the verdicts from those lines. Only step 4t was affected by the cut (the other labels are under 60 characters).

Not runnable here: the real canary (dev02: tests/sandbox-canary-1.18.15.sh).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper  # noqa: E402  (1.18.26: the helper and sandbox-selftest.py as one object)
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sh = load_helper(ROOT, "sandbox_helper_1815i")
SCRIPT = (ROOT / "tests" / "sandbox-canary-1.18.15.sh").read_text(encoding="utf-8")
LONG = "credential source folder is gone while the run is still active"
must(len(LONG) == 62, len(LONG))  # over the 60-character cut (the plan said 69; it is 62)

# ---- format_table cuts the label; the ROW line does not lose the row
table = [{"wall": "Credential", "attack": LONG, "expected": "absent", "actual": "absent", "verdict": "OK"},
         {"wall": "Limits", "attack": "memory beyond MemoryMax", "expected": "e", "actual": "a", "verdict": "ATTACK SUCCEEDED"}]
printed = sh.format_table(table)
must(LONG not in printed and LONG[:60] in printed, "the table still cuts the label at 60 characters")
lines = sh.row_lines(table)
must(lines == ["ROW credential-source-folder-is-gone-while-t OK", "ROW memory-beyond-memorymax ATTACK SUCCEEDED"], lines)
explicit = sh.credential_cleanup_rows(False, {"ExecStartPre": "", "ExecStartPost": "", "ExecStopPost": ""}, True)
must(sh.row_lines(explicit) == ["ROW credential-source-gone OK", "ROW no-host-command-property OK"], sh.row_lines(explicit))
must(sh.row_lines(sh.credential_cleanup_rows(True, {}, False)) == ["ROW credential-source-gone NOT RUN", "ROW no-host-command-property NOT RUN"], "NOT RUN rows keep their ids")

# ---- ids: valid, short, unique; a repeat gets a suffix; a bad explicit id falls back to the slug
rows = [{"attack": "same label", "verdict": "OK"}, {"attack": "same label", "verdict": "OK"}, {"attack": "Same  Label!", "verdict": "OK"},
        {"attack": "x" * 100, "verdict": "OK"}, {"attack": "x" * 100, "verdict": "OK"}, {"attack": "///", "verdict": "OK"},
        {"attack": "a", "id": "Bad Id/../", "verdict": "OK"}, {"attack": "b", "id": "good-id", "verdict": "OK"}]
ids = sh.assign_row_ids(rows)
must(len(set(ids)) == len(ids) and all(sh.ROW_ID_RE.match(i) and len(i) <= 40 for i in ids), ids)
must(ids[0] == "same-label" and ids[1] == "same-label-2" and ids[2] == "same-label-3" and ids[5] == "row" and ids[6] == "a" and ids[7] == "good-id", ids)
must(ids[3] == "x" * 40 and ids[4] == "x" * 38 + "-2", ids)

# ---- every label of the helper and the runner is unique as an id
helper_source = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
runner_source = (ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8")
labels = set(re.findall(r'"attack": "([^"]+)"', helper_source)) | set(re.findall(r'\brow\(\s*"([^"{]+)"', runner_source))
labels |= {"view " + folder for folder in sh.CANARY_VIEW_FOLDERS} | {"/ lists only the allowed set", "write /run"}
for exact, _prefixes in sh.CANARY_REQUIRED.values():
    labels |= set(exact)
labels |= {f"loopback 127.0.0.53:{port}" for port in sh.CANARY_STUB_PORTS}
labels = {label for label in labels if not label.endswith(" ")}
slugs = {}
for label in sorted(labels):
    slugs.setdefault(sh.row_slug(label), []).append(label)
clashes = {slug: found for slug, found in slugs.items() if len(found) > 1}
must(len(labels) > 60, len(labels))
must(not clashes, clashes)
# the ids of the explicit rows are not the slug of any other label
must("credential-source-gone" not in slugs and "no-host-command-property" not in slugs, "an explicit id is never also the slug of another label")

# ---- the script: no step 4x lookup relies on a label longer than 60 characters
lookups = re.findall(r"""row_ok_label\s+(?:'([^']+)'|"([^"]+)")""", SCRIPT) + re.findall(r"""grep -F\s+(?:'([^']+)'|"([^"]+)")""", SCRIPT)
labels_used = [a or b for a, b in lookups]
must(len(labels_used) >= 12, labels_used)
for text in labels_used:
    must(len(text) <= 60, (len(text), text))
for old in ("credential source folder is gone while the run is still active", "no host command property on the live unit"):
    must("grep -F '" + old + "'" not in SCRIPT and 'grep -F "' + old + '"' not in SCRIPT, old)
must("row_ok credential-source-gone" in SCRIPT and "row_ok no-host-command-property" in SCRIPT, "4t and 4u read the ROW lines by id")
# every verdict lookup of a step 4 row goes through the ROW lines: no `grep -F <label> | grep OK` is left
must(not re.search(r"grep -F [^|]*\"\$CANARY_OUT\" \| grep -Eq 'OK\[\[:space:\]\]\*\$'", SCRIPT), "no label-then-OK lookup is left")
# the ROW lines are not counted twice
for word in ("ATTACKS=", "NOTRUN=", "SKIPPED_SECURITY="):
    must("^ROW " in SCRIPT[SCRIPT.index(word):][:200], word)

# ---- the bash slug in the script gives the same ids as the helper's
slug_line = next(line for line in SCRIPT.splitlines() if line.startswith("slug() {"))
samples = ["credential arrives", "unix socket creation refused (stream)", "view /usr/local/lib/tec-tac/sandbox", "/ lists only the allowed set",
           "another dynamic user reads the credential file", "loopback 127.0.0.53:4433", "child process with stdio pipes", "view /", LONG]
NL = chr(10)
script = slug_line + NL + NL.join(f"slug '{sample}'" for sample in samples) + NL  # the whole script goes through stdin: no quoting between Windows and bash
bash = subprocess.run(["bash", "-s"], input=script.encode(), capture_output=True, check=False)  # bytes: no CRLF translation
must(bash.returncode == 0, bash.stderr)
got = bash.stdout.decode().split(NL)[:len(samples)]
must(got == [sh.row_slug(s) for s in samples], (got, [sh.row_slug(s) for s in samples]))

# ---- run_canary_command: one ROW line per row, after the table and before the totals line
fake_table = [{"wall": "W", "attack": f"attack {n}", "expected": "e", "actual": "a", "verdict": "OK"} for n in range(5)] + [explicit[0]]
saved = (sh.run_canary, sh.ensure_layout, sh._write_root_file, sh.append_audit)
sh.run_canary, sh.ensure_layout, sh._write_root_file, sh.append_audit = (lambda: fake_table), (lambda: None), (lambda *a, **k: None), (lambda *a, **k: None)
out = io.StringIO()
try:
    with contextlib.redirect_stdout(out):
        sh.run_canary_command()
finally:
    sh.run_canary, sh.ensure_layout, sh._write_root_file, sh.append_audit = saved
printed_lines = out.getvalue().splitlines()
row_positions = [i for i, line in enumerate(printed_lines) if line.startswith("ROW ")]
totals = next(i for i, line in enumerate(printed_lines) if " OK, " in line and "ATTACK SUCCEEDED" in line and not line.startswith("ROW "))
must(len(row_positions) == len(fake_table) and max(row_positions) < totals, (row_positions, totals))
must(printed_lines[row_positions[-1]] == "ROW credential-source-gone OK", printed_lines[row_positions[-1]])

# ---- the canary.json record keeps its fields
passed, counts = sh.canary_summary(fake_table + [dict(table[1])])
record = sh.canary_record(fake_table + [dict(table[1])], passed, counts)
must(all(set(r) == {"wall", "attack", "verdict"} for r in record["failing"]) and len(record["failing"]) == 1, record)
for name in ("scripts/sandbox-helper.py", "tests/sandbox-canary-1.18.15.sh"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox canary ids 1.18.15")
