#!/usr/bin/env python3
"""1.17.119 regression, rewritten for 1.17.120: every word after '--' in the systemd-run call reaches the program as validated.

1.17.119 escaped both '$' and '%' ('$$', '%%') and asked dev02 whether '%%' arrives as '%'. The review held that open question as a Medium
finding, so 1.17.120 fails closed: ``_exec_escape`` escapes '$' only, and a '%' in any command word is refused before a unit is started
(tests/sandbox-percent-refuse-1.17.120.py). Here:

* the escape table ('$' doubled, '%' left alone, so ``_exec_escape('a$HOME b%h$$') == 'a$$HOME b%h$$$$'``);
* the round trip through the fake systemd-run of the harness, which reduces '$$' only (a real child shows it);
* the ``--property=`` and ``--setenv=`` items, the separators and ``--unit=`` stay unescaped; the property list is unchanged;
* the canary's escape step (step 2c of tests/sandbox-canary-1.17.120.sh) runs here against the repo helper with a stand-in program that
  reduces '$$' only, so a wrong escape is caught offline too. That is NOT real systemd; the dev02 canary is the real proof.

Not runnable here: real systemd.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_119b", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
sh, must, make_runner, BASE, header, start, joined = H.sh, H.must, H.make_runner, H.BASE, H.header, H.start, H.joined

TABLE = [("plain", "plain"), ("$HOME", "$$HOME"), ("${X}", "$${X}"), ("$$", "$$$$"), ("$1x", "$$1x"), ("a$HOME b${X} $$", "a$$HOME b$${X} $$$$"),
         ("a$HOME b%h$$", "a$$HOME b%h$$$$"), ("", ""), ("a\nb", "a\nb"), ("%h", "%h"), ("100%", "100%")]
for plain, escaped in TABLE:
    must(sh._exec_escape(plain) == escaped, (plain, sh._exec_escape(plain)))
must(sh._exec_escape("a$HOME b%h$$") == "a$$HOME b%h$$$$", "the documented example")


def systemd_unescape(text):
    return re.sub(r"\$\$", "$", text)


for plain, _ in TABLE:
    if "%" not in plain:
        must(systemd_unescape(sh._exec_escape(plain)) == plain, plain)
must("%%" not in sh._exec_escape("%h") and sh._exec_escape("%") == "%", "'%' is never doubled")
docstring = sh._exec_escape.__doc__
must("'%' is not escaped" in docstring and "refused" in docstring, "the docstring says what happens to '%'")

RUN_ID = "ef" * 16
VALUE = "a$HOME b${X}$$"
row = make_runner("ai.chat", parameters={"text": {"type": "string", "max_length": 50}}, argv=["--lit", "x$Y z", "--t", {"param": "text"}],
                  environment={"MSG": "a b $X %h"})
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path) == str(sh.LAUNCHER_FILE) or str(path).startswith("/opt/tec-tac")
argv = sh.build_argv(row, RUN_ID, {"text": VALUE}, credential_names=[], exists=EXISTS)
cut = argv.index("--")
before, after = argv[:cut], argv[cut + 1:]
must(after[-4:] == ["--lit", "x$$Y z", "--t", sh._exec_escape(VALUE)], after)
must(after.count("--") == 1 and "--" in after, "inner separator kept")
for item in after:
    must("$" not in item.replace("$$", ""), ("unescaped '$'", item))
must([systemd_unescape(i) for i in after][-4:] == ["--lit", "x$Y z", "--t", VALUE], "round trip")
# options before the separator are untouched ('%' in an environment value is a --setenv= item, not a command word)
must(f"--unit={sh.unit_name(RUN_ID)}" in before and "--setenv=MSG=a b $X %h" in before, before)
props = [i for i in before if i.startswith("--property=")]
expected = ["--property=" + p for p in sh.build_properties(row, RUN_ID, credential_names=[], exists=EXISTS)]
must(props == expected, "properties unchanged")

# real child through the fake systemd-run: the program sees the validated value verbatim
make_runner("ai.echo", body="print(sys.argv[1:])", parameters={"text": {"type": "string", "max_length": 50}},
            argv=["--lit", "x$Y z", {"param": "text"}], environment={"MSG": "a b $X"})
code, frames = start(header("ai.echo", parameters={"text": VALUE}))
must(joined(frames, "out").decode().strip() == repr(["--lit", "x$Y z", VALUE]), joined(frames, "out"))
logs = sorted((BASE / "log").glob("*.json"), key=lambda p: p.stat().st_mtime)
logged = json.loads(logs[-1].read_text(encoding="utf-8"))
must(logged["setenv"].get("MSG") == "a b $X", logged["setenv"])

# ---- the canary's escape step, offline: the snippet of step 2c of the .sh runs against the repo helper
script = (H.ROOT / "tests" / "sandbox-canary-1.17.120.sh").read_text(encoding="utf-8")
step = script[script.index("== step 2c"):script.index("== step 3")]
found = re.search(r"<<'PY'\n(.*?)\nPY\n", step, re.S)
must(found, "step 2c holds the python snippet")
snippet = found.group(1)
must("_exec_escape" in snippet and "SourceFileLoader" in snippet, "the snippet loads the helper's own _exec_escape")
words = re.search(r"WORDS=\((.*)\)\n", step).group(1)
WORDS = ["plain", "a$HOME b${X} $$", "$$", "$1x"]
for word in WORDS:
    must("'" + word + "'" in words, ("the step's WORDS list holds", word))
run = subprocess.run([sys.executable, "-I", "-c", snippet, str(H.ROOT / "scripts" / "sandbox-helper.py")], capture_output=True, text=True, check=False)
must(run.returncode == 0, run.stderr[-500:])
escaped = run.stdout.splitlines()
must(len(escaped) == len(WORDS), escaped)
arrived = [systemd_unescape(line) for line in escaped]  # the stand-in for the program: reduces '$$' only (NOT real systemd)
must(arrived == WORDS, (escaped, arrived))
# a wrong escape (one that forgets '$') would be caught by the same comparison
must([systemd_unescape(w) for w in WORDS] != WORDS, "the unescaped words do not survive the stand-in, so the comparison can fail")

print("[TEST] PASS sandbox exec escape 1.17.120")
