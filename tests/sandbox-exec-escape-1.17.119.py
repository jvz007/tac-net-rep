#!/usr/bin/env python3
"""1.17.119 regression: every word after '--' in the systemd-run call reaches the program as validated (held Low finding on 1.17.118).

systemd expands '$VAR' and '%specifier' in ExecStart. build_argv escapes '$' and '%' in the command words only ('$$', '%%'); the
--property= and --setenv= items, the separators and --unit= are left alone; the property list is unchanged. The fake systemd-run of the
harness undoes the escape like systemd does, so a real child shows the round trip.

Not runnable here: real systemd. tests/sandbox-canary-1.17.118.sh on dev02 must be run with the one-line manual check in the release notes.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_119b", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
sh, must, make_runner, BASE, header, start, joined = H.sh, H.must, H.make_runner, H.BASE, H.header, H.start, H.joined

TABLE = [("plain", "plain"), ("$HOME", "$$HOME"), ("${X}", "$${X}"), ("$$", "$$$$"), ("%h", "%%h"), ("%%", "%%%%"), ("%n%H", "%%n%%H"),
         ("a$HOME b%h$$", "a$$HOME b%%h$$$$"), ("", ""), ("a\nb", "a\nb")]
for plain, escaped in TABLE:
    must(sh._exec_escape(plain) == escaped, (plain, sh._exec_escape(plain)))


def systemd_unescape(text):
    return re.sub(r"\$\$|%%", lambda m: m.group()[0], text)


for plain, _ in TABLE:
    must(systemd_unescape(sh._exec_escape(plain)) == plain, plain)

RUN_ID = "ef" * 16
VALUE = "a$HOME b${X}%h%%"
row = make_runner("ai.chat", parameters={"text": {"type": "string", "max_length": 50}}, argv=["--lit", "x$Y%z", "--t", {"param": "text"}],
                  environment={"MSG": "a b $X %h"})
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path) == str(sh.LAUNCHER_FILE) or str(path).startswith("/opt/tec-tac")
argv = sh.build_argv(row, RUN_ID, {"text": VALUE}, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)
cut = argv.index("--")
before, after = argv[:cut], argv[cut + 1:]
must(after[-4:] == ["--lit", "x$$Y%%z", "--t", sh._exec_escape(VALUE)], after)
must(after.count("--") == 1 and "--" in after, "inner separator kept")
for item in after:
    stripped = item.replace("$$", "").replace("%%", "")
    must("$" not in stripped and "%" not in stripped, ("unescaped", item))
must([systemd_unescape(i) for i in after][-4:] == ["--lit", "x$Y%z", "--t", VALUE], "round trip")
# options before the separator are untouched
must(f"--unit={sh.unit_name(RUN_ID)}" in before and "--setenv=MSG=a b $X %h" in before, before)
props = [i for i in before if i.startswith("--property=")]
expected = ["--property=" + p for p in sh.build_properties(row, RUN_ID, resolvers=["127.0.0.53"], credential_names=[], exists=EXISTS)]
must(props == expected, "properties unchanged")

# real child through the fake systemd-run: the program sees the validated value verbatim
make_runner("ai.echo", body="print(sys.argv[1:])", parameters={"text": {"type": "string", "max_length": 50}},
            argv=["--lit", "x$Y%z", {"param": "text"}], environment={"MSG": "a b $X"})
code, frames = start(header("ai.echo", parameters={"text": VALUE}))
must(joined(frames, "out").decode().strip() == repr(["--lit", "x$Y%z", VALUE]), joined(frames, "out"))
logs = sorted((BASE / "log").glob("*.json"), key=lambda p: p.stat().st_mtime)
logged = json.loads(logs[-1].read_text(encoding="utf-8"))
must(logged["setenv"].get("MSG") == "a b $X", logged["setenv"])
print("[TEST] PASS sandbox exec escape 1.17.119")
