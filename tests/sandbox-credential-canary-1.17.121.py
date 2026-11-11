#!/usr/bin/env python3
"""1.17.121 regression: the foreign-reader credential canary row can no longer pass when the credential file does not exist.

1.17.120 held finding (Medium): the probe program printed DENIED for every OSError, so a missing file (or a unit that was already gone) counted as
'denied' and the row was OK. Now:

* the probe program prints DENIED only for PermissionError (EACCES/EPERM), MISSING for a missing path, ERROR for anything else; never content or path;
* _foreign_credential_probe returns only READ, DENIED or MISSING words, everything else is '';
* a root-side pre-check (file exists as root and the unit is active) runs first; if it fails the probe is not started and the row is NOT RUN;
* after the probe the check runs again; a DENIED with the file gone is NOT RUN;
* DENIED -> OK, READ -> ATTACK SUCCEEDED, MISSING, '', error, exception -> NOT RUN. NOT RUN fails the canary through canary_summary.

Not runnable here: real systemd, root, Linux. tests/sandbox-canary-1.17.121.sh proves it on dev02.
"""
from __future__ import annotations

import base64
import builtins
import contextlib
import errno
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_121", "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
WALL = "another dynamic user reads the credential file"


# ---- (a) the probe program
def run_program(path, opener=None):
    out = io.StringIO()
    code = compile(sh._FOREIGN_READ, "foreign-read", "exec")
    real_open = builtins.open
    if opener:
        builtins.open = opener
    try:
        with contextlib.redirect_stdout(out):
            sys.argv = ["-c", str(path)]
            exec(code, {})  # noqa: S102 - the probe program under test
    finally:
        builtins.open = real_open
    return out.getvalue()


secret = BASE / "foreign-secret-121"
secret.write_text("TOPSECRET", encoding="utf-8")
text = run_program(secret)
must(text.strip() == "READ" and "TOPSECRET" not in text and str(secret) not in text, text)


def raiser(code):
    def opener(*args, **kwargs):
        if code in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise PermissionError(code, "denied")
        raise OSError(code, "other")
    return opener


for number in (errno.EACCES, errno.EPERM):
    text = run_program(secret, raiser(number))
    must(text.strip() == "DENIED" and str(secret) not in text, (number, text))
text = run_program(BASE / "no-such-credential-121")
must(text.strip() == "MISSING" and "no-such" not in text, text)
text = run_program(secret / "child")  # a path below a file: NotADirectoryError
must(text.strip() == "MISSING", text)
text = run_program(secret, raiser(errno.EIO))
must(text.strip() == "ERROR", text)
text = run_program(secret, raiser(errno.EROFS))  # a PermissionError with another errno is not a denial
must(text.strip() == "ERROR", text)
text = run_program(BASE)  # a directory: another OSError (IsADirectoryError, or PermissionError on Windows)
must(text.strip() in ("ERROR", "DENIED"), text)

# ---- (b) the probe function
calls = []


class StubRunner:
    answer = (0, "DENIED\n", "")

    def run_unit(self, name, properties, command, *, timeout=30):
        calls.append(command)
        return StubRunner.answer


real_runner = sh.UnitRunner
sh.UnitRunner = StubRunner
try:
    for answer, want in (((0, "DENIED\n", ""), "DENIED"), ((0, "READ\n", ""), "READ"), ((0, "MISSING\n", ""), "MISSING"),
                         ((1, "DENIED\n", "x"), ""), ((0, "", ""), ""), ((0, "ERROR\n", ""), ""), ((0, "odd\n", ""), ""), ((127, "", "no systemd-run"), "")):
        StubRunner.answer = answer
        must(sh._foreign_credential_probe("tectac-sbx-abc") == want, (answer, want))
finally:
    sh.UnitRunner = real_runner

# ---- (c) to (g) the rows
TOKEN = {}


def collect(group, plan, **kwargs):
    TOKEN["token"] = plan["credential_token"]
    stdout = ("CANARYROW\tcredential arrives\tOK\tarrived\nCANARYROW\tcredential mode\tOK\t0o440\n"
              "CANARYROW\tcredential not in environment\tOK\tabsent\n").encode()
    return {"stdout": stdout, "stderr": b"", "refused": None, "run_id": kwargs.get("run_id", ""),
            "end": {"reason": "exited", "exit": 0, "credential_b64": base64.b64encode(("refreshed-" + plan["credential_token"]).encode()).decode()}}


sh._holders_search = lambda token, unit: []
status = {"ready": True, "resolver": "127.0.0.53", "resolvers": ["127.0.0.53"]}


def rows_for(probe, ready):
    rows = sh._credential_rows(collect, status, probe, ready)
    found = [r for r in rows if r["attack"] == WALL]
    must(len(found) == 1, rows)
    text = json.dumps(rows)
    must(TOKEN["token"] not in text and "/run/credentials" not in text, "the rows print neither the token nor the credential path")
    return rows, found[0]


counter = {"n": 0}


def counting(answer):
    def probe(unit):
        counter["n"] += 1
        return answer
    return probe


def broken(unit):
    raise OSError("x")


# (c) pre-check says no (file missing, unit not active, pre-check raises): the probe is not started
for label, ready in (("file or unit missing", lambda unit: False), ("pre-check raises", broken)):
    counter["n"] = 0
    rows, row = rows_for(counting("DENIED"), ready)
    must(counter["n"] == 0, (label, "the probe must not start"))
    must(row["verdict"] == "NOT RUN" and "not there" in row["actual"], (label, row))
    passed, counts = sh.canary_summary(rows)
    must(passed is False and counts["NOT RUN"] == 1, (label, counts))

# (d) MISSING never gives OK
rows, row = rows_for(counting("MISSING"), lambda unit: True)
must(row["verdict"] == "NOT RUN" and "no credential file" in row["actual"], row)
must(sh.canary_summary(rows)[0] is False, "MISSING fails the canary")

# (e) DENIED but the file is gone afterwards
state = {"n": 0}


def vanishing(unit):
    state["n"] += 1
    return state["n"] == 1


rows, row = rows_for(counting("DENIED"), vanishing)
must(row["verdict"] == "NOT RUN" and "proves nothing" in row["actual"], row)
must(sh.canary_summary(rows)[0] is False, "a vanished file fails the canary")

# (f) the clean outcomes
rows, row = rows_for(counting("DENIED"), lambda unit: True)
must(row["verdict"] == "OK" and row["actual"] == "denied", row)
passed, counts = sh.canary_summary(rows)
must(passed is True and counts["NOT RUN"] == 0 and counts["ATTACK SUCCEEDED"] == 0, counts)
rows, row = rows_for(counting("READ"), lambda unit: True)
must(row["verdict"] == "ATTACK SUCCEEDED", row)
for label, probe in (("exception", lambda unit: (_ for _ in ()).throw(RuntimeError("boom"))), ("empty", lambda unit: ""), ("odd", lambda unit: "maybe")):
    rows, row = rows_for(probe, lambda unit: True)
    must(row["verdict"] == "NOT RUN", (label, row))

# (h) the default pre-check: file exists and the unit is active
seen = []
real_systemctl, real_exists = sh.systemctl, os.path.exists
sh.systemctl = lambda *args: seen.append(args) or (0, "active\n", "")
try:
    os.path.exists = lambda path: True
    must(sh._credential_file_ready("tectac-sbx-abc") is True, "file and unit present")
    must(seen and seen[-1][:2] == ("is-active", "tectac-sbx-abc.service"), seen)
    os.path.exists = lambda path: False
    must(sh._credential_file_ready("tectac-sbx-abc") is False, "file missing")
    sh.systemctl = lambda *args: (3, "inactive\n", "")
    os.path.exists = lambda path: True
    must(sh._credential_file_ready("tectac-sbx-abc") is False, "file present but unit not active")
finally:
    sh.systemctl, os.path.exists = real_systemctl, real_exists

print("[TEST] PASS sandbox credential canary 1.17.121")
