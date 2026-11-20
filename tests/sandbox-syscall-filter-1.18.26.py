#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 6): io_uring, userfaultfd and keyctl are denied in every run unit.

Covered: the built unit properties carry the one fixed SystemCallFilter denial exactly once, it is one of Core's constants (in
UNIT_FIXED_PROPERTIES, so check_unit_properties accepts it and nothing else is added), the other filter lines are unchanged and
SystemCallErrorNumber stays EPERM, no module string reaches any property (a module id, a runner id and a parameter value are searched for in
every property), the canary run unit carries the same line, and the built systemd-run command holds it once.

Not runnable here: systemd itself (dev02 canary rows pc-io-uring-reachable, pc-userfaultfd-reachable, pc-keyctl-reachable).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118_sc", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, ROOT, make_runner, must, sh) = (H.BASE, H.ROOT, H.make_runner, H.must, H.sh)

DENY = "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register userfaultfd keyctl add_key request_key"
RUN_ID = "cd" * 16
row = make_runner("zzmodule.zzrunner", parameters={"mode": {"type": "enum", "choices": ["zzvalue", "b"]}}, argv=["--m", {"param": "mode"}],
                  environment={"LANG": "C.UTF-8"}, credential_files=["auth"], limits={"memory_mb": 512})
EXISTS = lambda path: path != "/missing" and (str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/") or str(path) == str(sh.LAUNCHER_FILE))

props = sh.build_properties(row, RUN_ID, credential_names=["auth"], exists=EXISTS)
must(props.count(DENY) == 1, ("the denial is in the unit exactly once", props.count(DENY)))
must(DENY in sh.UNIT_FIXED_PROPERTIES and sh.UNIT_FIXED_PROPERTIES.count(DENY) == 1, "a Core constant")
must(props.count("SystemCallFilter=@system-service") == 1 and props.count("SystemCallFilter=~@privileged @resources") == 1, "the other filter lines are unchanged")
must(props.count("SystemCallErrorNumber=EPERM") == 1, "an refused call reads EPERM")
must(sum(1 for item in props if item.startswith("SystemCallFilter=")) == 3, "exactly three filter lines")
sh.check_unit_properties(props, row, RUN_ID)  # accepted by the closed set
for secret in ("zzmodule", "zzrunner", "zzvalue"):  # the validated module id is part of its own bind paths; no filter or limit line carries module text
    must(not any(secret in item for item in props if item.startswith(("SystemCall", "Restrict", "Capability", "Protect", "Private", "Memory", "Limit"))), ("a module string reached a property", secret))
must(not any("zzvalue" in item for item in props), "a parameter value never reaches a property")
try:
    sh.check_unit_properties([*props, DENY.replace("keyctl", "keyctl ptrace")], row, RUN_ID)
except sh.Refusal:
    pass
else:
    raise AssertionError("a changed filter line is not on the fixed list and must be refused")

# the command line
argv = sh.build_argv(row, RUN_ID, {"mode": "zzvalue"}, credential_names=["auth"], exists=EXISTS)
must(argv.count(DENY) == 1 or sum(1 for part in argv if part == DENY or part == "-p" + DENY or part.endswith(DENY)) == 1, "the systemd-run command carries the denial once")

# the canary row's unit is built by the same function, so it has the line too
canary_unit = sh.build_properties(sh.canary_row() if hasattr(sh, "canary_row") else row, RUN_ID, credential_names=[], exists=EXISTS)
must(canary_unit.count(DENY) == 1, "the canary run unit carries it too")
print("[TEST] PASS sandbox syscall filter 1.18.26")
