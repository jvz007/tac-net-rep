#!/usr/bin/env python3
"""1.17.35: the UI source pin in tests/contract-export-1.17.18.py is whitespace-tolerant.

The test used to pin the exact indent of the shell's context object ('        tacticalScope,\\n', eight spaces). UI 0.12.105 has six
spaces, so the test failed although the UI was right (src/main.js passes tacticalScope to authenticated modules). The layout is not the
contract, so the pin is now the three names in order, whatever the indent or the line ending.

Covered: the regex matches 4, 6 and 8 space indents and a Windows (CRLF) line ending; it does not match when tacticalScope is missing; the
fixed test runs and exits 0 when workspace/ui/src/main.js is beside this repository (skipped otherwise); the other two Core UI-source tests
still run and exit 0 when the UI is beside this repository.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "tests/contract-export-1.17.18.py"
PIN = re.compile(r"hasTacticalPermission,\s*\n\s*tacticalScope,\s*\n\s*tacticalOperation,")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def shell_block(indent: int, newline: str = "\n", missing: bool = False) -> str:
    pad = " " * indent
    lines = [f"{pad}hasTacticalPermission,", f"{pad}tacticalOperation," if missing else f"{pad}tacticalScope,",
             f"{pad}tacticalOperation,"]
    return newline.join(lines) + newline


for indent in (4, 6, 8):
    must(PIN.search(shell_block(indent)), f"a {indent} space indent matches")
must(PIN.search(shell_block(6, "\r\n")), "a Windows line ending matches")
must(not PIN.search(shell_block(6, missing=True)), "tacticalScope missing does not match")

source = TEST.read_text(encoding="utf-8")
must("hasTacticalPermission,\\s*\\n\\s*tacticalScope,\\s*\\n\\s*tacticalOperation," in source, "the fixed test uses the tolerant pin")
must("        tacticalScope,\\n" not in source, "the eight space pin is gone")

if (ROOT.parent / "ui" / "src" / "main.js").is_file():
    result = subprocess.run([sys.executable, str(TEST)], capture_output=True, text=True, encoding="utf-8", check=False)
    must(result.returncode == 0, f"tests/contract-export-1.17.18.py exits 0 against the UI: {result.stdout}{result.stderr}")
    for other in ("tests/contract-export-1.17.14.py", "tests/contract-browser-doc-cells-1.17.19.py"):
        result = subprocess.run([sys.executable, str(ROOT / other)], capture_output=True, text=True, encoding="utf-8", check=False)
        must(result.returncode == 0, f"{other} exits 0: {result.stdout}{result.stderr}")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

print("[TEST] PASS contract export UI pin 1.17.35")
