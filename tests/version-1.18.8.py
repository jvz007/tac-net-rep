#!/usr/bin/env python3
"""Regression: Core 1.18.8 (core.sandbox Patch A) keeps every module-facing name, the kill switch off and the sudo rule as it was."""
import importlib
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:  # Windows: only version_satisfies is used here
        sys.modules["fcntl"] = types.ModuleType("fcntl")
# Register the package without running its __init__ (no Django needed).
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
module = importlib.import_module("tec_tac.module_state")
satisfies = module.version_satisfies

raw = (ROOT / "VERSION").read_bytes()
assert raw == b"1.18.8\n", raw

package = json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))
assert package["version"] == "1.18.8"
assert package["id"] == "tec-tac"
assert package["type"] == "tec-tac-framework"

notes = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md"))
assert notes == ["RELEASE_NOTES_1.18.8.md"], notes
for v in ("1.17.124", "1.18.0", "1.18.1", "1.18.2", "1.18.3", "1.18.4", "1.18.5", "1.18.6", "1.18.7"):
    assert (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{v}.md").is_file(), v
assert (ROOT / "tests" / "legacy" / "version-1.18.7.py").is_file() and not (ROOT / "tests" / "version-1.18.7.py").exists()
legacy = (ROOT / "tests" / "legacy" / "version-1.18.7.py").read_text(encoding="utf-8")
assert "parents[2]" in legacy and 'b"1.18.7-1' not in legacy and "RELEASE_NOTES_1.18.7-1" not in legacy, "the legacy test is corrected"

text = (ROOT / "RELEASE_NOTES_1.18.8.md").read_text(encoding="utf-8")
assert text.count("## Module-facing") == 1
for needle in ("BEFORE you update", "sudo bash tests/sandbox-canary-1.18.8.sh before", "ls -l /usr/local/sbin/tec-tac-sandbox", "PASS", "FAIL", "ATTACK SUCCEEDED", "BEFORE RUN: N ATTACK SUCCEEDED",
               "ALL CANARY STEPS PASSED", "0 rows `ATTACK SUCCEEDED`", "0 rows `NOT RUN`", "public tcp 443", "ls -ld /usr/local/lib/tec-tac/sandbox/root", "--status", "\"enabled\": false",
               "systemctl status tec-tac-sandbox.slice", "audit.jsonl", "canary.json", "status.json", "uname -r", "systemctl --version", "ls -la /usr/local/lib/tec-tac/sandbox/root",
               "What changed and why", "Assumptions", "What is not in this release", "What could not be run on the PC", "Patch A of three", "Patch B", "Patch C",
               "/rmmbackups", "scp ", "<your dev02 login>", "/root/canary-1.18.8", "Differences from the plan", "nested", "memory.events"):
    assert needle in text, needle
assert text.index("BEFORE you update") < text.index("## What changed and why"), "the canary-first block opens the notes"
assert text.startswith("# Tec-Tac Framework 1.18.8\n\nDate: 18 November 2026.")
assert "tec-tac-sandbox --start" in text and "does not close" in text

helper = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
django = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
assert re.search(r"^SANDBOX_ENABLED = False\b", helper, re.MULTILINE), "the helper's kill switch is off"
assert re.search(r"^SANDBOX_ENABLED = False\b", django, re.MULTILINE), "the Django side's kill switch is off"
assert re.search(r'^CAPABILITY_VERSION = "1\.0\.0"$', django, re.MULTILINE), "core.sandbox is still 1.0.0"
install = (ROOT / "install.sh").read_text(encoding="utf-8")
rule = [line for line in install.splitlines() if "NOPASSWD: ${SANDBOX_HELPER}" in line]
assert rule == ["${TACTICAL_USER} ALL=(root) NOPASSWD: ${SANDBOX_HELPER} --start, ${SANDBOX_HELPER} --stop, ${SANDBOX_HELPER} --status"], rule

for constraint in (">=1.17.124,<2.0.0", ">=1.17.13,<2.0.0", ">=1.17.109,<2.0.0", ">1.17.124-9"):
    assert satisfies("1.18.8", constraint), constraint
assert not satisfies("1.18.8-1", "<1.18.8")
assert satisfies("1.18.8", ">=1.18.5,<2.0.0")
assert satisfies("1.18.8-1", ">1.18.8")
assert satisfies("1.18.8", ">1.18.7")

print("version 1.18.8 regression: PASS")
