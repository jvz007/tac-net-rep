#!/usr/bin/env python3
"""1.17.57 regression: the AD-40 extension to WinUpdatePolicy is recorded (Johan, Q-APM4 option d, 19 October 2026).

A decision record, so no Django. The project documents sit above the package; when they are not reachable
(the signed zip has no docs/ at that level) that part is skipped with a note.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.17.57"
failures: list[str] = []


def must(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


def _at_least(text: str) -> bool:  # at least 1.17.57, ignoring a -N rebuild suffix (the later bumps and rebuilds keep this record true)
    return tuple(int(x) for x in text.strip().split("-")[0].split(".")) >= (1, 17, 57)


version_text = (ROOT / "VERSION").read_text(encoding="utf-8")
must(_at_least(version_text), "VERSION is at least 1.17.57")
must(_at_least(json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"]), "tec_tac_package.json is at least 1.17.57")

notes = next((p for p in (ROOT / f"RELEASE_NOTES_{VERSION}.md", ROOT / "docs" / "releases" / f"RELEASE_NOTES_{VERSION}.md") if p.is_file()), None)
must(notes is not None, "release notes exist at the root or in docs/releases")
text = notes.read_text(encoding="utf-8") if notes else ""
low = text.lower()
must("decision record" in low and "no code change" in low, "notes say decision record and no code change")
must("PASS if the version shows 1.17.57 and nothing else changed." in text, "notes carry the dev-server PASS line")
must("## Module-facing change" in text, "notes carry the module-facing heading")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.56.md").is_file(), "1.17.56 notes moved to docs/releases")
must(not (ROOT / "RELEASE_NOTES_1.17.56.md").exists(), "1.17.56 notes are not left at the root")

if version_text.strip() == VERSION:  # the no-code claim is about the 1.17.57 build itself
    framework_hits = [p for p in (ROOT / "framwork").rglob("*.py") if VERSION in p.read_text(encoding="utf-8", errors="ignore")]
    must(not framework_hits, "no file under framwork/ names 1.17.57")

project = ROOT.parents[1]
standard = project / "docs" / "tec-tac-module-standard.md"
if standard.is_file():
    std = standard.read_text(encoding="utf-8")
    ad = (project / "docs" / "review-accepted-decisions.md").read_text(encoding="utf-8")
    req = (project / "reviews" / "requests" / "core.md").read_text(encoding="utf-8")
    must("WinUpdatePolicy" in std and "Agent model" in std, "standard names WinUpdatePolicy and the Agent model")
    row = next((line for line in ad.splitlines() if line.startswith("| 40 |")), "")
    must("WinUpdatePolicy" in row and "Agent model" in row, "AD row 40 names WinUpdatePolicy and the Agent model")
    must(ad.count("\n| 40 |") == 1, "AD row 40 is still one row (later rows such as AD-41 do not touch it)")
    must("record the AD-20 amendment for patchmanagement" not in req, "the option (a) request is gone")
    must("reviews/requests/core.md`, \"read contract for Windows update rows\"" not in std.replace("core.md\", ", "core.md`, "), "standard no longer points at core.md for the read contract")
else:
    print("NOTE project documents not reachable from this tree; document checks skipped")

if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("OK")
