#!/usr/bin/env python3
"""1.17.59 regression: AD-37 is extended to a premium module that honours AD-20 (Johan, Q-APM8 answer a, 20 October 2026).

A decision record, so no Django. The project documents sit above the package; when they are not reachable
(the signed zip has no docs/ at that level) that part is skipped with a note.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.17.59"
failures: list[str] = []


def must(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


def _at_least(text: str) -> bool:  # at least 1.17.59, ignoring a -N rebuild suffix (later bumps and rebuilds keep this record true)
    return tuple(int(x) for x in text.strip().split("-")[0].split(".")) >= (1, 17, 59)


version_text = (ROOT / "VERSION").read_text(encoding="utf-8")
must(_at_least(version_text), "VERSION is at least 1.17.59")
must(_at_least(json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"]), "tec_tac_package.json is at least 1.17.59")

notes = next((p for p in (ROOT / f"RELEASE_NOTES_{VERSION}.md", ROOT / "docs" / "releases" / f"RELEASE_NOTES_{VERSION}.md") if p.is_file()), None)
must(notes is not None, "release notes exist at the root or in docs/releases")
text = notes.read_text(encoding="utf-8") if notes else ""
must("decision record" in text.lower(), "notes say decision record")
must("## Module-facing change" in text, "notes carry the module-facing heading")
must("outside the signed package" in text or "outside this package" in text, "notes say the documents sit outside the package")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.58.md").is_file(), "1.17.58 notes moved to docs/releases")
must(not (ROOT / "RELEASE_NOTES_1.17.58.md").exists(), "1.17.58 notes are not left at the root")

project = ROOT.parents[1]
standard = project / "docs" / "tec-tac-module-standard.md"
if standard.is_file():
    std = standard.read_text(encoding="utf-8")
    ad = (project / "docs" / "review-accepted-decisions.md").read_text(encoding="utf-8")
    bullet = next((line for line in std.splitlines() if "(AD-37)" in line), "")
    must("premium module" in bullet and "AD-20" in bullet and "replaced module" in bullet, "standard AD-37 bullet names a premium module, AD-20 and the replaced module's routes")
    must("A missing permission still writes one `deny` row" in bullet, "standard AD-37 bullet still says a missing permission writes a deny row")
    must("does not cover the premium module's own routes" in bullet, "standard AD-37 bullet leaves the premium module's own routes out")
    row = next((line for line in ad.splitlines() if line.startswith("| 37 |")), "")
    must("20 Oct 2026" in row and "20 October 2026" in row, "AD index row 37 names the 20 October 2026 amendment")
    must(ad.count("\n| 37 |") == 1, "AD row 37 is still one row (later rows such as AD-41 do not touch it)")
    must("log-only" not in ad.lower() and ad.lower().count("licens") == 1, "no licensing decision row was added")
else:
    print("NOTE project documents not reachable from this tree; document checks skipped")

if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("OK")
