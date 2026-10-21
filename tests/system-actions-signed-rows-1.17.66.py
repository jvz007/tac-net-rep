#!/usr/bin/env python3
"""1.17.66 regression: Johan's 20 October 2026 sign-offs are on record, and the release notes say what is built and what waits.

Reads the project's reviews/questions/core.md when the folder is on this PC (it is the project's, not the package's) and the release notes of this
package. Covered: CQ173, CQ174, CQ175 and CQ178 each carry an 'Answered' line with Johan's words as relayed and are not left as open questions;
CQ176 and CQ177 are noted as built; CQ187 to CQ191 are agreed; CQ192 to CQ197 are written once each with their assumption; the release notes name
every CQ and every left-out row with its reason, carry the module-facing heading, the 'What I checked in modules/' heading, a PASS or FAIL
checklist with a FAIL line per step, and no stale wording.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def entry(text: str, cq: str) -> str:
    """The text of one '### CQnnn' entry, up to the next heading."""
    match = re.search(rf"^### {cq} \(.*?(?=^### |^## |\Z)", text, re.MULTILINE | re.DOTALL)
    must(match is not None, f"{cq} is in the questions file")
    return match.group(0)


reviews = ROOT.parents[1] / "reviews"
if reviews.is_dir():
    text = (reviews / "questions" / "core.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    for cq in ("CQ173", "CQ174", "CQ175", "CQ178"):
        body = entry(text, cq)
        must(text.count(f"### {cq} (") == 1, f"{cq} is there once")
        answered = [line for line in body.split("\n") if line.startswith("- **Answered")]
        must(any('"' in line and "Johan" in line and "20 October 2026" in line and "release plan" in line for line in answered), f"{cq} carries an Answered line with Johan's quoted words")
        must("Built in Core 1.17.66" in body or "Not built in Core 1.17.66" in body, f"{cq} says what 1.17.66 built")
    must("never a synthetic request" in entry(text, "CQ174") and "CQ192" in entry(text, "CQ174"), "the rule push is answered and the conflict is asked")
    must("scripts.run" in entry(text, "CQ175") and "CQ193" in entry(text, "CQ175") and "CQ194" in entry(text, "CQ175"), "CQ175 names the row built and the rows that wait")
    must("groups of at most 2000" in entry(text, "CQ178") and "CQ195" in entry(text, "CQ178"), "CQ178")
    must("Do NOT build R-36" in entry(text, "CQ173") or "R-36 is not built" in entry(text, "CQ173"), "CQ173 keeps R-36 unbuilt")
    for cq in ("CQ176", "CQ177"):
        must("Agreed as built" in entry(text, cq) or "Built in Core 1.17.63" in entry(text, cq), f"{cq} is noted as built")
    for cq in ("CQ187", "CQ188", "CQ190", "CQ191"):
        must("Agreed, 20 October 2026" in entry(text, cq), f"{cq} is agreed")
    must("**Answer (Johan, chat, 20 October 2026): yes." in entry(text, "CQ189"), "CQ189 stays answered")
    for cq in ("CQ192", "CQ193", "CQ194", "CQ195", "CQ196", "CQ197"):
        body = entry(text, cq)
        must(text.count(f"### {cq} (") == 1 and "Core 1.17.66" in body and "Assumption I went on with" in body, f"{cq} is written once with its assumption")
    print("       the questions file records the answers of CQ173, CQ174, CQ175 and CQ178, the agreed entries, and CQ192 to CQ197 once each")
else:
    print("       the project's reviews folder is not on this PC: the questions file was not read")

version = ROOT.joinpath("VERSION").read_text(encoding="utf-8").strip()
base = tuple(int(x) for x in re.sub(r"-\d+$", "", version).split("."))
must(base >= (1, 17, 66), version)
notes_path = ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.66.md"  # 1.17.68: this test is about the 1.17.66 notes, which are kept under docs/releases
must(notes_path.is_file(), f"{notes_path.name} exists")
notes = notes_path.read_text(encoding="utf-8").replace("\r\n", "\n")
for heading in ("## What changed and why", "## Module-facing", "## What was left out, and what ends each wait", "## Dev-server checklist", "## Tests"):
    must(heading in notes, f"the notes carry {heading}")
must("## What I checked in modules/" in notes or "## What I checked in `modules/`" in notes, "the notes carry the modules/ heading")
for cq in ("CQ173", "CQ174", "CQ175", "CQ176", "CQ177", "CQ178", "CQ187", "CQ191", "CQ192", "CQ193", "CQ194", "CQ195", "CQ196", "CQ197"):
    must(cq in notes, f"the notes name {cq}")
for left_out in ("Rule push", "Reboot with a result", "Software package uninstall", "Commands", "Checks run, tasks run and reports", "target type", "R-36", "native patching paths"):
    must(left_out.lower() in notes.lower(), f"the notes name the left-out item {left_out!r}")
steps = notes[notes.index("## Dev-server checklist"):]
count = steps.count("**Step ")
must(count >= 7 and steps.count("**FAIL**") >= count and "Expect" in steps, f"each of the {count} checklist steps has its FAIL line")
for phrase in ("inactive until the amended", "registered with unattended=True"):
    must(phrase not in notes, f"the notes carry no stale wording: {phrase}")
must("RELEASE_NOTES_1.17.65.md" not in [p.name for p in ROOT.glob("RELEASE_NOTES_*.md")] and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.65.md").is_file(), "1.17.65's notes moved to docs/releases")
print("       the release notes carry the headings, name every CQ and every left-out row, and give a checklist with a FAIL line per step")
print("PASS system actions signed rows 1.17.66")
