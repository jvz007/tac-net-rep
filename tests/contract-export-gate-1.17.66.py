#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.66 gate (the held Low of the 1.17.65 review): the exported public contract must equal what the code publishes.

Pure checker (framwork/tec_tac/contract_export_check.py) on small fixture files, then the real source against the newest export in the project's
docs/contracts folder when that export is for this version. Covered: a matching export passes; a changed capability field, a missing capability
block, a missing contract row, a changed purpose text, a wrong framework version and each stale phrase fail with a plain line; the stale phrases
are in none of contracts.py, system_actions.py, the docs of this package or the export; the management command exists, reads a file and fails on a
difference. Without an export for this version the real-export part reports 'not run' plainly and passes (Claude cannot export: the file is made
on the running dev server, and tec_tac_check_contract_export is the live check).
"""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

spec = importlib.util.spec_from_file_location("contract_export_check", APP / "contract_export_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

VERSION = ROOT.joinpath("VERSION").read_text(encoding="utf-8").strip()
META = sa.system_actions_contract_metadata()
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
ROWS = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
RULES = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "RULES")
SAMPLE = [r for r in ROWS if r["name"] in ("register_system_action", "run_system_action", "describe_confirmation", "SystemActionCreationRefused")]
must(len(SAMPLE) == 4, "the system-action rows are in the catalog")


def fake_export(version=VERSION, meta=None, rows=SAMPLE, extra=""):
    lines = ["# Tec-Tac Public Contracts", "", f"Framework: **{version}**  ", "Generated: `2026-10-20T19:09:11+00:00`", "", "## Core Python contracts", "",
             "| Import | Function / signature | Audience | Purpose |", "| --- | --- | --- | --- |"]
    for row in rows:
        lines.append(f"| `{row['import_path']}` | `{row['name']}()` | {row['audience']} | {row['purpose']} |")
    lines += ["", "## Registered capabilities", "", "### `core.system_actions`", "", "- Provider module: `core`", "- Published metadata:", "", "```json",
              json.dumps(META if meta is None else meta, indent=2, sort_keys=True), "```", "", extra]
    return "\n".join(lines)


def problems_of(text, **kw):
    return check.check_export_text(text, rows=SAMPLE, metadata=META, version=VERSION, **kw)


# ---- a matching export passes
must(problems_of(fake_export()) == [], problems_of(fake_export()))
must(problems_of(fake_export().replace("\n", "\r\n")) == [], "a CRLF export is read the same")
print("       a matching export passes")

# ---- each kind of difference fails with a plain line
changed = dict(META, max_agents=2000)
found = problems_of(fake_export(meta=changed))
must(found == ["core.system_actions metadata field 'max_agents' differs from the code"], found)
for key, value in (("version", "1.0.0"), ("operations", ["run"]), ("refusal_reasons", []), ("requires_framework", ">=1.17.61"), ("unattended", "old text")):
    found = problems_of(fake_export(meta=dict(META, **{key: value})))
    must(len(found) == 1 and f"'{key}'" in found[0], (key, found))
missing_key = {k: v for k, v in META.items() if k != "delivery"}
must(any("'delivery'" in p for p in problems_of(fake_export(meta=missing_key))), "a field missing from the export")
no_block = fake_export().replace("```json", "```text")
must(any("no published metadata" in p for p in problems_of(no_block)), "a missing metadata block")
found = problems_of(fake_export(rows=SAMPLE[:-1]))
must(len(found) == 1 and SAMPLE[-1]["name"] in found[0] and "missing" in found[0], found)
altered = [dict(SAMPLE[0], purpose=SAMPLE[0]["purpose"] + " An extra sentence.")] + SAMPLE[1:]
found = check.check_export_text(fake_export(rows=SAMPLE), rows=altered, metadata=META, version=VERSION)
must(len(found) == 1 and "differs" in found[0], found)
found = problems_of(fake_export(version="1.17.65"))
must(found == [f"the export is for Core 1.17.65, not {VERSION}"], found)
for phrase in check.STALE_PHRASES:
    found = problems_of(fake_export(extra=f"- A line with {phrase} in it."))
    must(len(found) == 1 and phrase in found[0], (phrase, found))
found = problems_of(fake_export(), stale_sources={"docs/system-actions.md": "x " + check.STALE_PHRASES[0]})
must(len(found) == 1 and "docs/system-actions.md" in found[0], found)
print("       a changed or missing capability field, a missing block or row, a changed purpose, a wrong version and each stale phrase fail with one plain line")

# ---- the live diff ignores only the Generated line
live = fake_export()
must(check.diff_against_live(live, live.replace("2026-10-20T19:09:11", "2026-10-21T08:00:00")) == [], "only the Generated line may differ")
found = check.diff_against_live(live, live.replace("Provider module: `core`", "Provider module: `other`"))
must(len(found) == 1 and found[0].startswith("line "), found)
must(check.diff_against_live(live, live + "\n- one more line")[-1].startswith("the export has"), "a longer file differs")
print("       the live diff ignores the Generated line and names the first differing line")

# ---- the stale wording is in none of the sources
docs = sorted((ROOT / "docs").glob("*.md"))
sources = {"contracts.py": (APP / "contracts.py").read_text(encoding="utf-8"), "system_actions.py": (APP / "system_actions.py").read_text(encoding="utf-8"),
           "system_action_confirmation.py": (APP / "system_action_confirmation.py").read_text(encoding="utf-8"),
           **{f"docs/{p.name}": p.read_text(encoding="utf-8") for p in docs}}
must(len(sources) > 20, "the docs were found")
for label, body in sources.items():
    for phrase in check.STALE_PHRASES:
        must(phrase not in body, f"{label} carries the stale wording {phrase!r}")
must(not any(p in rule for rule in RULES for p in check.STALE_PHRASES), "no rule carries it")
print("       the stale wording is in none of contracts.py, system_actions.py, the confirmation module or the package docs")

# ---- the management command exists, reads a file and fails on a difference
command = (APP / "management" / "commands" / "tec_tac_check_contract_export.py").read_text(encoding="utf-8")
must("class Command(BaseCommand)" in command and "check_export_text(" in command and "diff_against_live(" in command and "CommandError" in command and "system_actions_contract_metadata()" in command, "the command")
must("build_contract_catalog()" in command and "render_markdown(" in command and "CORE_CONTRACTS" in command, "it builds the live catalog")
print("       tec_tac_check_contract_export reads a file, builds the live catalog and fails on any difference")

# ---- the real export, when there is one for this version
exports = ROOT.parents[1] / "docs" / "contracts"
chosen = None
if exports.is_dir():
    candidates = []
    for path in exports.glob("*.md"):
        head = path.read_text(encoding="utf-8-sig", errors="replace")[:400]
        if check.export_version(head) == VERSION:
            candidates.append(path)
    chosen = max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None
if chosen is None:
    print(f"       real export: NOT RUN. No export for Core {VERSION} is in docs/contracts yet. It is made on the dev server; run tec_tac_check_contract_export on it.")
else:
    text = chosen.read_text(encoding="utf-8-sig")
    found = check.check_export_text(text, rows=ROWS, metadata=META, version=VERSION, stale_sources=sources)
    must(not found, f"{chosen.name} differs from the code: {found}")
    print(f"       real export {chosen.name} matches the code")
print("PASS contract export gate 1.17.66")
