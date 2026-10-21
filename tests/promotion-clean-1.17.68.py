#!/usr/bin/env python3
"""1.17.68 regression: the release can be promoted from its rebuild version to the clean one.

The pipeline (pipeline/tectac/promote.py) refuses a rebuild whose ``-N`` text still appears in any text file outside tests/ and docs/, other than VERSION,
the package manifests, package-lock.json, FIXING.md and the release notes named for the rebuild. It does not scan file names. This test applies the same
rule, plus one of its own: no file under tests/ or docs/ is named with the rebuild text, so nothing in the tree carries it. When VERSION is clean it
only checks that no stray rebuild note is left.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_EXT = {".py", ".js", ".mjs", ".vue", ".json", ".md", ".sh", ".txt", ".html", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".conf"}  # promote.py's list
PROMOTE = ROOT.parents[1] / "pipeline" / "tectac" / "promote.py"
if PROMOTE.is_file():  # in the workspace the pipeline's own list wins; the copy above is the fallback
    m = re.search(r"TEXT_EXT\s*=\s*\{(.*?)\}", PROMOTE.read_text(encoding="utf-8"), re.S)
    if m:
        TEXT_EXT = set(re.findall(r'"(\.[a-z0-9]+)"', m.group(1))) or TEXT_EXT

version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
rebuild = version if re.fullmatch(r"\d+\.\d+\.\d+-\d+", version) else None
problems = []
if rebuild:
    exempt = {"VERSION", "tec_tac_package.json", "package-lock.json", "FIXING.md", f"RELEASE_NOTES_{rebuild}.md"}
    for f in ROOT.rglob("*"):
        if ".git" in f.parts or not f.is_file():
            continue
        rel = f.relative_to(ROOT)
        top = rel.parts[0]
        if top in ("tests", "docs"):
            if rebuild in f.name:
                problems.append(f"{rel.as_posix()}: file name carries {rebuild}")
            continue
        if rel.as_posix() in exempt:
            continue
        if f.suffix.lower() in TEXT_EXT and rebuild in f.read_text("utf-8", "replace"):
            problems.append(f"{rel.as_posix()}: carries {rebuild}")
    problems += [f"tests/ or docs/ text names {rebuild}" for d in ("tests", "docs") for f in (ROOT / d).rglob("*")
                 if f.is_file() and f.suffix.lower() in TEXT_EXT and f.name != Path(__file__).name and rebuild in f.read_text("utf-8", "replace")]
    stale = sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md") if p.name != f"RELEASE_NOTES_{rebuild}.md")
    problems += [f"stale root note {n}" for n in stale]
if problems:
    raise AssertionError(problems)
print(f"       VERSION {version}: the rebuild text appears only where promotion allows" if rebuild else f"       VERSION {version} is clean")
print("PASS promotion clean 1.17.68")
