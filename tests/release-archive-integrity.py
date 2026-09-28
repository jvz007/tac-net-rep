#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

START_PATCH = 113


def fail(message: str) -> None:
    raise AssertionError(message)


def clean_version(version: str) -> str:
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-\d+)?", version)
    if not m:
        fail(f"unsupported VERSION format: {version!r}")
    return m.group(1)


def validate(root: Path) -> None:
    archive = root / "docs" / "releases"
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    clean = clean_version(version)
    major, minor, patch_s = clean.split(".")
    patch = int(patch_s)

    rebuild_named = sorted(
        p.name
        for p in archive.glob("RELEASE_NOTES_*.md")
        if re.fullmatch(r"RELEASE_NOTES_\d+\.\d+\.\d+-\d+\.md", p.name)
    )
    if rebuild_named:
        fail(f"rebuild-suffixed archive notes are forbidden: {rebuild_named}")

    if (major, minor) == ("1", "15") and patch > START_PATCH:
        missing = []
        bad_headings = []
        for archived_patch in range(START_PATCH, patch):
            archived_version = f"1.15.{archived_patch}"
            note = archive / f"RELEASE_NOTES_{archived_version}.md"
            if not note.is_file():
                missing.append(note.name)
                continue
            first_line = note.read_text(encoding="utf-8").splitlines()[0:1]
            expected = f"# Tec-Tac Core {archived_version}"
            if first_line != [expected]:
                bad_headings.append((note.name, first_line[0] if first_line else "<empty>", expected))
        if missing:
            fail(f"release archive is missing clean releases: {missing}")
        if bad_headings:
            fail(f"release archive headings do not match clean identities: {bad_headings}")

    legacy = archive / "1.15.96.md"
    if legacy.exists():
        fail("legacy noncanonical docs/releases/1.15.96.md must be named RELEASE_NOTES_1.15.96.md")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    validate(root)
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    print(f"[TEST] PASS release archive integrity {version}")


if __name__ == "__main__":
    main()
