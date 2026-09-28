#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("archive_integrity", HERE / "release-archive-integrity.py")
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


def make_root() -> Path:
    base = Path(tempfile.mkdtemp(prefix="tec-tac-release-archive-"))
    archive = base / "docs" / "releases"
    archive.mkdir(parents=True)
    (base / "VERSION").write_text("1.15.116\n", encoding="utf-8")
    for patch in range(113, 116):
        version = f"1.15.{patch}"
        (archive / f"RELEASE_NOTES_{version}.md").write_text(
            f"# Tec-Tac Core {version}\n\nfixture\n", encoding="utf-8"
        )
    return base


root = make_root()
mod.validate(root)

missing = root / "docs" / "releases" / "RELEASE_NOTES_1.15.114.md"
missing.unlink()
try:
    mod.validate(root)
except AssertionError as exc:
    assert "missing clean releases" in str(exc)
else:
    raise AssertionError("archive gap was accepted")

root = make_root()
(root / "docs" / "releases" / "RELEASE_NOTES_1.15.114-1.md").write_text(
    "# Tec-Tac Core 1.15.114\n", encoding="utf-8"
)
try:
    mod.validate(root)
except AssertionError as exc:
    assert "rebuild-suffixed" in str(exc)
else:
    raise AssertionError("rebuild-suffixed archive identity was accepted")

root = make_root()
(root / "docs" / "releases" / "RELEASE_NOTES_1.15.115.md").write_text(
    "# Tec-Tac Core 1.15.115-1\n", encoding="utf-8"
)
try:
    mod.validate(root)
except AssertionError as exc:
    assert "headings do not match" in str(exc)
else:
    raise AssertionError("mismatched clean archive heading was accepted")

print("[TEST] PASS release archive integrity regression")
