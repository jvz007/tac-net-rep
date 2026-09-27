#!/usr/bin/env python3
"""Regression coverage for detached signed System Update uploads."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import system_update


class Upload:
    def __init__(self, path: Path, name: str | None = None):
        self.path = path
        self.name = name or path.name
        self.size = path.stat().st_size

    def chunks(self):
        with self.path.open("rb") as handle:
            while True:
                block = handle.read(65536)
                if not block:
                    break
                yield block


def make_archive(base: Path, *, embedded_signing=False) -> Path:
    tree = base / "tree"
    (tree / "framwork" / "tec_tac").mkdir(parents=True)
    (tree / "VERSION").write_text("1.15.115\n", encoding="utf-8")
    (tree / "install.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (tree / "framwork" / "tec_tac" / "__init__.py").write_text("", encoding="utf-8")
    (tree / "tec_tac_package.json").write_text(json.dumps({"type": "tec-tac-framework", "version": "1.15.115"}), encoding="utf-8")
    if embedded_signing:
        (tree / "tec-tac-release.json").write_text("{}\n", encoding="utf-8")
        (tree / "tec-tac-release.json.sig").write_text("ed25519:test\n", encoding="utf-8")
    archive = base / "framework.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for path in tree.rglob("*"):
            if path.is_file():
                zf.write(path, Path("framework") / path.relative_to(tree))
    return archive


with tempfile.TemporaryDirectory(prefix="tt-detached-update-") as tmp:
    base = Path(tmp)
    staged = base / "staged"
    staged.mkdir()
    system_update.STAGED_ROOT = staged
    system_update._installed_version = lambda component: "1.15.114"
    system_update._accept_update_trust = lambda trust, subject: {"accepted": True, "actual_level": "signed_development"}

    seen = {}
    def fake_verify(*, root, expected_component, required_permissions):
        assert expected_component == "framework"
        assert (root / "tec-tac-release.json").read_text(encoding="utf-8") == '{"schema":2}\n'
        assert (root / "tec-tac-release.json.sig").read_text(encoding="utf-8") == "ed25519:detached\n"
        seen["verified"] = True
        return {"signed": True, "verified": True, "trusted": True, "state": "signed", "file_count": 4}
    system_update.verify_release_tree = fake_verify

    archive = make_archive(base)
    manifest = base / "tec-tac-release.json"
    signature = base / "tec-tac-release.json.sig"
    manifest.write_text('{"schema":2}\n', encoding="utf-8")
    signature.write_text("ed25519:detached\n", encoding="utf-8")

    result = system_update.stage_uploaded_package(
        Upload(archive),
        release_manifest_upload=Upload(manifest),
        release_signature_upload=Upload(signature),
    )
    assert seen.get("verified") is True
    assert result["preview"]["release_trust"]["verified"] is True
    upload_id = result["upload_id"]
    assert (staged / f"{upload_id}.zip").is_file()
    assert (staged / f"{upload_id}.release.json").is_file()
    assert (staged / f"{upload_id}.release.json.sig").is_file()

    system_update.discard_stage(upload_id)
    assert not any(staged.glob(f"{upload_id}*"))

    embedded = make_archive(base / "embedded", embedded_signing=True)
    try:
        system_update.stage_uploaded_package(
            Upload(embedded),
            release_manifest_upload=Upload(manifest),
            release_signature_upload=Upload(signature),
        )
    except system_update.SystemUpdateError as exc:
        assert "ambiguous" in str(exc).lower()
    else:
        raise AssertionError("embedded + detached signing metadata was accepted")

    try:
        system_update.stage_uploaded_package(Upload(archive), release_manifest_upload=Upload(manifest))
    except system_update.SystemUpdateError as exc:
        assert "both" in str(exc).lower()
    else:
        raise AssertionError("incomplete detached signing pair was accepted")

print("[TEST] PASS detached signed System Update upload staging")
