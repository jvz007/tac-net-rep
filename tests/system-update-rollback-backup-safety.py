#!/usr/bin/env python3
"""M6: rollback backup validation must complete before the live tree is swapped."""
from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "system-update-helper.py"
spec = importlib.util.spec_from_file_location("tec_tac_system_update_helper_m6", HELPER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def live_snapshot(target: Path):
    return {
        "live": (target / "live.txt").read_text(encoding="utf-8"),
        "git": (target / ".git" / "HEAD").read_text(encoding="utf-8"),
    }


with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    target = base / "framework"
    target.mkdir()
    (target / "live.txt").write_text("current-live\n", encoding="utf-8")
    (target / ".git").mkdir()
    (target / ".git" / "HEAD").write_text("current-git\n", encoding="utf-8")
    expected_live = live_snapshot(target)

    # Missing backup must fail before touching the live checkout.
    try:
        mod.restore_backup(base / "missing.tar.gz", target)
    except RuntimeError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("missing rollback archive was accepted")
    assert live_snapshot(target) == expected_live

    # A malformed archive with the wrong top-level directory is fully rejected
    # before the target is renamed or removed.
    wrong_top = base / "wrong-top.tar.gz"
    payload = b"not-the-target\n"
    with tarfile.open(wrong_top, "w:gz") as tf:
        info = tarfile.TarInfo("other/live.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    try:
        mod.restore_backup(wrong_top, target)
    except RuntimeError as exc:
        assert "unexpected top-level path" in str(exc)
    else:
        raise AssertionError("wrong-top rollback archive was accepted")
    assert live_snapshot(target) == expected_live

    # A truncated/corrupt gzip/tar must also leave the live checkout untouched.
    valid_for_truncate = base / "truncate-source.tar.gz"
    backup_source = base / "backup-source" / target.name
    backup_source.mkdir(parents=True)
    (backup_source / "restored.txt").write_text("restored\n", encoding="utf-8")
    with tarfile.open(valid_for_truncate, "w:gz") as tf:
        tf.add(backup_source, arcname=target.name)
    corrupt = base / "corrupt.tar.gz"
    blob = valid_for_truncate.read_bytes()
    corrupt.write_bytes(blob[: max(16, len(blob) // 3)])
    try:
        mod.restore_backup(corrupt, target)
    except (RuntimeError, tarfile.TarError, EOFError, OSError):
        pass
    else:
        raise AssertionError("corrupt rollback archive was accepted")
    assert live_snapshot(target) == expected_live

    # A valid rollback is staged completely, then swapped in, while preserving
    # the checkout's live .git metadata that is intentionally absent from backup.
    valid = base / "valid.tar.gz"
    with tarfile.open(valid, "w:gz") as tf:
        tf.add(backup_source, arcname=target.name)
    mod.restore_backup(valid, target)
    assert not (target / "live.txt").exists()
    assert (target / "restored.txt").read_text(encoding="utf-8") == "restored\n"
    assert (target / ".git" / "HEAD").read_text(encoding="utf-8") == "current-git\n"
    assert not list(base.glob(".framework.rollback-live-*")), "live quarantine survived successful swap"
    assert not list(base.glob(".framework.rollback-stage-*")), "staging directory survived successful swap"

print("[TEST] PASS system update rollback backup safety")
