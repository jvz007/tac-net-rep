#!/usr/bin/env python3
"""Regression coverage for the privileged System Update extraction boundary."""
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "system-update-helper.py"
spec = importlib.util.spec_from_file_location("tec_tac_system_update_helper_r2", HELPER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

real_chown = mod.os.chown
chown_calls = []

def fake_chown(path, uid, gid, *args, **kwargs):
    chown_calls.append((Path(path), uid, gid, kwargs.get("follow_symlinks")))

mod.os.chown = fake_chown
try:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        mod.RUNNING_ROOT = base / "running"
        mod.RUNNING_ROOT.mkdir(mode=0o750)
        job_id = "12345678-1234-1234-1234-123456789abc"

        # Success path: root-private work directory exists only inside context.
        with mod.private_update_work_dir(job_id) as work:
            assert work.exists()
            assert stat.S_IMODE(work.stat().st_mode) == 0o700
            assert any(path == work and uid == 0 and gid == 0 for path, uid, gid, _ in chown_calls)
            (work / "payload.txt").write_text("payload\n", encoding="utf-8")
        assert not work.exists(), "private update work directory survived successful use"

        # Failure path: cleanup is guaranteed by the context manager.
        try:
            with mod.private_update_work_dir(job_id) as failed_work:
                (failed_work / "partial.txt").write_text("partial\n", encoding="utf-8")
                raise RuntimeError("forced extraction failure")
        except RuntimeError as exc:
            assert "forced extraction failure" in str(exc)
        else:
            raise AssertionError("forced failure did not propagate")
        assert not failed_work.exists(), "private update work directory survived failed use"

        # Release mode/ownership normalization: package metadata must not grant
        # root execution privileges or leave group/world writable content.
        tree = base / "checkout"
        tree.mkdir()
        os.chmod(tree, 0o2777)
        dangerous = tree / "install.sh"
        dangerous.write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(dangerous, 0o6777)
        nested = tree / "subdir"
        nested.mkdir()
        os.chmod(nested, 0o2777)
        nested_file = nested / "data.txt"
        nested_file.write_text("x\n", encoding="utf-8")
        os.chmod(nested_file, 0o0666)
        git_dir = tree / ".git"
        git_dir.mkdir()
        os.chmod(git_dir, 0o0777)

        chown_calls.clear()
        mod.normalize_release_tree_security(tree)
        for path in (tree, dangerous, nested, nested_file):
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            assert not (mode & (stat.S_ISUID | stat.S_ISGID)), (path, oct(mode))
            assert not (mode & (stat.S_IWGRP | stat.S_IWOTH)), (path, oct(mode))
            assert any(call_path == path and uid == 0 and gid == 0 for call_path, uid, gid, _ in chown_calls), path
        assert stat.S_IMODE(git_dir.stat().st_mode) == 0o777, ".git metadata should not be normalized as release payload"
        assert not any(path == git_dir for path, *_ in chown_calls)

        # An unexpected link/special path is rejected rather than normalized by following it.
        bad = base / "bad-checkout"
        bad.mkdir()
        (bad / "real").write_text("x", encoding="utf-8")
        (bad / "link").symlink_to("real")
        try:
            mod.normalize_release_tree_security(bad)
        except RuntimeError as exc:
            assert "unsupported path" in str(exc)
        else:
            raise AssertionError("release symlink was accepted by normalization boundary")
finally:
    mod.os.chown = real_chown

print("[TEST] PASS system update root extraction boundary")
