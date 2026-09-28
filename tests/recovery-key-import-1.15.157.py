#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location('recovery_key_115157', ROOT / 'scripts' / 'recovery-key-cli.py')
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def main():
    mod = load_module()
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        victim = root / 'victim.json'
        victim.write_text('{"secret": true}', encoding='utf-8')
        link = root / 'import.json'
        link.symlink_to(victim)
        try:
            mod._read_import_regular(link)
        except RuntimeError as exc:
            assert 'regular file' in str(exc)
        else:
            raise AssertionError('symlink import source was accepted')

        oversized = root / 'oversized.json'
        oversized.write_bytes(b'x' * (256 * 1024 + 1))
        try:
            mod._read_import_regular(oversized)
        except RuntimeError as exc:
            assert 'unexpectedly large' in str(exc)
        else:
            raise AssertionError('oversized recovery import source was accepted')

        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        identity = mod._public_identity('test-recovery-key', public, server_name='test-server')
        source = root / 'valid-import.json'
        source.write_text(json.dumps(identity), encoding='utf-8')
        trust = root / 'trust'
        mod.TRUST_ROOT = trust
        mod.append_audit = lambda *args, **kwargs: None

        real_fsync = os.fsync
        synced_dir = False
        def tracking_fsync(fd):
            nonlocal synced_dir
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                synced_dir = True
            return real_fsync(fd)
        mod.os.fsync = tracking_fsync
        mod.cmd_import(SimpleNamespace(path=str(source)))
        target = trust / 'test-recovery-key.pub'
        assert target.read_bytes() == public
        assert synced_dir, 'trust directory was not fsynced after publishing imported recovery key'

    print('recovery key import 1.15.157: PASS')


if __name__ == '__main__':
    main()
