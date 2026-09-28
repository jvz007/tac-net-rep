#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location('recovery_key_115155', ROOT / 'scripts' / 'recovery-key-cli.py')
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def main():
    mod = load_module()
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        victim = root / 'victim.txt'
        victim.write_text('do-not-touch', encoding='utf-8')
        link = root / 'export.json'
        link.symlink_to(victim)

        try:
            mod._atomic_write_public_export(link, '{"safe": true}\n')
        except RuntimeError as exc:
            assert 'regular file' in str(exc)
        else:
            raise AssertionError('symlink export target was accepted')

        assert link.is_symlink(), 'symlink target should be rejected, not replaced'
        assert victim.read_text(encoding='utf-8') == 'do-not-touch', 'symlink destination was modified'

        link.unlink()
        target = mod._atomic_write_public_export(link, '{"safe": true}\n')
        assert target == link
        assert link.read_text(encoding='utf-8') == '{"safe": true}\n'
        assert stat.S_IMODE(link.stat().st_mode) == 0o644

        mod._atomic_write_public_export(link, '{"safe": false}\n')
        assert link.read_text(encoding='utf-8') == '{"safe": false}\n'
        assert list(root.glob('.export.json.*.tmp')) == [], 'temporary export files leaked'

    print('recovery key export 1.15.155: PASS')


if __name__ == '__main__':
    main()
