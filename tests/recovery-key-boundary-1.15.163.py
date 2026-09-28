#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/recovery-key-cli.py'
spec = importlib.util.spec_from_file_location('recovery_key_boundary_163', SCRIPT)
mod = importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as raw:
    base = Path(raw)
    os.chmod(base, 0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    identity = mod._public_identity('boundary-key', pem, server_name='boundary')
    source = base / 'import.json'; source.write_text(json.dumps(identity), encoding='utf-8')

    # Final trust root may never be a symlink or writable directory.
    victim = base / 'victim'; victim.mkdir(); os.chmod(victim, 0o755)
    link = base / 'trust-link'; link.symlink_to(victim, target_is_directory=True)
    mod.TRUST_ROOT = link; mod.append_audit = lambda *a, **k: None
    try: mod.cmd_import(SimpleNamespace(path=str(source)))
    except RuntimeError as exc: assert 'root-owned, real' in str(exc)
    else: raise AssertionError('symlink trust root accepted')
    assert not (victim / 'boundary-key.pub').exists()

    unsafe = base / 'unsafe-trust'; unsafe.mkdir(); os.chmod(unsafe, 0o777)
    mod.TRUST_ROOT = unsafe
    try: mod.cmd_import(SimpleNamespace(path=str(source)))
    except RuntimeError as exc: assert 'root-owned, real' in str(exc)
    else: raise AssertionError('writable trust root accepted')
    assert not (unsafe / 'boundary-key.pub').exists()

    # A missing trust root is only created under an already trusted parent.
    unsafe_parent = base / 'unsafe-parent'; unsafe_parent.mkdir(); os.chmod(unsafe_parent, 0o777)
    child = unsafe_parent / 'trust'
    mod.TRUST_ROOT = child
    try: mod.cmd_import(SimpleNamespace(path=str(source)))
    except RuntimeError as exc: assert 'directory parent' in str(exc)
    else: raise AssertionError('trust root created below writable parent')
    assert not child.exists()

    # The installer-selected config path controls the recovery trust root.
    layout_root = base / 'layout'; layout_root.mkdir(); os.chmod(layout_root, 0o700)
    configured_trust = layout_root / 'custom-trust'
    cfg = layout_root / 'tec-tac.conf'
    cfg.write_text(f'TEC_TAC_RECOVERY_TRUST_ROOT={configured_trust}\n', encoding='utf-8'); os.chmod(cfg, 0o600)
    pointer = layout_root / 'config-path'; pointer.write_text(str(cfg) + '\n', encoding='utf-8'); os.chmod(pointer, 0o600)
    layout = mod._root_layout(pointer=pointer, default=layout_root / 'unused.conf')
    assert mod._absolute_layout_path(layout, 'TEC_TAC_RECOVERY_TRUST_ROOT', '/etc/tec-tac/recovery-trust') == configured_trust

    # Execute the script via its shebang with a hostile PYTHONPATH. -I must ignore sitecustomize.
    poison = base / 'poison'; poison.mkdir()
    (poison / 'sitecustomize.py').write_text('raise SystemExit(93)\n', encoding='utf-8')
    env = dict(os.environ, PYTHONPATH=str(poison), TEC_TAC_TEST_ALLOW_NONROOT='1')
    proc = subprocess.run([str(SCRIPT), '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert 'usage: tec-tac-recovery-key' in proc.stdout

print('[TEST] PASS L76 isolated recovery-key uses configured trust root and rejects unsafe write boundaries')
