#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, os, tempfile
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery_key_boundary_160', ROOT/'scripts/recovery-key-cli.py')
mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as raw:
    base=Path(raw)
    key=Ed25519PrivateKey.generate()
    pem=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    identity=mod._public_identity('boundary-key', pem, server_name='boundary')
    source=base/'import.json'; source.write_text(json.dumps(identity),encoding='utf-8')
    victim=base/'victim'; victim.mkdir(); os.chmod(victim,0o755)
    link=base/'trust-link'; link.symlink_to(victim, target_is_directory=True)
    mod.TRUST_ROOT=link; mod.append_audit=lambda *a,**k: None
    try: mod.cmd_import(SimpleNamespace(path=str(source)))
    except RuntimeError as exc: assert 'root-owned, real' in str(exc)
    else: raise AssertionError('symlink trust root accepted')
    assert not (victim/'boundary-key.pub').exists(), 'write occurred through symlinked trust root'

    unsafe=base/'unsafe-trust'; unsafe.mkdir(); os.chmod(unsafe,0o777)
    mod.TRUST_ROOT=unsafe
    try: mod.cmd_import(SimpleNamespace(path=str(source)))
    except RuntimeError as exc: assert 'root-owned, real' in str(exc)
    else: raise AssertionError('writable/untrusted trust root accepted')
    assert not (unsafe/'boundary-key.pub').exists(), 'write occurred before trust-root safety validation'
print('[TEST] PASS L76 recovery-key import validates real root trust directory before writing')
