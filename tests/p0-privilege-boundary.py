#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location('tec_tac_privileged_trust_test', ROOT / 'scripts/privileged-trust.py')
priv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(priv)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def setup_verifier(base: Path, *, permissions):
    config = base / 'tec-tac.conf'
    config.write_text('TEC_TAC_ENVIRONMENT=development\n', encoding='utf-8')
    trust_root = base / 'trust'
    pubdir = trust_root / 'publisher-dev'
    pubdir.mkdir(parents=True)
    policy_root = base / 'policy'
    policy_root.mkdir()
    (policy_root / 'update-trust-policy.json').write_text(json.dumps({
        'schema': 1,
        'minimum_level': 'signed_development',
        'updated_at': None,
        'updated_by': 'test-root',
    }), encoding='utf-8')
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (pubdir / 'public.key').write_text('ed25519:' + base64.b64encode(public).decode() + '\n', encoding='utf-8')
    (pubdir / 'publisher.json').write_text(json.dumps({
        'schema': 1,
        'publisher_id': 'publisher-dev',
        'display_name': 'Publisher Dev',
        'status': 'trusted',
        'permissions': list(permissions),
        'environment': 'development',
        'keys': [{
            'key_id': 'key-dev',
            'status': 'active',
            'algorithm': 'Ed25519',
            'public_key_file': 'public.key',
        }],
    }), encoding='utf-8')
    priv.CONFIG = config
    priv.TRUST_ROOT = trust_root
    priv.POLICY_ROOT = policy_root
    priv.POLICY_FILE = policy_root / 'update-trust-policy.json'
    priv.FRAMEWORK_ROOT = ROOT / 'framwork'
    return key, pubdir


def make_signed_tree(base: Path, key: Ed25519PrivateKey, *, component='framework', version='9.9.9') -> Path:
    tree = base / 'tree'
    tree.mkdir()
    (tree / 'VERSION').write_text(version + '\n', encoding='utf-8')
    (tree / 'tec_tac_package.json').write_text(json.dumps({'type': f'tec-tac-{component}', 'version': version}), encoding='utf-8')
    if component == 'framework':
        (tree / 'install.sh').write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
        (tree / 'framwork' / 'tec_tac').mkdir(parents=True)
        (tree / 'framwork' / 'tec_tac' / '__init__.py').write_text('', encoding='utf-8')
    else:
        (tree / 'scripts').mkdir()
        (tree / 'scripts' / 'install.sh').write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
        (tree / 'src').mkdir()
        (tree / 'src' / 'main.js').write_text('export {}\n', encoding='utf-8')
    files = []
    for path in sorted(p for p in tree.rglob('*') if p.is_file()):
        files.append({'path': path.relative_to(tree).as_posix(), 'size': path.stat().st_size, 'sha256': sha(path)})
    manifest = {
        'schema': 2,
        'component': component,
        'version': version,
        'publisher_id': 'publisher-dev',
        'key_id': 'key-dev',
        'algorithm': 'Ed25519',
        'files': files,
    }
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    (tree / 'tec-tac-release.json').write_bytes(raw)
    (tree / 'tec-tac-release.json.sig').write_text('ed25519:' + base64.b64encode(key.sign(raw)).decode() + '\n', encoding='utf-8')
    return tree


def make_module_package(base: Path, key: Ed25519PrivateKey, *, signed=True) -> tuple[Path, Path | None, Path | None]:
    package = base / 'demo-1.0.0.zip'
    with zipfile.ZipFile(package, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('demo/tec_tac.json', json.dumps({
            'schema': 1,
            'type': 'extension',
            'id': 'demo',
            'version': '1.0.0',
            'publisher_permissions': ['module.install'],
        }))
        zf.writestr('demo/__init__.py', '')
    if not signed:
        return package, None, None
    sig = base / 'demo-1.0.0.zip.sig'
    sig.write_text('ed25519:' + base64.b64encode(key.sign(package.read_bytes())).decode() + '\n', encoding='utf-8')
    meta = base / 'demo-1.0.0.release.json'
    meta.write_text(json.dumps({
        'schema': 1,
        'publisher_id': 'publisher-dev',
        'key_id': 'key-dev',
        'filename': package.name,
        'sha256': sha(package),
        'signature': sig.name,
        'algorithm': 'Ed25519',
        'environment': 'development',
    }), encoding='utf-8')
    return package, sig, meta


# S1/S2/S3/S8: root verifier ignores claimed web trust and independently checks
# root-owned trust/policy, required component permission, and package bytes.
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    key, pubdir = setup_verifier(base, permissions=['module.install'])
    tree = make_signed_tree(base, key)
    try:
        priv.verify_tree(tree, 'framework')
    except Exception as exc:
        assert 'permission' in str(exc).lower(), exc
    else:
        raise AssertionError('framework release signed by module-only publisher was accepted')

    policy = json.loads((pubdir / 'publisher.json').read_text(encoding='utf-8'))
    policy['permissions'].append('framework.update')
    (pubdir / 'publisher.json').write_text(json.dumps(policy), encoding='utf-8')
    ok = priv.verify_tree(tree, 'framework')
    assert ok['verified'] is True and ok['root_policy']['minimum_level'] == 'signed_development'

    (tree / 'install.sh').write_text('tampered\n', encoding='utf-8')
    try:
        priv.verify_tree(tree, 'framework')
    except Exception:
        pass
    else:
        raise AssertionError('tampered framework tree was accepted by root verifier')

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    key, _ = setup_verifier(base, permissions=['module.install'])
    unsigned, _, _ = make_module_package(base, key, signed=False)
    # A forged web/job claim is intentionally irrelevant; only the actual bytes
    # and root trust material are inputs to the privileged verifier.
    forged_job = {'release_trust': {'verified': True, 'trusted': True}, 'publisher_trust': {'verified': True}}
    assert forged_job['release_trust']['verified'] is True
    try:
        priv.verify_package(unsigned, None, None)
    except Exception as exc:
        assert 'trust level unsigned' in str(exc).lower() or 'unsigned' in str(exc).lower(), exc
    else:
        raise AssertionError('unsigned module was accepted by root verifier')

    # A separately signed package is accepted, then byte tampering is rejected.
    package = base / 'signed-demo-1.0.0.zip'
    unsigned.replace(package)
    sig = base / 'signed-demo-1.0.0.zip.sig'
    sig.write_text('ed25519:' + base64.b64encode(key.sign(package.read_bytes())).decode() + '\n', encoding='utf-8')
    meta = base / 'signed-demo-1.0.0.release.json'
    meta.write_text(json.dumps({
        'schema': 1, 'publisher_id': 'publisher-dev', 'key_id': 'key-dev',
        'filename': package.name, 'sha256': sha(package), 'signature': sig.name,
        'algorithm': 'Ed25519', 'environment': 'development',
    }), encoding='utf-8')
    ok = priv.verify_package(package, sig, meta)
    assert ok['verified'] is True
    assert ok['artifact_modules'] == [{'id': 'demo', 'version': '1.0.0', 'previous_module_ids': []}]
    with package.open('ab') as handle:
        handle.write(b'tamper')
    try:
        priv.verify_package(package, sig, meta)
    except Exception:
        pass
    else:
        raise AssertionError('tampered module package was accepted by root verifier')

# S7 and request-only boundary: root helpers must not use trust claims from the
# tactical-writable status/request files as execution authority.
text = (ROOT / 'framwork/tec_tac/system_update.py').read_text(encoding='utf-8')
queue = text[text.index('def queue_install'):text.index('def public_job')]
job_block = queue[queue.index('_new_job({'):queue.index('})', queue.index('_new_job({')) + 2]
assert 'release_trust' not in job_block and 'package_sha256' not in job_block and 'source' not in job_block
for helper_name in ('system-update-helper.py', 'module-job-helper.py', 'module-v2-job-helper.py'):
    helper = (ROOT / 'scripts' / helper_name).read_text(encoding='utf-8')
    assert 'RUNNING_REQUEST_ROOT' in helper
    assert 'os.chown(req_path, 0, 0)' in helper
    assert '0o600' in helper
assert '_privileged_verify_package' in (ROOT / 'scripts/module-job-helper.py').read_text(encoding='utf-8')
assert '_verify_v2_job_trust' in (ROOT / 'scripts/module-v2-job-helper.py').read_text(encoding='utf-8')
assert 'root-verify-staged' in (ROOT / 'scripts/system-update-helper.py').read_text(encoding='utf-8')
assert 'root-verify-execution' in (ROOT / 'scripts/system-update-helper.py').read_text(encoding='utf-8')

# S4: web permission no longer reuses Tactical can_do_server_maint for code/root
# lifecycle operations.
views = (ROOT / 'framwork/tec_tac/views.py').read_text(encoding='utf-8')
assert 'core.privileged_operations' in views
assert '"manage_modules": can_manage_privileged_operations(user)' in views
assert 'def _can_manage_modules' in views and 'can_manage_privileged_operations(user)' in views
assert 'Only a Tactical or role superuser may grant or revoke Tec-Tac privileged-operations access.' in views
maintenance = (ROOT / 'framwork/tec_tac/server_maintenance_views.py').read_text(encoding='utf-8')
assert 'can_manage_privileged_operations' in maintenance

print('[TEST] PASS P0 privilege boundary S1-S4/S7-S8 root verification and authorization')
