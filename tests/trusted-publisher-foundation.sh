#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH="${ROOT}/framwork" python3 - <<'PY'
import base64, hashlib, json, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from tec_tac.trusted_publishers import PublisherTrustError, verify_release_files


def expect_code(code, fn):
    try: fn()
    except PublisherTrustError as exc:
        assert exc.code == code, (exc.code, str(exc))
    else: raise AssertionError(f"expected {code}")

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); trust=root/'trust'; pubdir=trust/'tech_flow_dynamics-dev'; pubdir.mkdir(parents=True)
    package=root/'serverhealth-0.1.0.zip'; package.write_bytes(b'canonical zip bytes for test')
    key=Ed25519PrivateKey.generate(); pub=key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (pubdir/'public.key').write_text('ed25519:'+base64.b64encode(pub).decode()+'\n')
    policy={"schema":1,"publisher_id":"tech_flow_dynamics-dev","display_name":"Tech Flow Dynamics Dev","status":"trusted","environment":"development","permissions":["module.install","server_maintenance.register"],"keys":[{"key_id":"tech-key-dev-1025","status":"active","algorithm":"Ed25519","public_key_file":"public.key"}]}
    (pubdir/'publisher.json').write_text(json.dumps(policy))
    digest=hashlib.sha256(package.read_bytes()).hexdigest(); sig=key.sign(package.read_bytes())
    sigp=root/'serverhealth-0.1.0.zip.sig'; sigp.write_text('ed25519:'+base64.b64encode(sig).decode()+'\n')
    meta={"schema":1,"publisher_id":"tech_flow_dynamics-dev","key_id":"tech-key-dev-1025","filename":"serverhealth-0.1.0.zip","sha256":digest,"signature":"serverhealth-0.1.0.zip.sig","algorithm":"Ed25519","environment":"development"}
    metap=root/'serverhealth-0.1.0.release.json'; metap.write_text(json.dumps(meta))
    args=dict(package_path=package,package_filename='serverhealth-0.1.0.zip',signature_path=sigp,signature_filename='serverhealth-0.1.0.zip.sig',metadata_path=metap,trust_root=trust,server_environment='development')
    ok=verify_release_files(**args); assert ok['verified'] and ok['publisher_id']=='tech_flow_dynamics-dev'
    original=package.read_bytes(); package.write_bytes(original+b'x')
    expect_code('sha256_mismatch', lambda: verify_release_files(**args)); package.write_bytes(original)
    badmeta=dict(meta,key_id='wrong-key'); metap.write_text(json.dumps(badmeta)); expect_code('key_unknown', lambda: verify_release_files(**args)); metap.write_text(json.dumps(meta))
    badmeta=dict(meta,publisher_id='wrong-publisher'); metap.write_text(json.dumps(badmeta)); expect_code('trust_material_missing', lambda: verify_release_files(**args)); metap.write_text(json.dumps(meta))
    policy['keys'][0]['status']='revoked'; (pubdir/'publisher.json').write_text(json.dumps(policy)); expect_code('key_revoked', lambda: verify_release_files(**args)); policy['keys'][0]['status']='active'; (pubdir/'publisher.json').write_text(json.dumps(policy))
    other=Ed25519PrivateKey.generate(); sigp.write_text('ed25519:'+base64.b64encode(other.sign(package.read_bytes())).decode()); expect_code('signature_invalid', lambda: verify_release_files(**args)); sigp.write_text('ed25519:'+base64.b64encode(sig).decode())
    expect_code('signature_required', lambda: verify_release_files(package_path=package,package_filename='serverhealth-0.1.0.zip',signature_path=None,signature_filename=None,metadata_path=None,trust_root=trust,server_environment='development',require_signed=True,required_permissions=('module.install','server_maintenance.register')))
    expect_code('environment_mismatch', lambda: verify_release_files(**{**args,'server_environment':'production'}))
    policy['permissions']=['module.install']; (pubdir/'publisher.json').write_text(json.dumps(policy)); expect_code('publisher_permission_denied', lambda: verify_release_files(**{**args,'required_permissions':('module.install','server_maintenance.register')}))
print('[TEST] PASS trusted publisher verification')
PY
