#!/usr/bin/env python3
import importlib.util
import io
import json
import os
import pathlib
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_backup_helper_d2d3', ROOT / 'scripts' / 'server-backup-helper.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def make_identity(base, key_id='source-a', trust=True):
    signing=base/'sign'; trust_root=base/'recovery-trust'; signing.mkdir(); trust_root.mkdir()
    os.chmod(signing,0o700); os.chmod(trust_root,0o755)
    key=Ed25519PrivateKey.generate()
    private=signing/'private.pem'; private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); os.chmod(private,0o600)
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    if trust:
        (trust_root/f'{key_id}.pub').write_bytes(public); os.chmod(trust_root/f'{key_id}.pub',0o644)
    return key,private,public,trust_root


def cfg(private, trust_root, key_id='source-a'):
    return {'TEC_TAC_INSTALLATION_ID':key_id,'TEC_TAC_RECOVERY_SIGNING_KEY':str(private),'TEC_TAC_RECOVERY_TRUST_ROOT':str(trust_root),'TEC_TAC_FRAMEWORK_SOURCE':'/no/framework','TEC_TAC_ROOT':'/no/runtime'}

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    key, private, public, trust_root = make_identity(td, trust=False)
    config=cfg(private, trust_root)
    manifest={'format_version':2,'artifact_type':'tec-tac-recovery-bundle','created_at':h.now(),'installation_id':'source-a','server_name':'old-rmm','components':{'tec_tac':{'included':True,'framework_version':'1.15.83'}},'recovery_modes':['tec_tac']}
    mb=(json.dumps(manifest,sort_keys=True)+'\n').encode(); cb=b''
    env=h.create_recovery_signature(config,mb,cb)
    eb=(json.dumps(env,sort_keys=True)+'\n').encode()
    inspected=h.verify_recovery_signature(config,mb,cb,eb,allow_untrusted=True)
    assert inspected['verified'] is True and inspected['trusted'] is False and inspected['trust_required'] is True
    try:
        h.verify_recovery_signature(config,mb,cb,eb)
    except RuntimeError as exc:
        assert 'not trusted' in str(exc)
    else:
        raise AssertionError('destructive trust boundary accepted unknown signer')

    # One-confirmation trust path validates the bundle with its candidate key, then writes that exact public key.
    bundle=td/'tec-tac-backup-d3.tgz'
    import tarfile
    mpath=td/'manifest.json'; cpath=td/'checksums.sha256'; epath=td/h.RECOVERY_SIGNATURE_MEMBER
    mpath.write_bytes(mb); cpath.write_bytes(cb); epath.write_bytes(eb)
    with tarfile.open(bundle,'w:gz') as tf:
        tf.add(mpath,arcname='manifest.json'); tf.add(cpath,arcname='checksums.sha256'); tf.add(epath,arcname=h.RECOVERY_SIGNATURE_MEMBER)
    state=td/'state'
    config.update({'TEC_TAC_SERVER_BACKUP_ROOT':str(state),'TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS':str(td),'TACTICAL_USER':'root'})
    job={'id':'11111111-1111-4111-8111-111111111111','request':{'backup_ref':'destination:local:tec-tac-backup-d3.tgz','destination':{'id':'local','type':'local','name':'test','path':str(td)}},'context':{'requested_by':'admin'}}
    old_audit=h.RECOVERY_AUDIT_FILE; h.RECOVERY_AUDIT_FILE=td/'recovery-audit.jsonl'
    try:
        result=h.operation_trust_recovery_signer(config,job,io.StringIO())
    finally:
        h.RECOVERY_AUDIT_FILE=old_audit
    assert result['ok'] is True and result['signer']['trusted'] is True
    trusted=(trust_root/'source-a.pub')
    assert trusted.read_bytes()==public
    audit=(td/'recovery-audit.jsonl').read_text()
    assert 'recovery_signer_trusted' in audit and 'admin' in audit

    # Trust-floor merge: target/current secure_signed must survive an older restored signed_production policy.
    snap=td/'snap'; (snap/'trusted-publishers'/'pub-a').mkdir(parents=True)
    (snap/'trusted-publishers'/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'revoked'}]}))
    current_policy=snap/'update-trust-policy.json'; current_policy.write_text(json.dumps({'schema':1,'minimum_level':'secure_signed'}))
    restored_trust=td/'restored-trust'; (restored_trust/'pub-a').mkdir(parents=True)
    (restored_trust/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'active'}]}))
    restored_policy=td/'restored-policy.json'; restored_policy.write_text(json.dumps({'schema':1,'minimum_level':'signed_production'}))
    log=io.StringIO()
    h._merge_restore_security_state({'trust_root':str(snap/'trusted-publishers'),'policy':str(current_policy)},actor='tester',log=log,restored_trust=restored_trust,restored_policy=restored_policy)
    merged=json.loads((restored_trust/'pub-a'/'publisher.json').read_text())
    assert merged['keys'][0]['status']=='revoked'
    assert json.loads(restored_policy.read_text())['minimum_level']=='secure_signed'

    # An older Core restore is allowed but must produce a clear transition notice.
    original=h.detect_version
    h.detect_version=lambda path: '1.15.86'
    transition=h._restore_version_transition({'TEC_TAC_FRAMEWORK_SOURCE':'/x','TEC_TAC_ROOT':'/y'},manifest)
    h.detect_version=original
    assert transition['is_core_downgrade'] is True
    assert 'puts Core back to 1.15.83' in transition['notice']

source=(ROOT/'scripts'/'server-backup-helper.py').read_text()
assert 'recovery_signer_trusted' in source
assert 'version_transition' in source
assert '_merge_restore_security_state' in source
assert 'allow_untrusted_signer=True' in source
assert 'recovery-signature.json' in source

install=(ROOT/'install.sh').read_text()
assert 'tec-tac-recovery-key' in install
cli=(ROOT/'scripts'/'recovery-key-cli.py').read_text()
assert "add_parser('export')" in cli and "add_parser('import')" in cli and "add_parser('status')" in cli

print('[TEST] PASS D2/D3 recovery continuity, trust merge and signer inspection')
