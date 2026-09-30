#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_backup_helper_d2d3', ROOT / 'scripts' / 'server-backup-helper.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
trust_spec = importlib.util.spec_from_file_location('trusted_publishers_d2d3', ROOT / 'framwork' / 'tec_tac' / 'trusted_publishers.py')
trusted_publishers = importlib.util.module_from_spec(trust_spec); trust_spec.loader.exec_module(trusted_publishers)

# This decision-level regression is intentionally runnable as an unprivileged
# user. Production writes remain root-owned; only the test's temporary files
# suppress fchown when the runner itself is not root.
if os.geteuid() != 0:
    _real_atomic_json = h.atomic_json
    def _portable_atomic_json(path, payload, *, mode=0o600, uid=None, gid=None):
        return _real_atomic_json(path, payload, mode=mode, uid=None, gid=None)
    h.atomic_json = _portable_atomic_json
    def _portable_recovery_audit(event, *, actor="root", **detail):
        h.RECOVERY_AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with h.RECOVERY_AUDIT_FILE.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps({'event': event, 'actor': actor, **detail}, sort_keys=True) + '\n')
    def _portable_account_audit(*, actor, before, restored, effective):
        h.ACCOUNT_SECURITY_AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        row={'event':'account_security_policy_restore_merge','actor':actor,'before':before,'restored':restored,'effective':effective}
        with h.ACCOUNT_SECURITY_AUDIT_FILE.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(row, sort_keys=True) + '\n')
        _portable_recovery_audit('account_security_policy_restore_merge', actor=actor, before=before, restored=restored, effective=effective)
    h._append_recovery_audit = _portable_recovery_audit
    h._append_account_security_restore_audit = _portable_account_audit

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    framework=td/'framework'; framework.mkdir(); (framework/'VERSION').write_text('1.15.188\n')
    runtime=td/'runtime'; runtime.mkdir()
    config={
        'TEC_TAC_INSTALLATION_ID':'install-a',
        'TEC_TAC_FRAMEWORK_SOURCE':str(framework),
        'TEC_TAC_ROOT':str(runtime),
        'TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS':str(td),
        'TEC_TAC_SERVER_BACKUP_ROOT':str(td/'state'),
        'TACTICAL_ROOT':str(td/'tactical'),
        'TACTICAL_USER':str(os.getuid()),
    }

    # AD-3: every new archive is published with an adjacent SHA-256 companion,
    # and inventory exposes provenance without any recovery signer/trust state.
    archive=td/'tec-tac-backup-ad3.tgz'; archive.write_bytes(b'ad3-backup-bytes')
    metadata=h.metadata_for_archive(archive,'manual',config,components={'tec_tac':{'included':True,'framework_version':'1.15.188'}},recovery_modes=['tec_tac'])
    assert metadata['installation_id']=='install-a'
    assert metadata['server_name']
    assert metadata['core_version']=='1.15.188'
    assert 'recovery_signer' not in metadata
    dest=td/'dest'; result=h.store_local({'id':'local','type':'local','name':'local','path':str(dest)},archive,metadata)
    published=dest/archive.name; hash_path=dest/(archive.name+'.sha256')
    assert published.is_file() and hash_path.is_file() and (dest/(archive.name+'.tectac.json')).is_file()
    assert h.parse_archive_hash_text(hash_path.read_text(),archive.name)==metadata['sha256']
    assert h.verify_archive_hash_companion(config,{'id':'local','type':'local','name':'local','path':str(dest)},archive.name,published,io.StringIO())['status']=='verified'
    item=h.backup_item({'id':'local','type':'local','name':'local'},archive.name,str(published),published.stat().st_size,metadata['created_at'],metadata)
    assert item['installation_id']=='install-a' and item['server_name']==metadata['server_name']
    assert item['created_at']==metadata['created_at'] and item['core_version']=='1.15.188'

    # A present but wrong companion is fatal.
    hash_path.write_text(('0'*64)+'  '+archive.name+'\n')
    try:
        h.verify_archive_hash_companion(config,{'id':'local','type':'local','name':'local','path':str(dest)},archive.name,published,io.StringIO())
    except RuntimeError as exc:
        assert 'companion mismatch' in str(exc)
    else:
        raise AssertionError('AD-3 accepted a mismatched SHA-256 companion')

    # Missing companion remains restorable and is explicitly not verified.
    hash_path.unlink()
    missing=h.verify_archive_hash_companion(config,{'id':'local','type':'local','name':'local','path':str(dest)},archive.name,published,io.StringIO())
    assert missing=={'status':'not_verified','reason':'sha256 companion missing'}

    # New format-2 bundles are unsigned. Build a minimal Tec-Tac-only bundle and
    # prove the normal validator accepts it without a trust step.
    payload=td/'tec-tac-backup.tar.gz'; payload.write_bytes(b'component')
    payload_hash=hashlib.sha256(payload.read_bytes()).hexdigest()
    manifest={
        'format_version':2,'artifact_type':'tec-tac-recovery-bundle','created_at':h.now(),
        'installation_id':'install-a','server_name':'source-rmm','backup_class':'manual',
        'components':{'tactical':{'included':False},'tec_tac':{'included':True,'archive':'tec-tac/tec-tac-backup.tar.gz','sha256':payload_hash,'size_bytes':payload.stat().st_size,'framework_version':'1.15.188'}},
        'recovery_modes':['tec_tac'],
    }
    manifest_bytes=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
    checksums_bytes=(f'{payload_hash}  tec-tac/tec-tac-backup.tar.gz\n').encode()
    unsigned=td/'tec-tac-backup-unsigned-ad3.tgz'
    m=td/'manifest.json'; c=td/'checksums.sha256'; m.write_bytes(manifest_bytes); c.write_bytes(checksums_bytes)
    with tarfile.open(unsigned,'w:gz') as tf:
        tf.add(m,arcname='manifest.json'); tf.add(c,arcname='checksums.sha256'); tf.add(payload,arcname='tec-tac/tec-tac-backup.tar.gz')
    stage=td/'stage'; stage.mkdir()
    parsed,_=h.validate_recovery_bundle(unsigned,'tec_tac',stage,validate_components=False,config=config)
    assert parsed['legacy_signature'] is None

    # Older signed bundles remain readable. The embedded public key verifies the
    # historical signature, but no replacement-server trust decision is needed.
    key=Ed25519PrivateKey.generate()
    public_pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    public_raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    envelope={
        'schema':1,'algorithm':'ed25519','key_id':'legacy-source',
        'public_key_sha256':hashlib.sha256(public_raw).hexdigest(),
        'public_key_pem':public_pem.decode('ascii'),
        'manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),
        'checksums_sha256':hashlib.sha256(checksums_bytes).hexdigest(),
        'signature':base64.b64encode(key.sign(h._recovery_signing_message(manifest_bytes,checksums_bytes))).decode('ascii'),
    }
    sig=td/h.RECOVERY_SIGNATURE_MEMBER; sig.write_text(json.dumps(envelope))
    signed=td/'tec-tac-backup-signed-ad3.tgz'
    with tarfile.open(signed,'w:gz') as tf:
        tf.add(m,arcname='manifest.json'); tf.add(c,arcname='checksums.sha256'); tf.add(sig,arcname=h.RECOVERY_SIGNATURE_MEMBER); tf.add(payload,arcname='tec-tac/tec-tac-backup.tar.gz')
    stage2=td/'stage2'; stage2.mkdir()
    parsed,_=h.validate_recovery_bundle(signed,'tec_tac',stage2,validate_components=False,config=config)
    assert parsed['legacy_signature']['verified'] is True
    assert parsed['legacy_signature']['trust_required'] is False

    # D2 trust/account-policy merge: target state must win over an older backup.
    # This preserves publisher/key revocations, does not resurrect publishers
    # deleted after the backup, keeps the stricter trust floor, and keeps D1 on.
    snap=td/'snap'; (snap/'trusted-publishers'/'pub-a').mkdir(parents=True)
    (snap/'trusted-publishers'/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'revoked'}]}))
    current_policy=snap/'update-trust-policy.json'; current_policy.write_text(json.dumps({'schema':1,'minimum_level':'secure_signed'}))
    current_account_policy=snap/'account-security-policy.json'; current_account_policy.write_text(json.dumps({'schema':1,'protect_superuser_accounts':True}))

    restored_trust=td/'restored-trust'; (restored_trust/'pub-a').mkdir(parents=True)
    (restored_trust/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'active'}]}))
    # pub-deleted existed in the backup but is absent from the current target.
    (restored_trust/'pub-deleted').mkdir()
    (restored_trust/'pub-deleted'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-deleted','status':'trusted'}))
    restored_policy=td/'restored-policy.json'; restored_policy.write_text(json.dumps({'schema':1,'minimum_level':'signed_production'}))
    restored_account_policy=td/'restored-account-policy.json'; restored_account_policy.write_text(json.dumps({'schema':1,'protect_superuser_accounts':False}))

    old_recovery_audit=h.RECOVERY_AUDIT_FILE; old_account_audit=h.ACCOUNT_SECURITY_AUDIT_FILE
    h.RECOVERY_AUDIT_FILE=td/'restore-recovery-audit.jsonl'
    h.ACCOUNT_SECURITY_AUDIT_FILE=td/'account-security-policy-audit.jsonl'
    log=io.StringIO()
    try:
        h._merge_restore_security_state(
            {
                'trust_root':str(snap/'trusted-publishers'),
                'trust_authoritative':True,
                'trust_entries':['pub-a'],
                'policy':str(current_policy),
                'account_policy':str(current_account_policy),
            },
            actor='tester',
            log=log,
            restored_trust=restored_trust,
            restored_policy=restored_policy,
            restored_account_policy=restored_account_policy,
        )
    finally:
        h.RECOVERY_AUDIT_FILE=old_recovery_audit
        h.ACCOUNT_SECURITY_AUDIT_FILE=old_account_audit
    merged=json.loads((restored_trust/'pub-a'/'publisher.json').read_text())
    assert merged['keys'][0]['status']=='revoked'
    assert not (restored_trust/'pub-deleted').exists(), 'deleted publisher was resurrected by restore'
    assert json.loads(restored_policy.read_text())['minimum_level']=='secure_signed'
    assert json.loads(restored_account_policy.read_text())['protect_superuser_accounts'] is True
    account_audit=(td/'account-security-policy-audit.jsonl').read_text()
    recovery_audit=(td/'restore-recovery-audit.jsonl').read_text()
    assert 'account_security_policy_restore_merge' in account_audit
    assert 'account_security_policy_restore_merge' in recovery_audit
    assert 'removed restored-only publishers: pub-deleted' in log.getvalue()


    # D2 regression: on the same installation the current publisher directory
    # replaces the restored directory wholesale. A key deleted after the backup
    # and its public-key file must not be resurrected.
    same_snap=td/'same-snap'; (same_snap/'trusted-publishers'/'pub-a').mkdir(parents=True)
    (same_snap/'trusted-publishers'/'pub-a'/'publisher.json').write_text(json.dumps({
        'schema':1,'publisher_id':'pub-a','status':'trusted',
        'keys':[{'key_id':'k2','status':'active','public_key':'k2.pub'}],
    }))
    (same_snap/'trusted-publishers'/'pub-a'/'k2.pub').write_text('current-k2')
    same_restored=td/'same-restored'; (same_restored/'pub-a').mkdir(parents=True)
    (same_restored/'pub-a'/'publisher.json').write_text(json.dumps({
        'schema':1,'publisher_id':'pub-a','status':'trusted',
        'keys':[
            {'key_id':'k1','status':'active','public_key':'k1.pub'},
            {'key_id':'k2','status':'active','public_key':'k2.pub'},
        ],
    }))
    (same_restored/'pub-a'/'k1.pub').write_text('restored-k1')
    (same_restored/'pub-a'/'k2.pub').write_text('restored-k2')
    h._merge_restore_security_state(
        {'trust_root':str(same_snap/'trusted-publishers'),'trust_authoritative':True,'installation_id':'same-server'},
        actor='tester', log=io.StringIO(), restored_trust=same_restored, source_installation_id='same-server',
    )
    same_policy=json.loads((same_restored/'pub-a'/'publisher.json').read_text())
    assert [item['key_id'] for item in same_policy['keys']]==['k2'], 'same-server restore resurrected a deleted key'
    assert not (same_restored/'pub-a'/'k1.pub').exists(), 'same-server restore kept a deleted key file'
    assert (same_restored/'pub-a'/'k2.pub').read_text()=='current-k2'

    # D2 regression: replacement-server merge normalises legacy current policy
    # before merging so a top-level revoked key cannot be reactivated by a
    # restored keys[] record for the same key.
    legacy_snap=td/'legacy-snap'; (legacy_snap/'trusted-publishers'/'pub-a').mkdir(parents=True)
    (legacy_snap/'trusted-publishers'/'pub-a'/'publisher.json').write_text(json.dumps({
        'schema':1,'publisher_id':'pub-a','status':'trusted',
        'key_id':'k','key_status':'revoked','public_key':'k.pub',
    }))
    legacy_restored=td/'legacy-restored'; (legacy_restored/'pub-a').mkdir(parents=True)
    (legacy_restored/'pub-a'/'publisher.json').write_text(json.dumps({
        'schema':1,'publisher_id':'pub-a','status':'trusted',
        'keys':[{'key_id':'k','status':'active','public_key':'k.pub'}],
    }))
    (legacy_restored/'pub-a'/'k.pub').write_text('placeholder')
    h._merge_restore_security_state(
        {'trust_root':str(legacy_snap/'trusted-publishers'),'trust_authoritative':True,'installation_id':'replacement-server'},
        actor='tester', log=io.StringIO(), restored_trust=legacy_restored, source_installation_id='source-server',
    )
    merged_legacy=json.loads((legacy_restored/'pub-a'/'publisher.json').read_text())
    assert merged_legacy['keys']==[{'key_id':'k','status':'revoked','algorithm':'Ed25519','public_key':'k.pub'}]
    try:
        trusted_publishers._publisher_policy('pub-a','k',trust_root=legacy_restored)
    except trusted_publishers.PublisherTrustError as exc:
        assert exc.code=='key_revoked'
    else:
        raise AssertionError('legacy revoked key became active after replacement-server merge')


    # D2 replacement-server merge keeps publishers that exist only in the restored
    # source installation, while current revoked key state still wins on conflict.
    replacement_snap=td/'replacement-snap'; (replacement_snap/'trusted-publishers'/'pub-a').mkdir(parents=True)
    (replacement_snap/'trusted-publishers'/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'revoked'}]}))
    replacement_restored=td/'replacement-restored'; (replacement_restored/'pub-a').mkdir(parents=True)
    (replacement_restored/'pub-a'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'pub-a','status':'trusted','keys':[{'key_id':'k','status':'active'}]}))
    (replacement_restored/'source-only').mkdir()
    (replacement_restored/'source-only'/'publisher.json').write_text(json.dumps({'schema':1,'publisher_id':'source-only','status':'trusted'}))
    replacement_log=io.StringIO()
    h._merge_restore_security_state(
        {'trust_root':str(replacement_snap/'trusted-publishers'),'trust_authoritative':True,'installation_id':'replacement-server'},
        actor='tester', log=replacement_log, restored_trust=replacement_restored, source_installation_id='source-server',
    )
    assert (replacement_restored/'source-only'/'publisher.json').is_file(), 'replacement restore dropped a source publisher'
    assert json.loads((replacement_restored/'pub-a'/'publisher.json').read_text())['keys'][0]['status']=='revoked'
    assert 'replacement-server restore retained restored-only publishers' in replacement_log.getvalue()

    # D2 downgrade extraction clears stale newer-only files before the backup tree
    # is unpacked and refuses configurable roots that are symlinks or touch Tactical.
    clear_root=td/'clear-runtime'; clear_framework=td/'clear-framework'; clear_ui=td/'clear-ui'
    for root in (clear_root,clear_framework,clear_ui):
        root.mkdir(); (root/'newer-only.py').write_text('stale')
    clear_cfg={'TEC_TAC_ROOT':str(clear_root),'TEC_TAC_FRAMEWORK_SOURCE':str(clear_framework),'TEC_TAC_UI_SOURCE':str(clear_ui),'TACTICAL_ROOT':str(td/'tactical')}
    h._clear_tec_tac_restore_roots(clear_cfg, io.StringIO())
    assert not clear_root.exists() and not clear_framework.exists() and not clear_ui.exists(), 'stale Tec-Tac roots survived pre-extraction clear'
    symlink_root=td/'symlink-runtime'; symlink_root.symlink_to(td/'outside-target', target_is_directory=True)
    bad_cfg=dict(clear_cfg); bad_cfg['TEC_TAC_ROOT']=str(symlink_root)
    try:
        h._clear_tec_tac_restore_roots(bad_cfg, io.StringIO())
    except RuntimeError as exc:
        assert 'symlinked' in str(exc)
    else:
        raise AssertionError('symlinked Tec-Tac restore root was accepted')

    # An older Core restore is allowed but must produce a clear transition notice.
    original=h.detect_version
    h.detect_version=lambda path: '1.15.86'
    old_manifest=json.loads(json.dumps(manifest)); old_manifest['components']['tec_tac']['framework_version']='1.15.83'
    transition=h._restore_version_transition({'TEC_TAC_FRAMEWORK_SOURCE':'/x','TEC_TAC_ROOT':'/y'},old_manifest)
    h.detect_version=original
    assert transition['is_core_downgrade'] is True
    assert 'puts Core back to 1.15.83' in transition['notice']


    # D2 rebuild regression: on a replacement server, a restored-only key must
    # never keep a filename that is overwritten by a different current key.
    # Dropping the restored-only key on a differing-byte collision is allowed by
    # the restore contract and fails closed for any package that claims its id.
    def _pub_text(key):
        raw=key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return 'ed25519:'+base64.b64encode(raw).decode()+'\n'

    def _assert_colliding_replacement_fails(*, legacy=False):
        current_key=Ed25519PrivateKey.generate()   # kB: current, revoked
        restored_key=Ed25519PrivateKey.generate() # kA: restored-only, active
        suffix='legacy' if legacy else 'keys'
        snap=td/f'collision-{suffix}-snap'; current_dir=snap/'trusted-publishers'/'P'; current_dir.mkdir(parents=True)
        restored_root=td/f'collision-{suffix}-restored'; restored_dir=restored_root/'P'; restored_dir.mkdir(parents=True)
        if legacy:
            current_policy={'schema':1,'publisher_id':'P','status':'trusted','key_id':'kB','key_status':'revoked','algorithm':'Ed25519','public_key':'public.key','environment':'development','permissions':['module.install']}
            restored_policy={'schema':1,'publisher_id':'P','status':'trusted','key_id':'kA','key_status':'active','algorithm':'Ed25519','public_key':'public.key','environment':'development','permissions':['module.install']}
        else:
            current_policy={'schema':1,'publisher_id':'P','status':'trusted','environment':'development','permissions':['module.install'],'keys':[{'key_id':'kB','status':'revoked','algorithm':'Ed25519','public_key':'public.key'}]}
            restored_policy={'schema':1,'publisher_id':'P','status':'trusted','environment':'development','permissions':['module.install'],'keys':[{'key_id':'kA','status':'active','algorithm':'Ed25519','public_key':'public.key'}]}
        (current_dir/'publisher.json').write_text(json.dumps(current_policy))
        (current_dir/'public.key').write_text(_pub_text(current_key))
        (restored_dir/'publisher.json').write_text(json.dumps(restored_policy))
        original_restored_bytes=_pub_text(restored_key).encode()
        (restored_dir/'public.key').write_bytes(original_restored_bytes)

        h._merge_restore_security_state(
            {'trust_root':str(snap/'trusted-publishers'),'trust_authoritative':True,'installation_id':'replacement-server'},
            actor='tester', log=io.StringIO(), restored_trust=restored_root, source_installation_id='source-server',
        )

        # kA may be preserved only if it still resolves to its original bytes.
        # This implementation deliberately drops it on a differing-byte filename
        # collision, so _publisher_policy must fail rather than alias kB's file.
        try:
            _policy,_record,key_path=trusted_publishers._publisher_policy('P','kA',trust_root=restored_root)
        except trusted_publishers.PublisherTrustError as exc:
            assert exc.code in {'key_unknown','key_revoked'}, (legacy, exc.code)
        else:
            assert key_path.read_bytes()==original_restored_bytes, 'restored-only kA resolved to current kB bytes'

        assert (restored_dir/'public.key').read_text()==_pub_text(current_key), 'current key file did not remain authoritative'

        # A package signed by compromised kB but labelled kA must fail trusted
        # publisher verification after the merge.
        package=td/f'collision-{suffix}.zip'; package.write_bytes(b'collision regression package')
        sig=td/f'collision-{suffix}.zip.sig'; sig.write_text('ed25519:'+base64.b64encode(current_key.sign(package.read_bytes())).decode()+'\n')
        meta={
            'schema':1,'publisher_id':'P','key_id':'kA','filename':package.name,
            'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'signature':sig.name,
            'algorithm':'Ed25519','environment':'development',
        }
        metap=td/f'collision-{suffix}.release.json'; metap.write_text(json.dumps(meta))
        try:
            trusted_publishers.verify_release_files(
                package_path=package, package_filename=package.name,
                signature_path=sig, signature_filename=sig.name, metadata_path=metap,
                required_permissions=('module.install',), trust_root=restored_root,
                server_environment='development', require_signed=True,
            )
        except trusted_publishers.PublisherTrustError as exc:
            assert exc.code in {'key_unknown','key_revoked','signature_invalid'}, (legacy, exc.code)
        else:
            raise AssertionError('kB signature labelled as restored-only kA verified after filename collision')

    _assert_colliding_replacement_fails(legacy=False)
    _assert_colliding_replacement_fails(legacy=True)

print('[TEST] PASS D2/D3 recovery continuity, AD-3 hash verification and legacy signed-bundle compatibility')
