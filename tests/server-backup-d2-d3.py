#!/usr/bin/env python3
import base64
import hashlib
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
trust_spec = importlib.util.spec_from_file_location('trusted_publishers_d2d3', ROOT / 'framwork' / 'tec_tac' / 'trusted_publishers.py')
trusted_publishers = importlib.util.module_from_spec(trust_spec); trust_spec.loader.exec_module(trusted_publishers)

# This regression must be ordinary-CI portable. Production requires root-owned
# recovery material; when the test itself is non-root, stub only that ownership
# boundary while retaining the real type/symlink/mode checks and cryptography.
if os.geteuid() != 0:
    import stat
    def _portable_secure_dir(path, *, private=False):
        info = pathlib.Path(path).lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"recovery trust directory is not a real directory: {path}")
        forbidden = 0o077 if private else 0o022
        if info.st_mode & forbidden:
            raise RuntimeError(f"recovery trust directory permissions are unsafe: {path}")
        return info
    def _portable_secure_file(path, *, private=False):
        info = pathlib.Path(path).lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"recovery trust file is not a regular file: {path}")
        forbidden = 0o077 if private else 0o022
        if info.st_mode & forbidden:
            raise RuntimeError(f"recovery trust file permissions are unsafe: {path}")
        return info
    h._secure_root_directory = _portable_secure_dir
    h._secure_regular_root_file = _portable_secure_file
    h.os.chown = lambda *_a, **_k: None
    h.os.fchown = lambda *_a, **_k: None
    def _portable_load_registered_destination(config, destination_id):
        path = h._registered_destination_path(config, destination_id)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("backup destination is not registered; validate it before trusting a recovery signer")
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RuntimeError("registered backup destination permissions are unsafe")
        item = json.loads(path.read_text(encoding="utf-8"))
        item = h.validate_destination(item, config)
        if item["id"] != str(destination_id):
            raise RuntimeError("registered backup destination id mismatch")
        return item
    h.load_registered_destination = _portable_load_registered_destination


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
    h.ensure_runtime_dirs(config)
    h.register_destination(config, {'id':'local','type':'local','name':'test','path':str(td)})
    job={'id':'11111111-1111-4111-8111-111111111111','request':{
        'backup_ref':'destination:local:tec-tac-backup-d3.tgz',
        'destination_id':'local',
        'expected_key_id':'source-a',
        'expected_fingerprint':env['public_key_sha256'],
        'expected_server_name':'old-rmm',
        'expected_installation_id':'source-a',
    },'context':{'requested_by':'admin'}}
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

    # The helper must re-check the exact identity confirmed by the superuser.
    mismatch_trust=td/'mismatch-trust'; mismatch_trust.mkdir()
    target_mismatch_cfg=dict(config); target_mismatch_cfg['TEC_TAC_RECOVERY_TRUST_ROOT']=str(mismatch_trust)
    bad_job=json.loads(json.dumps(job)); bad_job['id']='22222222-2222-4222-8222-222222222222'
    bad_job['request']['expected_fingerprint']='00'*32
    try:
        h.operation_trust_recovery_signer(target_mismatch_cfg,bad_job,io.StringIO())
    except RuntimeError as exc:
        assert 'changed since confirmation' in str(exc)
    else:
        raise AssertionError('recovery signer fingerprint change was accepted')
    assert not (mismatch_trust/'source-a.pub').exists(), 'mismatched signer was trusted'

    # Remote recovery trust resolves only a root-registered destination id; the
    # trust job itself carries no browser-supplied host/secret destination.
    remote_cfg=dict(config)
    h.register_destination(remote_cfg, {
        'id':'remote-a','type':'webdav','url':'https://backup.example.invalid/d3',
        'remote_path':'backups','secret_ref':'11111111-1111-4111-8111-111111111111',
    })
    captured={}
    original_bundle=h._bundle_signer_from_download
    try:
        def fake_bundle(_cfg, destination, _name, _stage, _log):
            captured.update(destination)
            return {
                'key_id':'source-a','public_key_sha256':env['public_key_sha256'],
                'server_name':'old-rmm','installation_id':'source-a',
                'signed_at':h.now(),'trusted':True,'trust_required':False,
                'public_key_pem':public.decode('ascii'),
            }
        h._bundle_signer_from_download=fake_bundle
        remote_job={'id':'33333333-3333-4333-8333-333333333333','request':{
            'backup_ref':'destination:remote-a:tec-tac-backup-remote-d3.tgz','destination_id':'remote-a',
            'expected_key_id':'source-a','expected_fingerprint':env['public_key_sha256'],
            'expected_server_name':'old-rmm','expected_installation_id':'source-a',
        },'context':{'requested_by':'admin'}}
        result=h.operation_trust_recovery_signer(remote_cfg,remote_job,io.StringIO())
        assert result['already_trusted'] is True
        assert captured['id']=='remote-a' and captured['url']=='https://backup.example.invalid/d3'
        assert captured['secret_ref']=='11111111-1111-4111-8111-111111111111'
        missing=json.loads(json.dumps(remote_job)); missing['id']='44444444-4444-4444-8444-444444444444'
        missing['request']['backup_ref']='destination:missing:tec-tac-backup-remote-d3.tgz'; missing['request']['destination_id']='missing'
        try:
            h.operation_trust_recovery_signer(remote_cfg,missing,io.StringIO())
        except RuntimeError as exc:
            assert 'not registered' in str(exc)
        else:
            raise AssertionError('unregistered remote destination was accepted for recovery trust')
    finally:
        h._bundle_signer_from_download=original_bundle

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
    transition=h._restore_version_transition({'TEC_TAC_FRAMEWORK_SOURCE':'/x','TEC_TAC_ROOT':'/y'},manifest)
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

print('[TEST] PASS D2/D3 recovery continuity, trust merge and signer inspection')
