#!/usr/bin/python3
import importlib.util, json, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_backup_helper', ROOT/'scripts/server-backup-helper.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)

with tempfile.TemporaryDirectory() as td:
    cfg={'TEC_TAC_SERVER_BACKUP_ROOT': td}
    rs=h.roots(cfg); rs['secrets'].mkdir(parents=True)
    a={'id':'a','type':'sftp','host':'backup.example.com','port':22,'username':'backup','remote_path':'/one'}
    b={'id':'b','type':'sftp','host':'evil.example.com','port':22,'username':'backup','remote_path':'/one'}
    c={'id':'c','type':'sftp','host':'BACKUP.EXAMPLE.COM','port':22,'username':'backup','remote_path':'/two'}
    binding=h.destination_credential_binding(a,cfg)
    ref='11111111-1111-4111-8111-111111111111'
    h.atomic_json(rs['secrets']/f'{ref}.json', {'version':1,'binding':binding,'secret':{'password':'secret'}}, mode=0o600)
    a['secret_ref']=ref; b['secret_ref']=ref; c['secret_ref']=ref
    assert h.load_secret(cfg,a)=={'password':'secret'}
    assert h.load_secret(cfg,c)=={'password':'secret'}, 'remote path/id must not change network credential endpoint binding'
    try:
        h.load_secret(cfg,b)
    except RuntimeError as exc:
        assert 'different destination endpoint' in str(exc)
    else:
        raise AssertionError('credential was reusable against another host')
    legacy='22222222-2222-4222-8222-222222222222'
    h.atomic_json(rs['secrets']/f'{legacy}.json', {'password':'old'}, mode=0o600)
    a['secret_ref']=legacy
    try:
        h.load_secret(cfg,a)
    except RuntimeError as exc:
        assert 'legacy/unbound' in str(exc)
    else:
        raise AssertionError('legacy unbound credential remained usable remotely')
print('server backup credential binding regression OK')
