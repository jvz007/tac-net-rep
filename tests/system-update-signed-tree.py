#!/usr/bin/env python3
import base64, hashlib, importlib.util, json, os, shutil, sys, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'framwork'))
os.environ['TEC_TAC_ENVIRONMENT']='development'
from tec_tac.trusted_publishers import PublisherTrustError, verify_release_tree
from tec_tac import system_update

spec=importlib.util.spec_from_file_location('system_update_helper',ROOT/'scripts/system-update-helper.py')
helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def make_tree(base, *, key_id='key-dev', status='active'):
    root=base/'tree'; trust=base/'trust'/'publisher-dev'; root.mkdir(parents=True); trust.mkdir(parents=True)
    (root/'VERSION').write_text('1.15.36\n'); (root/'install.sh').write_text('#!/bin/sh\n'); (root/'framwork'/'tec_tac').mkdir(parents=True); (root/'framwork'/'tec_tac'/'__init__.py').write_text('x=1\n')
    private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    (trust/'public.key').write_text('ed25519:'+base64.b64encode(public).decode()+'\n')
    policy={'schema':1,'publisher_id':'publisher-dev','display_name':'Publisher Dev','status':'trusted','permissions':['module.install'],'environment':'development','keys':[{'key_id':key_id,'status':status,'algorithm':'Ed25519','public_key_file':'public.key'}]}
    (trust/'publisher.json').write_text(json.dumps(policy,indent=2)+'\n')
    files=[]
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        rel=path.relative_to(root).as_posix(); files.append({'path':rel,'size':path.stat().st_size,'sha256':sha(path)})
    manifest={'schema':2,'component':'framework','version':'1.15.36','publisher_id':'publisher-dev','key_id':key_id,'algorithm':'Ed25519','files':files}
    raw=(json.dumps(manifest,indent=2)+'\n').encode(); (root/'tec-tac-release.json').write_bytes(raw)
    sig=private.sign(raw); (root/'tec-tac-release.json.sig').write_text('ed25519:'+base64.b64encode(sig).decode()+'\n')
    return root, base/'trust'

def expect_code(fn, code):
    try: fn()
    except PublisherTrustError as exc:
        assert exc.code==code,(exc.code,code,str(exc)); return
    raise AssertionError('expected '+code)

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp); root, trustroot=make_tree(base)
    result=verify_release_tree(root=root,expected_component='framework',trust_root=trustroot,server_environment='development')
    assert result['verified'] and result['file_count']==3 and result['publisher_id']=='publisher-dev'
    helper.verify_signed_tree_snapshot(root,'framework','1.15.36',result)
    # changed bytes
    (root/'install.sh').write_text('tampered\n')
    expect_code(lambda: verify_release_tree(root=root,expected_component='framework',trust_root=trustroot,server_environment='development'),'tree_mismatch')
    try: helper.verify_signed_tree_snapshot(root,'framework','1.15.36',result)
    except RuntimeError as exc: assert 'differs' in str(exc)
    else: raise AssertionError('worker accepted changed checkout')

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp); root, trustroot=make_tree(base)
    (root/'tec-tac-release.json.sig').unlink()
    expect_code(lambda: verify_release_tree(root=root,expected_component='framework',trust_root=trustroot,server_environment='development'),'tree_signature_material_incomplete')

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp); root, trustroot=make_tree(base,status='revoked')
    expect_code(lambda: verify_release_tree(root=root,expected_component='framework',trust_root=trustroot,server_environment='development'),'key_revoked')

with tempfile.TemporaryDirectory() as tmp:
    base=Path(tmp); root, trustroot=make_tree(base)
    policy=json.loads((trustroot/'publisher-dev'/'publisher.json').read_text()); policy['keys'][0]['key_id']='other'; (trustroot/'publisher-dev'/'publisher.json').write_text(json.dumps(policy))
    expect_code(lambda: verify_release_tree(root=root,expected_component='framework',trust_root=trustroot,server_environment='development'),'key_unknown')

# Stable release cutoff: old unsigned allowed, new unsigned rejected; branches remain transitional.
old=system_update._unsigned_release_trust(component='framework',version='1.15.36',source={'type':'release'})
assert old['legacy'] and old['label']=='Unsigned / legacy'
try: system_update._unsigned_release_trust(component='framework',version='1.15.37',source={'type':'release'})
except system_update.SystemUpdateError: pass
else: raise AssertionError('unsigned 1.15.37 stable release bypassed cutoff')
branch=system_update._unsigned_release_trust(component='framework',version='9.0.0',source={'type':'branch'})
assert not branch['legacy'] and branch['label']=='Unsigned'
print('[TEST] PASS signed System Update tree verification and cutoff')
