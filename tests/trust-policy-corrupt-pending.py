#!/usr/bin/env python3
"""M9: corrupt pending trust-policy revert must fail closed."""
from __future__ import annotations
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('trust_policy_cli_m9', ROOT/'scripts'/'trust-policy-cli.py')
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

def configure(td: Path, *, env: str, level: str):
    mod.CONFIG_FILE = td/'tec-tac.conf'
    mod.POLICY_ROOT = td/'policy'
    mod.POLICY_FILE = mod.POLICY_ROOT/'update-trust-policy.json'
    mod.PENDING_FILE = mod.POLICY_ROOT/'pending-trust-policy-revert.json'
    mod.AUDIT_DIR = td/'audit'
    mod.AUDIT_FILE = mod.AUDIT_DIR/'trust-policy-audit.jsonl'
    mod.CONFIG_FILE.write_text(f'TEC_TAC_ENVIRONMENT={env}\n', encoding='utf-8')
    mod.POLICY_ROOT.mkdir(parents=True)
    mod.POLICY_FILE.write_text(json.dumps({'schema':1,'minimum_level':level,'updated_at':None,'updated_by':'test'})+'\n', encoding='utf-8')
    mod.PENDING_FILE.write_bytes(b'{ definitely not json')
    mod.os.chown = lambda *a, **k: None

def audit_rows():
    return [json.loads(x) for x in mod.AUDIT_FILE.read_text(encoding='utf-8').splitlines() if x.strip()]

with tempfile.TemporaryDirectory(prefix='tec-tac-m9-') as raw:
    td=Path(raw)
    configure(td, env='production', level='unsigned')
    result=mod.check_revert_due()
    assert result['status']=='corrupt_pending_recovered', result
    assert result['minimum_level']=='signed_production', result
    assert mod.read_policy()['minimum_level']=='signed_production'
    assert not mod.PENDING_FILE.exists()
    rows=audit_rows(); assert rows[-1]['event']=='policy_pending_revert_corrupt_recovered'
    assert rows[-1]['restored_level']=='signed_production'

with tempfile.TemporaryDirectory(prefix='tec-tac-m9-strong-') as raw:
    td=Path(raw)
    configure(td, env='production', level='secure_signed')
    result=mod.check_revert_due()
    assert result['minimum_level']=='secure_signed', result
    assert mod.read_policy()['minimum_level']=='secure_signed'
    assert not mod.PENDING_FILE.exists()

with tempfile.TemporaryDirectory(prefix='tec-tac-m9-dev-') as raw:
    td=Path(raw)
    configure(td, env='development', level='unsigned')
    result=mod.check_revert_due()
    assert result['minimum_level']=='signed_development', result

print('M9 corrupt pending trust-policy recovery: PASS')

with tempfile.TemporaryDirectory(prefix='tec-tac-m9-semantic-') as raw:
    td=Path(raw)
    configure(td, env='production', level='unsigned')
    mod.PENDING_FILE.write_text(json.dumps({'schema':1,'change_id':'x','previous_level':'bogus','temporary_level':'unsigned','expires_at':'bad'})+'\n')
    result=mod.check_revert_due()
    assert result['minimum_level']=='signed_production', result
    assert not mod.PENDING_FILE.exists()

with tempfile.TemporaryDirectory(prefix='tec-tac-m9-set-order-') as raw:
    td=Path(raw)
    configure(td, env='production', level='unsigned')
    confirmations=[]
    mod.confirm=lambda current,target,hours,reason: confirmations.append((current,target))
    result=mod.set_level('signed_development', reason='test', hours=8)
    assert confirmations==[('signed_production','signed_development')], confirmations
    assert result['temporary'] is True
    assert result['revert_level']=='signed_production'

print('M9 semantic corruption and set ordering: PASS')
