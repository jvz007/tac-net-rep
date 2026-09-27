#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import pathlib
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

hk=load('hk_m8', ROOT/'framwork/tec_tac/housekeeping.py')
helper=load('hk_helper_m8', ROOT/'scripts/housekeeping-helper.py')

with tempfile.TemporaryDirectory() as td:
    base=pathlib.Path(td)
    config_dir=base/'config'; config_dir.mkdir()
    hk.CONFIG_DIR=config_dir; hk.CONFIG=config_dir/'config.json'

    policies={k:dict(v) for k,v in hk.DEFAULT_POLICIES.items()}
    age_key='module_staging'; keep_key='system_update_backups'
    policies[age_key]['days']=0
    policies[keep_key]['keep']='0'
    hk.CONFIG.write_text(json.dumps({'policies':policies,'allow_zero_destructive':True}), encoding='utf-8')

    loaded=hk._load_config()
    assert loaded['policies'][age_key]['days']==hk.DEFAULT_POLICIES[age_key]['days']
    assert loaded['policies'][keep_key]['keep']==hk.DEFAULT_POLICIES[keep_key]['keep']
    assert loaded['allow_zero_destructive'] is False

    # New writes remain strict; zero is compatibility input only, never a newly
    # persisted policy value.
    try:
        hk.save_config({'policies':policies})
    except hk.HousekeepingError as exc:
        assert 'between 1 and 3650' in str(exc)
    else:
        raise AssertionError('new zero-valued policy was accepted')

    # The privileged helper independently repairs an already-queued legacy
    # zero request on its real main() path.
    with tempfile.TemporaryDirectory() as state_dir:
        state=pathlib.Path(state_dir)
        helper.STATE=state
        helper.ROOT=state/'housekeeping'
        helper.RESULTS=helper.ROOT/'results'
        helper.RUNNING=helper.ROOT/'running'
        requests=helper.ROOT/'requests'
        requests.mkdir(parents=True)
        helper.RESULTS.mkdir()
        helper.RUNNING.mkdir()
        target=state/'module-staging'; target.mkdir()
        helper.CATEGORY_PATHS={age_key:[(target,'children',None)]}
        helper.JOB_ROOTS={}
        helper.STAGING_CATEGORIES=set(); helper.HISTORY_CATEGORIES=set()
        helper.ACTIVE_GUARD_CATEGORIES=set()
        helper.DEFAULTS={age_key:dict(helper.DEFAULTS[age_key])}
        req=requests/'11111111-1111-4111-8111-111111111111.json'
        req.write_text(json.dumps({
            'dry_run':True,
            'categories':[age_key],
            'policies':{age_key:{'mode':'age_days','days':0}},
            'allow_zero_destructive':True,
        }), encoding='utf-8')
        captured={}
        helper.claim_request=lambda path:path
        helper._write_result=lambda request_id,payload:captured.update(payload) or pathlib.Path('/dev/null')
        old_argv=list(helper.sys.argv)
        helper.sys.argv=['tec-tac-housekeeping','--scan',str(req)]
        try:
            helper.main()
        finally:
            helper.sys.argv=old_argv
        assert captured['ok'] is True
        assert captured['categories'][0]['policy']['days']==helper.DEFAULTS[age_key]['days']
        assert captured['allow_zero_destructive'] is False

    # Non-zero invalid values are not silently repaired.
    policies[age_key]['days']=-1
    hk.CONFIG.write_text(json.dumps({'policies':policies}), encoding='utf-8')
    loaded=hk._load_config()
    assert loaded['policies'][age_key]['days']==-1

print('housekeeping legacy zero compatibility: PASS')
