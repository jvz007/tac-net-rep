#!/usr/bin/env python3
from pathlib import Path
import os, subprocess, sys, tempfile, textwrap
ROOT=Path(sys.argv[1]).resolve()
helper=ROOT/'scripts/server-maintenance-helper.py'

# Caller environment must not control any privileged helper trust root.
env=os.environ.copy()
env.update({
    'TEC_TAC_SERVER_MAINTENANCE_ROOT':'/tmp/attacker-state',
    'TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT':'/tmp/attacker-registry',
    'TEC_TAC_SERVER_MAINTENANCE_ACTION_ROOT':'/tmp/attacker-actions',
    'TEC_TAC_CONFIG_FILE':'/tmp/attacker.conf',
})
code=textwrap.dedent(f'''
import importlib.util
spec=importlib.util.spec_from_file_location("sm", {str(helper)!r})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert str(m.CONFIG)=="/opt/tec-tac/etc/tec-tac.conf", m.CONFIG
assert str(m.STATE_ROOT)!="/tmp/attacker-state", m.STATE_ROOT
assert str(m.REGISTRY_ROOT)!="/tmp/attacker-registry", m.REGISTRY_ROOT
assert str(m.ACTION_ROOT)!="/tmp/attacker-actions", m.ACTION_ROOT
print("environment override rejection: PASS")
''')
subprocess.run([sys.executable,'-c',code],env=env,check=True)

text=helper.read_text(encoding='utf-8')
for bad in (
    'os.environ.get("TEC_TAC_SERVER_MAINTENANCE_ROOT"',
    'os.environ.get("TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT"',
    'os.environ.get("TEC_TAC_SERVER_MAINTENANCE_ACTION_ROOT"',
    'os.environ.get("TEC_TAC_CONFIG_FILE"',
):
    assert bad not in text, bad
assert 'CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")' in text
assert 'st.st_uid != 0 or (st.st_mode & 0o022)' in text
assert 'stat.S_ISLNK(st.st_mode)' in text
print('server maintenance root layout: PASS')
