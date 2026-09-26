#!/usr/bin/env python3
from pathlib import Path
import os, subprocess, sys, textwrap
ROOT=Path(sys.argv[1]).resolve()
helper=ROOT/'scripts/server-backup-helper.py'
env=os.environ.copy()
env.update({'TEC_TAC_CONFIG_FILE':'/tmp/attacker.conf','TEC_TAC_SERVER_BACKUP_ROOT':'/tmp/attacker-state','TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS':'/'})
code=textwrap.dedent(f'''
import importlib.util
spec=importlib.util.spec_from_file_location("sb", {str(helper)!r})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert str(m.CONFIG)=="/opt/tec-tac/etc/tec-tac.conf", m.CONFIG
cfg=m.load_config()
assert cfg["TEC_TAC_SERVER_BACKUP_ROOT"]!="/tmp/attacker-state", cfg
assert cfg["TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS"]!="/", cfg
print("server backup environment override rejection: PASS")
''')
subprocess.run([sys.executable,'-c',code],env=env,check=True)
text=helper.read_text(encoding='utf-8')
assert 'CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")' in text
assert 'os.environ.get("TEC_TAC_CONFIG_FILE"' not in text
assert 'st.st_uid != 0 or (st.st_mode & 0o022)' in text
assert 'stat.S_ISLNK(st.st_mode)' in text
print('server backup root layout: PASS')
