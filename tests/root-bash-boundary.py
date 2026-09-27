#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
files=[
 'scripts/server-backup-helper.py','scripts/system-update-helper.py','scripts/module-v2-job-helper.py',
 'scripts/module-hotfix-job-helper.py','scripts/module-job-helper.py',
]
for rel in files:
    text=(ROOT/rel).read_text(encoding='utf-8')
    assert 'def _trusted_bash()' in text, rel
    assert 'stat.S_ISREG(info.st_mode)' in text and 'info.st_uid == 0' in text and 'info.st_mode & 0o022' in text, rel
    # /usr/bin/bash may exist only as one candidate in the fixed resolver.
    for line in text.splitlines():
        if '"/usr/bin/bash"' in line:
            assert 'for raw in ("/bin/bash", "/usr/bin/bash")' in line, (rel,line)
print('[TEST] PASS privileged bash fixed-list/root-ownership boundary')
