#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def text(path):
    return (ROOT / path).read_text(encoding='utf-8')

backup = text('tests/server-backup-foundation.sh')
for name in ('server-backup-d2-d3.py', 'server-backup-d2-version-transition.py', 'server-backup-d3-service-state.py'):
    assert name in backup, f'{name} is not wired into server-backup-foundation.sh'

review = text('tests/review-hygiene-foundation.sh')
assert 'review-regressions-1.15.52.py' in review
assert 'review-1.15.52-rebuild.sh' in review
for name in ('privileged-helper-environment.py', 'module-artifact-immutable-claim.py', 'server-backup-recovery-trust.py'):
    assert name in review, f'{name} is not wired into portable review hygiene'
assert 'system-update-claim-security.py' not in review, 'root-only system update claim test remains in normal review runner'

module_runner = text('tests/module-management-foundation.sh')
assert 'python3 "${ROOT}/tests/module-v2-verified-bytes-boundary.py"' not in module_runner, 'root-only v2 verified-bytes test remains in normal module runner'
system_runner = text('tests/system-update-foundation.sh')
assert 'system-update-claim-security.py' not in system_runner, 'root-only system update claim test remains in normal system-update runner'

root_runner = text('tests/root-required-foundation.sh')
for name in ('system-update-claim-security.py', 'module-v2-verified-bytes-boundary.py'):
    assert name in root_runner, f'{name} missing from root-required runner'
assert 'requires root privileges' in root_runner

notes = text('docs/releases/RELEASE_NOTES_1.15.83.md')
assert 'not a full behavioral regression harness' in notes
assert 'regression coverage' not in notes.lower(), '1.15.83 still overclaims grep-only checks as regression coverage'

# The dedicated root runner must be safe to invoke from ordinary/non-root CI.
if subprocess.run(['id', 'nobody'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
    proc = subprocess.run(['runuser', '-u', 'nobody', '--', 'bash', str(ROOT / 'tests/root-required-foundation.sh')], text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    assert 'SKIP root-required foundation: requires root privileges' in proc.stdout

print('[TEST] PASS 1.15.146 tracker closure D2 D3 M18 L61 L62')
