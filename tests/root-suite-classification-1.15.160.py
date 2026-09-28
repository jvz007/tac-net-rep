#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
review=(ROOT/'tests/review-hygiene-foundation.sh').read_text()
portable=(ROOT/'tests/portable-privileged-foundation.sh').read_text()
root=(ROOT/'tests/root-required-foundation.sh').read_text()
for name in ('privileged-helper-environment.py','module-artifact-immutable-claim.py','server-backup-recovery-trust.py'):
    assert name in portable, f'{name} is not wired to the portable runner'
    assert name not in root, f'{name} incorrectly remains root-only'
assert 'portable-privileged-foundation.sh' in review, 'portable security runner is not in review hygiene'
for name in ('system-update-claim-security.py','module-v2-verified-bytes-boundary.py'):
    assert name in root, f'{name} missing from explicit root-only runner'
    assert name not in review, f'{name} leaked into normal review runner'
assert 'requires root privileges' in root, 'root-only runner does not state its privilege requirement'
print('[TEST] PASS M18/L61 portable and root-required suites are explicitly separated and wired')
