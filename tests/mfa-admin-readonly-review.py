#!/usr/bin/env python3
"""L47-L49: protected admin MFA reads are guarded/read-only and audits are distinct."""
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
views = (ROOT / 'framwork/tec_tac/mfa_backup_views.py').read_text(encoding='utf-8')
mfa = (ROOT / 'framwork/tec_tac/mfa_backup.py').read_text(encoding='utf-8')

# The administrator GET must enforce the protected-account boundary before it
# asks for status, and the status call must not attribute a read to the admin.
block = views.split('class AdminUserMfaRecoveryView', 1)[1].split('    def delete(', 1)[0]
guard = 'can_administer_account_security_target(request.user, target)'
status = 'backup_code_status(target)'
assert guard in block, 'protected-target guard missing from admin MFA GET'
assert status in block, 'read-only status call missing from admin MFA GET'
assert block.index(guard) < block.index(status), 'MFA status is read before protected-account authorization'
assert 'backup_code_status(target, requested_by=' not in block, 'admin GET still attributes status-side mutation to administrator'

# GET/status must be structurally read-only: no transaction/deletion/audit path.
tree = ast.parse(mfa)
status_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'backup_code_status')
calls = {getattr(n.func, 'id', None) or getattr(n.func, 'attr', None) for n in ast.walk(status_fn) if isinstance(n, ast.Call)}
assert '_delete_stale_codes_locked' not in calls, 'backup_code_status still deletes stale codes on read'
assert '_security_audit' not in calls, 'backup_code_status still audits a read as a mutation'

# Explicit admin invalidation and automatic TOTP-change invalidation must remain
# distinguishable during an investigation.
assert '"mfa_backup_codes_invalidated_totp_change"' in mfa
assert '"mfa_backup_codes_invalidated"' in mfa
assert 'reason="totp-key-changed"' in mfa
assert '"explicit": True' in mfa
print('[TEST] PASS admin MFA status is protected/read-only and invalidation audits are distinct')
