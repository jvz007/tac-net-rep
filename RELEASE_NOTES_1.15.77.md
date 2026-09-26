# Tec-Tac Core 1.15.77

## Role permission full-map save regression

- Changed `RoleExtensionPermissionsView` so `core.privileged_operations` is protected only when its requested value actually changes.
- Ordinary Tactical role managers may save normal Tec-Tac permission edits when the UI resends the complete permission map with an unchanged privileged value.
- Both unchanged `false` and unchanged `true` privileged states are permitted; grant/revoke transitions still require an effective superuser.
- Privileged-operation auditing now records only real privileged transitions and includes both the previous and requested values.
- Permission value type validation now runs before privilege-transition evaluation, so malformed full-map values return the normal validation response rather than being treated as an escalation attempt.
- Added `tests/role-permission-save-regression.py` and integrated it into the access API foundation suite.
