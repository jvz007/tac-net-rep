# Review scope: Tec-Tac Core 1.15.93

This release is intentionally narrow. Review the items below and do not treat unrelated tracker items as part of this build.

## Tracker items in this release

### L81 - account-security audit rollback

Expected result:
- `AccountSecurityPolicyView.put()` treats both `AuditWriteError` and `AuditContractError` as a failed audited mutation.
- The requested policy value is not retained without a strict Core audit record.
- If the prior policy was readable, the previous logical value is restored.

Primary files:
- `framwork/tec_tac/account_security_views.py`
- `tests/account-security-policy-edge-cases.py`

### L82 - valid Tactical usernames rejected as policy actor

Expected result:
- Usernames containing `+` and Unicode characters are accepted as `updated_by`.
- Actor data remains bounded to Tactical's 150-character username limit and rejects NUL.
- The helper is still invoked with a subprocess argv list; no shell interpolation is introduced.

Primary files:
- `framwork/tec_tac/account_security_policy.py`
- `tests/account-security-policy-edge-cases.py`

### L84 - corrupt policy cannot be repaired through API

Expected result:
- An effective superuser can replace an unreadable/corrupt policy with a valid requested policy.
- The audit `before` value records `policy_state=unreadable` and metadata records `repaired_corrupt_policy=true`.
- If the strict audit cannot be written, the requested unaudited repair is not retained; Core forces protection ON as the fail-closed state.

Primary files:
- `framwork/tec_tac/account_security_views.py`
- `tests/account-security-policy-edge-cases.py`

## Explicitly not in this release

- L85: sudo authority for the `tactical` OS user.
- L86: replacement of remaining root/grep-only D1 tests.
- U3 is in the paired UI 0.12.41 package, not this Core package.
- No M2+ work is included.
