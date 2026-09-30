# Core 1.15.187

## F8 SSO audit provenance closure (AD-4)

- `session_created` now records read-only authentication provenance in audit metadata.
- Accounts linked to Tactical allauth `SocialAccount` records are audited with `auth_method: sso` and the linked provider (for example `openid_connect`).
- Accounts without an SSO link are audited with `auth_method: password`.
- Tactical remains the authentication authority; Tec-Tac only reads the existing `SocialAccount` relationship when creating its own session audit row.
- The F8 Django integration regression now asserts the SSO method/provider and a real local password/TOTP session's `auth_method: password`.
- F8 prerequisite/skip checks now run before `TestCase.setUpClass()` so skipped environments cannot leak Django's class-level atomic transaction.

Unsigned source delivery.
