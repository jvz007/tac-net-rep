# Account security policy

Tec-Tac can optionally add a stricter protection boundary around existing Tactical superuser accounts without changing Tactical source.

## Policy

The root-owned policy is stored at:

```text
/etc/tec-tac/policy/account-security-policy.json
```

`protect_superuser_accounts` defaults to `false`. With the default off, Tactical's normal account-management behaviour applies, except that Tec-Tac always keeps the existing superuser-grant boundary: only an effective superuser may grant or revoke superuser authority.

When protection is enabled, only an effective native or role superuser may act on an account that is currently a native superuser or belongs to a superuser role. Protected operations include account edit/delete, password reset, TOTP reset and API-key create/update/delete. Self-service password/TOTP operations remain available to the superuser acting on their own account.

## Administration

Account managers can read the current policy from `GET /api/tfd/access/security-policy/`. Only an effective superuser can change it with `PUT /api/tfd/access/security-policy/`. The UI exposes the setting under **Access -> Account protection**.

The Django process never writes the policy file directly. Changes are delegated to the root-owned Tec-Tac privileged helper and are audited through the Core audit contract.

The privileged helper also writes a second root-owned audit trail before every policy mutation at:

```text
/var/log/tec-tac/account-security-policy-audit.jsonl
```

That root audit records the real sudo invoker (`SUDO_USER`/`SUDO_UID`) separately from the application actor label, the previous policy state, and the requested state. If the root audit cannot be written safely, the helper refuses the policy mutation. This means a direct privileged invocation cannot change D1 silently even though the Django service and a shell both run as the `tactical` OS account.

## Authenticator setup session (1.17.22)

First-time authenticator setup (and setup after "Reset my own two-factor") uses the short Knox token that Tactical issues from `checkcreds`. Tactical gives it a 180-second life, but its Knox settings refresh a token on first use (`AUTO_REFRESH`, `TOKEN_TTL` 5 hours), so after one request the expiry reads about five hours ahead. Core therefore judges the token by its age and never by expiry minus created.

`POST /api/tfd/auth/totp/enrollment/` accepts the token only when all of these hold:

- the token has a Knox digest and an aware creation time;
- the user has no authenticator yet and is not an SSO user;
- the token was created no more than 5 minutes ago (30 seconds of clock skew is tolerated into the future);
- the token has not expired.

Naive or missing times are refused. The current password is still required before any seed is made, the token is deleted in the same transaction, and the seed is returned once with no-store headers. A refusal returns 403 with `"code": "setup_session_required"` so the UI can say the setup session ended and the user must sign in again. Tactical's own 5-hour life of a used setup token is Tactical's behaviour and Core does not change it.

## Role client and site lists (1.17.22)

A role's `can_view_clients` and `can_view_sites` lists decide which clients and sites its users see. Tactical's own role routes read and save them (`PUT` replaces both). Tactical writes no audit row for a change that touches only these lists, so Core does: after a successful role create or update, when the id lists changed, Core writes one strict audit row in the same transaction (module `core`, object type `role_scope`, object id the role id, `before` and `after` as sorted id lists capped at 1000 with a count and a truncated flag, ids only). A failed audit write rolls the role save back. Core does not change who may edit these lists: a role with Manage roles can still change them, as in Tactical. That question is open as CQ72.
