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
