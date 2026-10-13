# SSO admin (Tactical's SSO provider and settings admin, Core's half)

Tactical lets an administrator add single sign-on providers, choose whether SSO is on, block local sign-in, and disconnect a linked
account. Tec-Tac replaces Tactical's UI, so a technician must be able to do the same here. The screens are Core UI work. This page covers
what Core does on the server (Core 1.17.28, CQ84 a: "enforce the guard, superuser only").

## What Tactical does (v1.5.2, `ee/sso/views.py`)

| Route | Method | Tactical flag | What it does |
|---|---|---|---|
| `/accounts/ssoproviders/` | GET | `can_list_accounts` | Lists every provider: id, name, provider, provider id, client id, **client secret**, server URL, callback URL, role |
| `/accounts/ssoproviders/` | POST | `can_manage_accounts` | Adds a provider (the provider id is made from the name) |
| `/accounts/ssoproviders/<id>/` | PUT | `can_manage_accounts` | Edits the client id, secret, server URL and role |
| `/accounts/ssoproviders/<id>/` | DELETE | `can_manage_accounts` | Deletes the provider |
| `/accounts/ssoproviders/settings/` | GET | `can_list_accounts` | Reads `sso_enabled` and `block_local_user_logon` |
| `/accounts/ssoproviders/settings/` | POST | `can_manage_accounts` | Saves `sso_enabled` and `block_local_user_logon`. Tactical's licence check can answer 423 |
| `/accounts/ssoproviders/account/` | DELETE | `can_manage_accounts` | Disconnects one linked SSO account |

Tactical has no per-provider on or off switch. A provider that exists is a working provider. Tactical also has a failsafe: when SSO is off,
it clears the local-sign-in block on save.

The sign-in routes (`ssoproviders/token/`, the OIDC callback and the allauth routes) are not changed by Core. They are how people sign in,
and they stay exactly as Tactical has them.

## What Core adds

Core wraps the handlers at start-up (`tactical_account_guard`). If Tactical's `ee.sso` is not installed, Core skips the wrappers and logs
one line.

**Superuser only for every change (CQ84 a).** Add, edit and delete a provider, save the settings and disconnect an account need an
effective superuser. Anyone else gets 403 and one Core `deny` row. The holder of Tactical's `can_manage_accounts` is included. The check runs
before the body is read. The answer is `{"detail": "Only a Tec-Tac superuser may change SSO providers or SSO settings."}`. The deny row has
object type `sso_admin_superuser_required` and names the operation (`add_provider`, `edit_provider`, `delete_provider`, `save_settings` or
`disconnect_account`).

**The lock-out guard.** Blocking local sign-in with no provider would leave nobody able to sign in except through a superuser's local
account. Core refuses two cases with 409:

- A settings save that leaves `block_local_user_logon` true while no provider row exists.
- A delete of the last provider while `block_local_user_logon` is true.

The answer is `{"detail": "<a plain sentence>", "code": "sso_lockout_guard"}`. It writes one Core `deny` row (object type
`sso_lockout_guard`) and changes nothing. Core counts any provider row as a working provider (assumption on CQ89). It cannot tell that a client id,
secret or server URL is wrong. Tactical still lets a local superuser sign in while local sign-in is blocked, so that account stays the way back in.

The check and Tactical's call run in one transaction with Tactical's settings row locked. Two administrators cannot both pass the check.
A settings save is checked on the state Tactical stored, after its own failsafe. So a request that turns SSO off while asking to block is
left to Tactical's failsafe, and the audit row shows the block as stored (false).

Tactical's 423 (licence) changes nothing and writes no success row. So does a 400 or 404 from Tactical.

**Redaction.** The provider list shows `secret` as `[REDACTED]` to anyone who is not an effective superuser. Only a superuser can edit a
provider, so this removes nothing a person can use (CQ88 b). A superuser still sees the value, as in Tactical.

**One Core audit row per successful write (1.17.28).** Each row is written in the guard's transaction. A failed audit write rolls the change back.

| Action | `object_type` | `object_id` | Before and after | Metadata |
|---|---|---|---|---|
| add | `sso_provider` | the new provider's id | after: name, provider id, server URL, role | the same four |
| modify | `sso_provider` | the provider's id | before and after: name, provider id, server URL, role | the after view, and `changed`: the names among `name`, `client_id`, `secret`, `server_url` and `role` that changed |
| delete | `sso_provider` | the provider's id | before: name, provider id, server URL, role | the same four |
| settings save | `sso_settings` | `sso_settings` | before and after: `sso_enabled`, `block_local_user_logon` (as stored) | none |
| disconnect | `sso_account` | the Tactical user id | none | `provider` and `username` |

**The client id and the client secret are never stored in a row.** An edit lists only the names of the fields that changed. An add whose
new provider cannot be matched by id is still written, with `matched: 0` and no id. Core finds the new provider by comparing the provider
ids before and after the create, and by name when two creates overlap. The disconnect row never carries the external account id (the uid).

Refused and Tactical-refused calls write no success row.

## Audit visibility

Tactical's own audit records are readable by anyone who can read the Tec-Tac audit. Core's rows carry names and ids. They never carry a
client id, a secret or an external account id.

## Tests

- `tests/sso-admin-guard-1.17.28.py`: the stub test (in-memory provider, account and settings tables with a rolling-back transaction, and
  Tactical's handlers as small fakes that behave like `ee/sso/views.py`). Run without Django.
- `tests/sso-admin-runtime-1.17.28.py`: the real-database check for the dev server (real `SocialApp` rows, rolled back). It is not run on the
  development PC.
