# Tec-Tac Framework 1.17.28

This release does three things. It withdraws the private mail relay from 1.17.26 (Johan, 14 October 2026: Core's own email uses Tactical's SMTP, with one public-address check for every sender). It adds Tactical's SSO provider and settings admin, superuser only, with a guard that stops every local sign-in from being blocked with no working provider (CQ84 a). It lets a module record a list of objects, such as a task's actions, in the audit row in clear, the way Tactical does (CQ85 a).

Capability: `core.tactical_operations` goes from 1.9.0 to 1.10.0. It is still major 1 and additive. The other capabilities are unchanged. No migration in this release.

Date: 14 October 2026.

## Module-facing changes

Read these before you adopt 1.17.28.

- **New optional declaration keyword `audit_lists` (capability `core.tactical_operations` 1.10.0).** `register_tactical_operation(..., audit_lists=["actions"])` names up to two body or before fields that hold a list of flat objects. Python only. A declaration without it behaves exactly as before.
  - The success row's after value holds the list from the cleaned body. When the operation has a before read, the before value holds Tactical's own GET answer.
  - Each list is written with `<field>_count` (the full length). `<field>_truncated: true` appears only when something was cut or dropped.
  - Bounds (`limits_added_in_1_10_0` in the contract): 50 objects per list, 24 keys per object, text cut at 4096 characters with control characters other than tab and newline removed, one level of up to 100 scalars, 64 KiB of text per list field.
  - A failed, denied or outcome-unknown row carries no list.
  - A GET cannot declare it. A name must be a body field or come from a before read. It may not repeat a field of `audit.before` or `audit.audit_fields`, and may not look like a secret.
  - `describe()` and `list_operations` show `audit.lists`.
- **Recorded in clear.** Script arguments and environment values are written as Tactical stores them. Core does not mask them. Anyone who can read the Tec-Tac audit can read them. This follows Johan's answer to CQ85 a. Module authors should say so in their own docs.
- **Runtime settings: `priority_mail_private_relay` is gone.** `GET /api/tfd/system/runtime-settings/` no longer carries it. A PATCH that names it is the normal 400 (`Unknown runtime setting(s): priority_mail_private_relay`), for every caller. No module or UI build used it.
- **Priority 1 audit row.** The `custom:priority-mail` row has six keys: `recipients`, `sent`, `refused`, `outcome`, `code` and `requested_by`. The `private_relay` key is gone.
- **SSO admin routes are superuser only (CQ84 a).** `/accounts/ssoproviders/` add, edit, delete, settings save and account disconnect return 403 for anyone who is not an effective superuser, with one Core deny row, before the body is read. The provider list shows `secret` as `[REDACTED]` to anyone who is not a superuser. A settings save or a delete that would block local sign-in with no provider returns 409 `sso_lockout_guard`. Sign-in routes are unchanged. Core's contract rules and `docs/sso-admin.md` name every route.
- **Not changed.** `core.caller_identity` 1.0.0 is unchanged. `calling_module` is unchanged. Tactical's `/accounts/users/`, `/accounts/roles/` and API key routes and Core's guard on them are unchanged. No contract that a module already uses changed.

## Closes

In `reviews/requests/core.md`:

- "Binding: remove the private mail relay setting (AD-30 amendment, 14 October 2026)". CQ82 and CQ83 are withdrawn.
- "API keys and SSO admin (Johan, 10 October 2026)". The SSO half ships here. The API keys half shipped in 1.17.26. The UI half is in `reviews/requests/ui.md` (From Core 1.17.28).
- "from tasks 0.5.0: actions before and after as Tactical (Johan, 11 October 2026)". Core's half ships here. Tasks adopts it in its own release (`reviews/requests/core-modules.md`, From Core 1.17.28 (tasks)).

Questions: CQ84 a and CQ85 a are applied. CQ82 and CQ83 are withdrawn. CQ88 and CQ89 are new and wait for Johan (see `reviews/questions/core.md`).

## What changed

### Private mail relay withdrawn (AD-30 amendment)

- **`runtime_settings.py`.** The setting, its validator, its reader, its serialiser entry, its denial text and the PATCH branches are removed. A new `clear_retired_private_relay()` sets a stored true back to false and writes one strict Core audit row (`runtime_settings`, `modify`, object `priority_mail_private_relay`, before true, after false, a message that says the setting was retired) in the same transaction. A failed audit write leaves the column true, and the next tick retries. It is idempotent: a stored false or a missing row writes nothing. It never raises.
- **`management/commands/tec_tac_scheduler_tick.py`.** The tick calls `clear_retired_private_relay()` once a minute. Its output line is unchanged.
- **`priority_mail.py`.** One rule: `public_refusal`. `refused_reason` takes the address only. `host_refusal` is the same function. The private-network ranges, `host_check` and the core-seams argument are removed. Metadata, loopback, link-local, unspecified, multicast, embedded IPv4 and unresolved names are refused as before.
- **`module_failure_notices.py`.** The Priority 1 email uses the public-address check only. The audit row drops `private_relay`.
- **`caller_identity.py`.** `module_frame_on_stack` is removed. Only the relay used it. Its docstring in the contract text is unchanged.
- **`models.py`.** The column `priority_mail_private_relay` stays this release, with a comment that it is retired and never read. Migration 0029 is unchanged.
- **Docs.** `docs/runtime-settings.md` says the setting is withdrawn and what clears it. `docs/caller-identity.md` and `docs/module-replacement.md` match the one rule. `contracts.py` no longer carries the setting or its 403 text.

### SSO provider and settings admin (CQ84 a)

- **`tactical_account_guard.py`.** `install_tactical_account_guard` also wraps Tactical's `ee/sso/views.py` handlers: the list (`GET`), add (`POST /accounts/ssoproviders/`), edit and delete (`PUT` and `DELETE /accounts/ssoproviders/<id>/`), settings save (`POST /accounts/ssoproviders/settings/`) and disconnect (`DELETE /accounts/ssoproviders/account/`). The settings GET and the sign-in routes are not wrapped. If `ee.sso` is missing, the wrappers are skipped with one log line. The import uses `importlib.import_module`, so a `None` entry in `sys.modules` also counts as missing.
- **Superuser check first.** Every write checks `is_effective_superuser` before the body is read. A refusal writes one best-effort Core deny row (`sso_admin_superuser_required`, operation named in the metadata) and returns 403.
- **Lock-out guard.** A settings save is refused before Tactical is called when the body is two real booleans and the result would block local sign-in with no provider row. Any other body is checked on the state Tactical stored after its own save, inside the guard's transaction, and rolled back when it would lock everyone out. Deleting the last provider while local sign-in is blocked is refused before Tactical is called. The refusal is 409 with `code` `sso_lockout_guard` and a plain sentence, and writes one deny row (`sso_lockout_guard`). Tactical's failsafe (SSO off clears the block) is left to Tactical.
- **Lock.** Each write locks Tactical's `CoreSettings` row for the transaction, so two administrators queue behind each other.
- **Audit.** One strict Core row per successful write, in the guard's transaction: `sso_provider` add, modify (lists the changed names among `name`, `client_id`, `secret`, `server_url` and `role`) and delete; `sso_settings` modify (before and after `sso_enabled` and `block_local_user_logon`, as stored); `sso_account` delete (object id the Tactical user id; provider and username; never the external uid). A create whose new provider cannot be matched by id is still written, with `matched: 0`. A 423 (licence), 400 or 404 from Tactical writes no success row.
- **Secrets.** The client id and the client secret are never written to a row. Only the names of the changed fields are.
- **`contracts.py` and `docs/sso-admin.md` (new).** The contract rule names every route, flag, answer and row shape. `docs/api-keys.md` drops its "Not in this release" paragraph about SSO.

### Lists of objects in the audit row (CQ85 a)

- **`tactical_operations.py`.** `TacticalOperation.audit_lists`, the `audit_lists` keyword, `_clean_audit_lists` (registration rules), `_list_record`, `_list_value`, `_list_entry` and `_list_text` (bounds and cleaning), wired into `_after_values` and `_before_values`. `describe()` gains `audit.lists`. `CAPABILITY_VERSION` is `1.10.0`. The contract metadata lists the new keyword, the behaviour and the limits.
- **Bounds that never fail a row.** Anything cut or dropped is flagged with `<field>_truncated`. A value that is not a list is recorded as an empty list with count 0. A list with an item that is not an object is recorded as its count only. Nothing raises, and the change is still written and made.
- **No secret-name filter on values.** The name check applies to the field name only, as it does for every other audited field.
- **`docs/tactical-operations.md`.** The header states 1.10.0, and a section "Added in 1.17.28" states the clear-text rule and the bounds.

### Tests

- `tests/priority-mail-no-private-relay-1.17.28.py` (new, stubs): the key is gone from GET and PATCH for every caller; `refused_reason` takes no `allow_private` and still refuses every private, loopback, metadata, link-local and embedded-IPv4 case; Core's own send refuses a private mail server with the column True; the audit row has six keys; `module_frame_on_stack` is gone; `clear_retired_private_relay` clears once with one strict row, rolls back on a failed audit write and never raises; the scheduler tick calls it; the phrase "private relay" and the column name appear only in the files the release keeps.
- `tests/sso-admin-guard-1.17.28.py` (new, stubs): every write is refused for a non-superuser before the body is read; the superuser's writes each write one row of the right shape; no client id, secret or uid appears anywhere; the lock-out cases; Tactical's failsafe, 423, 400 and 404; rollback on a failed audit write; an unmatched create; redaction; idempotent install and install without `ee.sso`; the contract and docs.
- `tests/tactical-operations-audit-lists-1.17.28.py` (new, stubs): the clear-text record for edit and delete, every bound, the failed, denied and outcome-unknown rows, the registration refusals, capability 1.10.0 and the docs.
- `tests/runtime-settings-1.17.28.py` (new, dev server): see Checks.
- `tests/sso-admin-runtime-1.17.28.py` (new, dev server): see Checks.
- Pins moved to 1.10.0: `tests/audit-correlation-1.17.16.py`, `tests/contract-export-1.17.16.py`, `tests/tactical-operations-1.17.7.py`, `tests/tactical-operations-audit-before-lists-1.17.23.py`, `tests/tactical-operations-before-scope-1.17.14.py`, `tests/tactical-operations-core-refused-rows-1.17.21.py`, `tests/tactical-operations-failed-rows-1.17.20.py`, `tests/tactical-operations-object-field-1.17.21.py` (describe() now shows `audit.lists`), `tests/tactical-operations-permissions-any-1.17.26.py`, `tests/tactical-operations-server-only-1.17.19.py`.
- Other test changes: `tests/priority-mail-1.17.25.py` (no `private_relay` key); `tests/api-key-audit-1.17.26.py` (no longer pins the SSO sentence removed from `docs/api-keys.md`); `tests/tactical-operations-modules-compat-1.17.18.py` (the stub also registers `permissions_any` flags, as Report Manager declares them since 1.17.26).
- Removed: `tests/priority-mail-private-relay-1.17.26.py`, `tests/runtime-settings-private-relay-1.17.26.py` and `tests/priority-mail-runtime-1.17.26.py`. Their checks are in the new no-relay test.

## Not in this release

- **Dropping the column `priority_mail_private_relay`** (a migration) waits for the release after this one, so that installs clear the stored value with its audit row first.
- **Tasks adopts `audit_lists`.** That is a Tasks release (`reviews/requests/core-modules.md`).
- **The SSO admin screens** are Core UI work (`reviews/requests/ui.md`, From Core 1.17.28).
- **Left out of this release, as before:** the C4 terminal WebSocket ticket; AU2 (waits on Johan's install log); automation 0.9.0 list paging on the server; the reportmanager file relay; streamed answers; the per-call audit action and conditional scope; the secret-field changed marker; the bulk correlation id; general secret storage; the AD-13 system-action contract; enforcing module categories (AD-21 condition 6); and a rule that a granted role may not hold a flag its inviter lacks (a design call for Johan).
- **Open questions for Johan** (`reviews/questions/core.md`): CQ88 (show the OIDC client secret to non-superusers or not; built as `[REDACTED]`) and CQ89 (what counts as a working provider; built as any provider row).

## Checks

Run on this PC:

- `bash tests/release-integrity.sh`, with a `python3` shim, because the Windows `python3` alias is a Store stub.
- Every test named above that runs without Django, and the tests that load the changed modules (the tick tests, the caller-identity tests, the contract-export tests, the operations tests, the API key guard test and the accounts tests).
- `python -m py_compile` on each changed Python file.
- `ruff check` with `pipeline/pyproject.toml` on the changed framework files. It reports no new findings against the 1.17.27 tree: the findings that remain were already there.

Not run here:

- Anything that needs Django, allauth, Knox or Tactical's database. On this PC the full test directory gives 111 failing tests on the 1.17.27 tree (copied from git), almost all of them needing Django or the dev server. This release changes none of their results, except the two dev-server scripts below, which are new and fail only at the Django import.
- `tests/runtime-settings-1.17.28.py` and `tests/sso-admin-runtime-1.17.28.py`. They are for the dev server, and they did not run here.
- `tests/contract-export-1.17.18.py` reads `workspace/ui/src/main.js`, a UI file, and fails on a UI check that this release does not touch.

## Dev server, after the release is signed

Update the dev server to Core 1.17.28 from the dev branch. Migrations are unchanged. Then run, through Tactical's `manage.py shell`:

- `tests/runtime-settings-1.17.28.py`
- `tests/sso-admin-runtime-1.17.28.py`

Both roll back everything they write. The SSO script deletes no provider. Export the 1.17.28 contract so `docs/contracts` shows the SSO rules and `audit.lists`.
