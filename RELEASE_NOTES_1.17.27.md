# Tec-Tac Framework 1.17.27

This release gives User Invite a Core path to create a Tactical account when someone accepts an invite, and to list the roles an inviter may grant. Core does the account work, with the same checks Tactical's own add-user applies, plus the extra checks the invite path needs. A server module no longer writes Tactical's User model or calls Tactical's roles route.

Capability: new `core.accounts` 1.0.0 (module `core`, framework `>=1.17.27`). Additive. Nothing in `modules/` uses it yet.

Date: 14 October 2026.

## Module-facing changes

Read these before you adopt `core.accounts` in a module.

- **New capability `core.accounts` 1.0.0 (Python, `tec_tac.accounts`).** Two operations, both on the capability provider:
  - `create_user(*, username, email, first_name, last_name, role_id, password, invited_by_id)` returns `CreatedUser(user_id, username, role_id)`. It creates a Tactical user the way Tactical's own add-user does, sets the names and the role, never sets a TOTP key (so the first-sign-in two-factor set-up of Core 1.17.22 applies), writes one strict Core audit row, and runs Tactical's Mesh permission sync once after the commit.
  - `list_grantable_roles(inviter)` returns `[{id, name, is_superuser}]` ordered by name then id. Each row carries those three keys only.
- **There is no `caller` argument.** The request asked for `*, caller`. AD-26 says a module never passes its own identity in, so Core takes the caller from the call stack instead. The calling module must be the enabled `userinvite` extension (the allow-list `CALLERS` is in Core). Any other caller gets `caller_not_allowed` and nothing is written.
- **The purpose is fixed.** The audit row says `accept-invite`. A caller cannot choose another purpose.
- **Superuser roles are refused by `create_user` (`role_not_grantable`).** This is the safest choice while CQ86 is open. `list_grantable_roles` still lists superuser roles to an effective superuser, so the module should hide rows with `is_superuser` true from its role picker until Johan answers CQ86.
- **The inviter is checked again at acceptance.** `invited_by_id` must still exist, be active, not be an installer user and hold Tactical's `can_manage_accounts`. Otherwise `inviter_not_allowed` and nothing is created. `list_grantable_roles` applies the same permission check and denies with `accounts_permission_required`.
- **Typed errors.** Every refusal raises a subclass of `tec_tac.accounts.AccountsError` with a stable `.code`: `invalid_input`, `username_taken`, `email_taken`, `weak_password`, `role_not_found`, `role_not_grantable`, `inviter_not_allowed`, `caller_not_allowed`, `accounts_permission_required` and `audit_failed`. The messages are plain English and never hold a password or an email.
- **The module still verifies its own invite token and emailed code.** Core does not check them and never trusts the module's word about them. The signed-out invite page has no session, so Core's authority rests on the verified caller, the fixed purpose and the inviter re-check (CQ86 and CQ87).
- **Password rules.** `create_user` runs Django's validators with Tactical's `AUTH_PASSWORD_VALIDATORS` (the validators User Invite applies today). Tactical's own add-user route runs no validation. This is stricter than the route, and Johan may ask for parity (Info note in `reviews/questions/core.md`).
- **Feature detection.** `has_capability("core.accounts")`. A module that uses it needs `requires.framework >=1.17.27`.
- **Not changed.** `core.caller_identity` 1.0.0 and `calling_module` are unchanged. Tactical's `/accounts/users/` and `/accounts/roles/` routes and Core's guard on them are unchanged. No contract that a module already uses changed (`contractChange` false).
- **Contract and docs.** The public contract adds an `accounts` area with two rows. The full description is in `docs/accounts-contract.md`. `docs/caller-identity.md` has a short "Core as a provider" note.

## Closes

In `reviews/requests/core.md`:

- "Binding: accounts contracts for User Invite (14 October 2026, from the userinvite 0.9.0 plan)". Both operations ship in this release. The `*, caller` keyword is replaced by the verified call (see above).
- "Create a user and accept an invite through Core accounts" under "from the build-queue survey (10 October 2026)". The User Invite switch is a separate module release (requested in `reviews/requests/core-modules.md`).
- "Send mail through Tactical's SMTP settings" in the same survey entry is superseded by AD-28 and AD-30 (Global Settings `globalsettings.email` and the verified caller). It is annotated there, not built as a Core mail call.
- "userinvite 0.9.0 (14 October 2026)": "Create a Tactical user from an accepted invite (0.9.0 detail)" and "A role list the inviter may grant".

## What changed

### Core accounts contract (`core.accounts` 1.0.0)

- **`framwork/tec_tac/accounts.py` (new).** `create_user` and `list_grantable_roles`, the typed errors, the audit row and the capability registration.
- **One transaction for a new account.** The inviter re-check, the role lookup (with a row lock), the duplicate checks, the password check, the user, and the audit row are in one `transaction.atomic()`. A failed audit write rolls the user back. The Mesh sync is queued with `transaction.on_commit`, so it runs once and only after the commit. A failure to queue it is logged and does not undo the account.
- **Duplicate checks ignore case.** A database clash found on insert (a row written between the check and the insert) gives the same code.
- **Password check on an unsaved user.** Django's similarity validator compares the password with the username, email and names being set.
- **Audit row.** One strict `add` row on object type `user`, module `core`. The actor is a Core service actor named for the verified caller (`userinvite.accept-invite`). The metadata is `role_id`, `invited_by_id`, `caller_module`, `purpose` (`accept-invite`) and `totp_set` (false). No password, hash, username or email. Core's audit writer refuses a service actor whose module differs from the row's module, so the row is written under module `core`, the same path Module Replacement uses (`audit.service_audit_actor(module_id="core", ...)`). This is a deviation from the request's wording, which named the caller as the actor module. The caller is in the identity and in the metadata.
- **Registration.** `register_core_accounts_capability()` runs in `TecTacFrameworkConfig.ready()`, guarded like the caller-identity block, so a fault never stops Tactical starting.

### Verified caller for a signed-out provider (`caller_identity.py`)

- **`calling_module_for_core_provider(*, provider_file)`.** A private, Core-internal helper (CQ87). It skips every frame in the provider's own file, then the first other frame must be the code of an installed, enabled, non-legacy extension. A Core frame, a library or Django frame, a generated frame, a disabled or legacy module, an empty provider file and any registry or state error give `None`, which the provider refuses. It is not a contract row and no module may import it.
- **`calling_module` and `core.caller_identity` 1.0.0 are unchanged.** `tests/caller-identity-1.17.21.py` and `tests/caller-identity-server-module-1.17.26.py` still pass.

### Tests

- `tests/accounts-contract-1.17.27.py`: the accounts rules against stubs (Django is not installed here). Covers the happy path, duplicates ignoring case and on insert, weak passwords, roles, the inviter at acceptance, bool and non-positive ids, a failed audit write, the caller, `list_grantable_roles`, error codes, metadata, registration, the contract rows and the docs.
- `tests/caller-identity-core-provider-1.17.27.py`: the real `caller_identity.py` against a temporary extensions folder. The provider is a stand-in at the real `accounts.py` path, because the real file needs Django.
- `tests/accounts-runtime-1.17.27.py`: for the dev server, real tables, inside one transaction that is rolled back. Written here, not run (see Checks).

## Not in this release

- User Invite does not use `core.accounts` yet. Its own release does (`reviews/requests/core-modules.md`, "from Core 1.17.27 (userinvite)").
- Superuser roles through the invite path (CQ86).
- The Tactical SSO admin (CQ84), the Tasks "actions before and after" audit (CQ85), the C4 terminal ticket, and AU2 are not in this release.

## Checks

Run on this PC:

- `bash tests/release-integrity.sh`
- `tests/accounts-contract-1.17.27.py`, `tests/caller-identity-core-provider-1.17.27.py` (both pass)
- `tests/caller-identity-1.17.21.py`, `tests/caller-identity-server-module-1.17.26.py`, `tests/contract-export-1.17.16.py`, `tests/contract-export-1.17.14.py`, `tests/api-key-audit-1.17.26.py`, `tests/tactical-operations-1.17.7.py`, `tests/contract-browser-doc-cells-1.17.19.py` (all pass)
- `python -m py_compile` on the changed Python files, and `ruff check` with the repo's pipeline configuration (`pipeline/pyproject.toml`)

Not run here:

- `tests/accounts-runtime-1.17.27.py` needs the dev server (Django, Tactical's database). It is written, and it has not run.
- `tests/contract-export-1.17.18.py` reads `workspace/ui/src/main.js`, a UI file, and fails on a UI check that does not involve this release.
