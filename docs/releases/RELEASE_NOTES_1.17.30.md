# Tec-Tac Framework 1.17.30

This release adds the Core side of **AD-34** (Johan, 14 October 2026). User Invite can now build its mail context, a server module can leave a deny trace for a person it refuses, server-wide report rows are limited to superusers, and `check_available` checks who is asking. Each path fails closed.

Capabilities: `core.resources` goes from 1.8.0 to 1.9.0 and `core.accounts` from 1.1.0 to 1.2.0. Both are still major 1 and additive. No migration in this release.

Date: 14 October 2026.

## Module-facing changes

Read these before you adopt 1.17.30. Each needs `requires.framework >=1.17.30`. A module that does not use them behaves as before, with the one exception under "Server-wide report rows".

- **`trusted_service_context(actor, purpose, global_access=False)` for `userinvite` (core.resources 1.9.0, AD-34 condition 1).** Until now `global_access=False` always raised `ResourcePermissionDenied`. Now Core verifies the caller from the call stack (a private Core helper, the same rule as `core.accounts`). It returns a context only when the verified caller is the enabled module `userinvite` and the stripped actor is exactly `userinvite`. Every other caller fails closed: another module, no verified caller, Core, a disabled or legacy module, or a different actor (for example `alerts` called from `userinvite`). Core gives no hint of who is allowed and writes no audit row for a refusal. Actor and purpose are checked first, so an empty one is still `ResourceValidationError`. The context carries the actor and purpose and has `is_service` true and `trusted_global` false, so every list, get, resolve and write on it is still refused and no `custom:resource-global-context` row is written. Global Settings reads only `is_service`, `service_actor` and `service_purpose`, so User Invite's recipe in the Global Settings `CONTRACT.md` ("How User Invite builds its context") now works unchanged. `global_access=True` is byte-for-byte as before: no caller check, one strict audit row. Another module that wants the non-global form needs Johan's sign-off first (AD-34 condition 2).
- **A deny audit row from a server module (`tec_tac.audit.record`, AD-34 conditions 1 and 2).** A signed-in person who holds none of a module's permissions is accepted as the actor only when all of these hold: the module's manifest category is `server`, the action is exactly `deny`, and Core verifies that the caller is that same module. The row carries `debug_info.actor_authority = server-module-deny`, set by Core only. Any other action, any other category (core, premium, test, empty), another module's id, a Core, library or generated frame, an installer user, an unauthenticated actor, and a disabled or legacy module stay refused with `AuditContractError`. A person who holds a module permission gets the normal row. `record_core_refusal`, `record_browser_declared` and Core's own executor rows never take this path. `custom:operation-failed` is still Core-only. The caller check helper stays private; no module may import it.
- **Server-wide report rows: superusers only (reporting, AD-34 condition 3, Johan CQ91 b).** For a model declared `scoped_report_manager(server_wide=True)`, `filter_by_role` now returns every row only to an effective superuser (a Django superuser or a role superuser). It returns no rows to a role with no client or site limits, a scoped role, no role, no user, an installer user, and on any error (logged, never raised). **This replaces the Tactical-rule behaviour that shipped in 1.17.29**, where a role with neither `can_view_clients` nor `can_view_sites` saw those rows. A manager that is not `server_wide` keeps the client and site rule exactly as before. `model_row_scope` is unchanged (`enforced` true, `server_wide` true, no new key), so Report Manager needs no change. No module in `modules/` declares `server_wide=True` yet. Limit, stated plainly: a report run with no signed-in user (a schedule) never calls `filter_by_role`, so it stays unscoped (CQ15 a). A schedule made by a superuser could send server-wide rows to any recipient. Report Manager's own permission decides who may schedule. Johan is asked (CQ93). Server modules will get their own role system later (AD-34 condition 4, Johan to plan).
- **`core.accounts.check_available(username, email, invited_by_id)` (core.accounts 1.2.0, AD-34 condition 4).** `invited_by_id` is now required, with the same whole-number rule as `create_user` (a bool or a number not above zero is `invalid_input`). Order of checks: verified caller (`caller_not_allowed`, nothing read), input cleaning, the inviter re-check as `create_user` does (the person exists, is active, is not an installer user and still holds `can_manage_accounts`, else `inviter_not_allowed`), Core's rate limit, then the clash lookup. The limit is 30 answered calls per 10 minutes and 300 per day for each inviter, a Django cache counter per inviter id, counted only after the inviter check passes. The key never holds a username or email. Over the limit raises the new `rate_limited`. A cache error raises the new `rate_check_unavailable` and answers nothing. A limit hit logs a warning and writes no audit row. The answer still has no id, name or other user field. No module in `modules/` calls `check_available` (User Invite 0.9.0 does not), so the signature change breaks nothing. The module still binds the call to its signed-in create step and keeps its own limit. This stricter form is the main session's choice (14 October 2026); Johan may relax it to the plain signature. `create_user` and `list_grantable_roles` are unchanged.
- **Not changed.** `core.caller_identity` 1.0.0 and `calling_module`, `core.tactical_operations` 1.10.0, the Resource Directory record shapes, and every other contract. `calling_module_for_core_provider` stays private.

## Closes

In `reviews/requests/core.md`: the four AD-34 bullets of "Binding (Johan, 14 October 2026, AD-34): next Core release after 1.17.29", and the two `userinvite 0.9.0` entries ("a service context without global access" and "deny rows for a person with no module permission").

The held Medium from the core-1.17.29 review (`check_available` as an account-enumeration oracle) is closed by the inviter re-check and the Core limit.

Adoption by User Invite and the server-wide models is a request in `reviews/requests/core-modules.md`. It waits for this release to be signed.

Questions: CQ93, CQ94 and CQ95 are new (`reviews/questions/core.md`). Each was built on the assumption stated there.

## What changed

- **`resources.py`.** `SERVICE_CONTEXT_CALLERS`, the verified-caller branch in `trusted_service_context`, `CONTRACT_VERSION` 1.9.0 with its comment line, and the `service` text in the capability metadata.
- **`audit.py`.** `_server_module_deny_allowed`, `ACTOR_AUTHORITY_SERVER_MODULE_DENY`, and the new branch in `_actor_provenance` (run only when no Core authority is passed and the declared-owner rule did not apply).
- **`reporting.py`.** `_server_wide_queryset` and the branch in `ScopedReportManager.filter_by_role`; the `scoped_report_manager` docstring.
- **`accounts.py`.** `check_available` with `invited_by_id`, `_check_rate`, `RateLimited`, `RateCheckUnavailable`, the limit constants, `CAPABILITY_VERSION` 1.2.0 and the metadata.
- **`contracts.py`** (the `trusted_service_context`, `audit.record`, `scoped_report_manager`, `model_row_scope` and `check_available` rows) and the docs: `docs/resource-directory.md`, `docs/caller-identity.md`, `docs/module-audit.md`, `docs/module-reporting.md`, `docs/accounts-contract.md`.
- The 1.17.29 release notes moved to `docs/releases/`, as the release-integrity check allows one root note.

## Tests

New (all run on this PC, against stubs):

- `tests/resource-service-context-1.17.30.py`
- `tests/audit-server-module-deny-1.17.30.py`
- `tests/reporting-server-wide-scope-1.17.30.py`
- `tests/accounts-check-available-1.17.30.py`
- `tests/accounts-runtime-1.17.30.py` (dev server only; did not run here). It replaces `accounts-runtime-1.17.29.py` and adds the inviter checks against real roles, a real limit step and the userinvite service context, all through a stand-in frame in userinvite's folder.

Updated: the `core.resources` 1.9.0 pins in `resource-alert-template-1.17.17.py`, `resource-client-sites-1.17.22.py`, `resource-custom-field-definitions-1.17.23.py`, `resource-directory-foundation.py`, `resource-move-site-1.17.25.py` and `resource-policy-fields-1.17.24.py`; `core.accounts` 1.2.0, the cache stub and the new signature in `accounts-contract-1.17.27.py` and `accounts-check-available-1.17.29.py`; `reporting-server-wide-scope-1.17.29.py` (a role with no limits now sees none).

## Where the plan was wrong

- The plan listed `contract-export-1.17.16.py`, `tactical-operations-*` tests and `resource-move-site-1.17.24.py` for 1.8.0 pins. Those hold `core.tactical_operations` versions or only comments, so they needed no edit.
- `resources.py` and `audit.py` import `calling_module_for_core_provider` inside the function that uses it, not at module level. Two tests, `audit-contract-foundation.py` and `networkprobe-contract-requests-1.15.179.py`, load `audit.py` by file path, outside the package, and a module-level relative import broke them. Inside `_server_module_deny_allowed` a failed import is now a refusal. `accounts.py` keeps its module-level import.
- The capability's `operations` list in the metadata never named `user_context` or `trusted_service_context`, so it is unchanged; the `service` text carries the new rule.

## Not in this release

- **Module adoption** (User Invite, the server-wide models, a Global Settings note that the recipe needs Core 1.17.30): requests in `reviews/requests/core-modules.md`.
- **A role system for server modules** (AD-34 condition 4): a separate design for Johan.
- **Module failure notices raised late for later recipients; module user preferences and "save all UI preferences"; public-contract rows for the browser runtime object services; dropping the retired `priority_mail_private_relay` column; the system-action contract (AD-13); the C4 terminal ticket; secret storage; the streamed file relay; nested scope sources; CQ88 and CQ89 changes; enforcing module categories (AD-21 condition 6).** Unchanged and waiting for their own releases.

## Checks

Run on this PC: `bash tests/release-integrity.sh` (with a `python3` shim, because the Windows alias is a Store stub), the new and edited tests above, the resource, audit, reporting, accounts and caller-identity tests that load the changed files, `python -m py_compile` on each changed Python file, and `ruff check` with the repository's configuration.

Not run here: anything that needs Django, allauth, Knox or Tactical's database. The tests use stubs for Django, the cache and the verified-caller helper, so they prove the rules and not the real tables or the real call stack. The frame rule itself is pinned by `tests/caller-identity-core-provider-1.17.27.py`. `tests/accounts-runtime-1.17.30.py` is for the dev server.

## Dev server, after the release is signed

Update the dev server to Core 1.17.30 from the dev branch. Migrations are unchanged. Then run, through Tactical's `manage.py shell`, `tests/accounts-runtime-1.17.30.py`. It rolls back what it writes and clears its own limit keys. Export the 1.17.30 contract so `docs/contracts` shows `core.resources` 1.9.0, `core.accounts` 1.2.0 and the new audit and reporting text.
