# Tec-Tac Framework 1.17.29

This release gives User Invite what it needs to send an invitation safely. It adds two small, opt-in Core paths. Each one fails closed. It also names two signed decisions that held reviews asked for.

Capabilities: `core.accounts` goes from 1.0.0 to 1.1.0, still major 1 and additive. `core.resources` stays at 1.8.0. No migration in this release.

Date: 14 October 2026.

## Module-facing changes

Read these before you adopt 1.17.29. Each needs `requires.framework >=1.17.29`. A module that does not use them behaves exactly as before.

- **`core.accounts.check_available(username, email)` (core.accounts 1.1.0).** Returns a frozen `Availability(status, username_taken, email_taken)`. `status` is exactly `username_taken`, `email_taken` or `free`. When both clash it is `username_taken`, the order `create_user` uses, and both flags are true. The match ignores case and uses the same lookups as `create_user` (one shared helper, so the two cannot drift). Same verified caller rule as `create_user`: only the enabled `userinvite` module, `caller_not_allowed` for anyone else, and no query runs. Bad input raises `invalid_input`. It is a read: no audit row, no write, no transaction. It returns no id, name or other field of a matching user. Core cannot see whether a person is signed in, so the module must call it only from the signed-in create step and rate-limit it (`docs/accounts-contract.md`). `create_user` and `list_grantable_roles` behave exactly as before. Cites AD-31, including condition 5 (Core does not verify the invite token; an accepted limit). CQ92 asks Johan whether Core should also re-check the inviter.
- **`scoped_report_manager(server_wide=True)` (reporting).** An explicit, opt-in keyword for report models whose rows belong to the server and have no client or site (User Invite's invitation history, a certificate observation). It must be a bool. With `client`, `site` or `include_unassigned=True` it is refused when the manager is declared (`ReportingRegistrationError`). `filter_by_role` is the fail-closed rule a pathless model already had: an unrestricted person (a superuser, or a role with neither `can_view_clients` nor `can_view_sites`, Tactical's own rule) sees every row, a scoped person sees none, no role and any error see none. It never raises. `model_row_scope` gains the key `server_wide` and reports `enforced` true for a server-wide model with no path. A pathless `scoped_report_manager()` without the flag stays `enforced` false, with `server_wide` false, so certificatemanagement's current declaration and every other module behave exactly as today, and Report Manager still refuses them until they opt in. Report Manager reads only `enforced`, so it needs no change. A subclass that replaces `filter_by_role` is still source `model` and not enforced. CQ91 asks Johan who should see these rows.
- **New key in `model_row_scope`.** Every `model_row_scope` result and every reporting status row's `row_scope` now carries `server_wide` (false unless declared). A module test that compares the whole dict with an exact value needs the new key. In this tree only Core's own two tests did; no module under `modules/` compares the whole dict (Report Manager reads `enforced`; the others use their own stubs).
- **Not changed.** `core.caller_identity` 1.0.0, `calling_module`, `core.tactical_operations` 1.10.0, the Resource Directory record shapes and every other contract are unchanged. `calling_module_for_core_provider` stays private.

## Closes

In `reviews/requests/core.md`:

- "User Invite: check_available for username and email".
- The first bullet of "from certificatemanagement 0.3.0 fix round 1": server-wide row scope for Report Manager (AD-15 condition 3). The second bullet (a completion path for a finished server job) stays open.

Adoption by the modules is a request in `reviews/requests/core-modules.md` (From Core 1.17.29: userinvite, certificatemanagement, globalsettings). It waits for this release to be signed.

Held findings addressed (documentation and contract text only, no behaviour change):

- The held Medium from the core-1.17.28 review, `audit_lists` recorded in clear: **AD-32** (Johan, 14 October 2026) now exists, and its condition 3 is met. `docs/tactical-operations.md` (the `audit_lists` section) and the `audit_lists` wording in `contracts.py` name AD-32, and so do these notes. The values are still recorded in clear, as Tactical does, and only holders of the audit view permission can read them.
- The held Medium from the core-1.17.27 review, signed-out account creation: **AD-31** exists, with condition 5 (Core does not verify the invite token; an accepted limit). The `accounts.py` module docstring, `docs/accounts-contract.md` and the `accounts_contract_metadata()` text now cite AD-31 and condition 5. `docs/sso-admin.md` cites **AD-33**.

Questions: CQ91 and CQ92 are new and wait for Johan (`reviews/questions/core.md`). Each was built on the assumption stated there. CQ90 (the two caller-verified paths) is open and those paths are not in this release.

## What changed

### check_available

- **`accounts.py`.** `Availability`, the shared `_clashes` helper (used by `_check_free` and `check_available`), `check_available`, the registration and the metadata (`operations`, `availability_statuses`, `check_available`, `accepted_decisions`, `limits`, `requires_framework`). `CAPABILITY_VERSION` is `1.1.0`.
- **`contracts.py` and `docs/accounts-contract.md`.** A `check_available` row and a section that states the signed-in-step and rate-limit duty.

### Server-wide row scope

- **`reporting.py`.** The manager takes `server_wide`; `scoped_report_manager` validates it; `model_row_scope` reports it and treats a server-wide, pathless model as enforced.
- **`contracts.py` and `docs/module-reporting.md`.** The two reporting rows, a "Server-wide data" section, and the new key list.

### Tests

New (all run on this PC, against stubs):

- `tests/accounts-check-available-1.17.29.py`: free, taken in both cases, both taken, no user detail, input errors, caller refusals with no query, no audit or write, the capability, the contract row and docs, and the AD-31, AD-32 and AD-33 citations.
- `tests/reporting-server-wide-scope-1.17.29.py`: who sees what, declaration refusals, `model_row_scope` for every kind of model, the bridge status and the docs.
- `tests/accounts-runtime-1.17.29.py` (dev server only; did not run here): see Checks.

Updated pins: `core.accounts` 1.1.0 and the third operation in `accounts-contract-1.17.27.py`; the `server_wide` key in `reporting-row-scope-1.17.4.py` and `reporting-handover-1.17.4.py`.

## Where the plan was wrong

- The plan said to re-run `reporting-handover-1.17.4.py` unchanged. It compares the whole `row_scope` dict with an exact value, so the new `server_wide` key needs a one-line change there (and in `reporting-row-scope-1.17.4.py`). The behaviour that test protects is unchanged.
- `resource-scope-descriptor-1.17.17.py` pinned no 1.8.0 value (it reuses the shared harness of `resource-alert-template-1.17.17.py`), so it needed no edit.

## Not in this release

- **Module adoption.** User Invite, certificatemanagement and Global Settings adopt these paths in their own releases (`reviews/requests/core-modules.md`).
- **Two caller-verified paths, taken out of this release.** A service context without global access (`trusted_service_context`, User Invite only) and a `deny` audit row from a server module are not built here. AD-31 condition 6 needs Johan's sign-off in chat for any further module, and CQ90 is unanswered. Both stay open in `reviews/requests/core.md`. They return in a later release once Johan answers CQ90 and AD-34 exists; each rule is one tuple or one check.
- **A completion path for a finished server job** (certificatemanagement 0.3.0 fix round 1, second bullet): a separate design on `core.server_maintenance`.
- **Left out, as before:** the C4 terminal WebSocket ticket; AU2; the streamed file relay; nested scope sources; the per-call audit action and conditional scope; a GET operation with no audit row; literal audit object ids and secret body fields as changed; the secret-safe changed marker; the bulk correlation id; automation 0.9.0 list paging on the server; the system-action contract (AD-13); general secret storage; `conflicts_with`; hand registrations surviving uninstall; the declared installer route; enforcing module categories for production; dropping the retired `priority_mail_private_relay` column.
- **Invite-time rate limiting and signed-out refusal audit** are User Invite work, not Core.

## Checks

Run on this PC:

- `bash tests/release-integrity.sh`, with a `python3` shim, because the Windows `python3` alias is a Store stub.
- The four new tests above, and the tests they extend or that load the changed files: `accounts-contract-1.17.27.py`, `caller-identity-core-provider-1.17.27.py`, the resource tests that pin 1.8.0, `resource-scope-descriptor-1.17.17.py`, `audit-declared-owner-rows-1.17.20.py`, `audit-private-operation-writer-1.17.8.py`, `reporting-row-scope-1.17.4.py`, `reporting-handover-1.17.4.py` and `reporting-takeback-unregister-1.17.6.py`.
- `python -m py_compile` on each changed Python file, and `ruff check` with `pipeline/pyproject.toml`.

Not run here:

- Anything that needs Django, allauth, Knox or Tactical's database. The new tests use stubs for Django and Tactical, so they prove the rules and not the real tables.
- `tests/accounts-runtime-1.17.29.py`. It is for the dev server and did not run here.
- The real call-stack behaviour of the new `check_available` caller check. The stubs fake `calling_module_for_core_provider`. The frame rule itself is pinned by `tests/caller-identity-core-provider-1.17.27.py`.

## Dev server, after the release is signed

Update the dev server to Core 1.17.29 from the dev branch. Migrations are unchanged. Then run, through Tactical's `manage.py shell`:

- `tests/accounts-runtime-1.17.29.py`

It rolls back everything it writes. Export the 1.17.29 contract so `docs/contracts` shows `core.accounts` 1.1.0 and `server_wide`.

## Precheck round 0 (14 October 2026)

The pipeline's precheck held 1.17.29 on one finding: two caller-verified paths shipped on an open decision (CQ90, AD-34 not signed). AD-31 condition 2 covers a Core provider verifying its caller for `core.accounts` only, and condition 6 needs Johan's sign-off for any further module. Core took both paths out and kept the rest:

- Removed: `trusted_service_context` without `global_access` (core.resources back to 1.8.0, which refuses it as before) and the `deny` row from a server module in `tec_tac.audit.record` (`_server_module_deny_allowed`, `actor_authority = "server-module-deny"`).
- Removed with them: their `contracts.py` text, the sections in `docs/resource-directory.md`, `docs/caller-identity.md` and `docs/module-audit.md`, and the tests `resource-service-context-1.17.29.py` and `audit-server-module-deny-1.17.29.py`. The version pins in the six resource tests are back at 1.8.0. `accounts-runtime-1.17.29.py` now checks `check_available` only.
- Unchanged: `check_available`, `scoped_report_manager(server_wide=True)` and the AD-32 and AD-31 text.
- Module-facing: nothing that was accepted in 1.17.28 changes. No module could rely on the two paths, because they were never signed. The User Invite requests for them stay open in `reviews/requests/core.md`.
