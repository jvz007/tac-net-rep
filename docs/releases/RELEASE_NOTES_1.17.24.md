# Tec-Tac Framework 1.17.24

This release lets an administrator end every login session at once. It holds a chosen theme for the signed-in session only. It lets Core store the policy a client or site uses. It documents and tests the move of a site to another client. It also closes the Low finding held from the 1.17.23 review: only a superuser may change the system name.

Capability: `core.resources` goes from 1.6.0 to 1.7.0. It is still major 1, and everything below is additive.

Date: 13 October 2026.

## Closes

In `reviews/requests/core.md`:

- "Resource Directory (from automation 0.6.0): policy fields on client and site records" (AU8, AU10).
- "Resource Directory: an alert template filter on clients and sites (alerts 0.8.0)".
- "System name: only a superadmin may change it" (the Low held from the 1.17.23 review).
- From Johan's test, sections 1 to 5: CO17 (end all sessions), CO25 (move a site, the Core half) and CO9 (the session theme, the Core half).

## What changed

### Only a superuser may change the system name (held Low)

Before, anyone with `core.runtime_settings.manage` could rename the system. The name appears in every person's authenticator app, so we now treat it like the upload limit.

- `PATCH /api/tfd/system/runtime-settings/` with `system_name` (a new name, or `null` to reset it) answers 403 unless the caller is an effective superuser: `Only a Tec-Tac superuser may change the system name.`
- The check runs before any value is read. A person without the right never sees a 400.
- A body that mixes `system_name` with another setting is refused whole. Nothing is saved.
- A person with `core.runtime_settings.manage` still changes the register time limit on its own.
- A refusal writes one best-effort Core `deny` row (module `core`, object type `runtime_settings`, `object_id` the setting name, reason `superuser_required`). The row never carries the value. A failed deny write never turns the 403 into a 500.
- The upload-limit refusal writes the same kind of row. It wrote none before. That is additive.
- Reading the name (`GET runtime-settings`, `system_name` in the UI context) is unchanged. A superuser's change is unchanged: validation, one strict row, rollback if the audit write fails.

### End every login session (CO17)

`POST /api/tfd/access/sessions/revoke-all/` ends every user's sessions at once. It is a Tec-Tac addition. Tactical has no such route.

- Only an effective superuser may call it. An account administrator who only holds the manage-accounts permission gets 403, and the refusal writes one Core `deny` row.
- Body (both optional): `reason` (text, cut at 255 characters) and `include_current` (true or false, default false).
- By default the caller's own session and token stay, so the button does not sign the administrator out. `include_current: true` ends that one too.
- In one transaction Core revokes every active Tec-Tac session row, deletes every Tactical Knox token (protected accounts included) except the caller's own unless `include_current`, writes one session audit event (`all_login_sessions_revoked`) and one strict Core audit row (action `custom:revoke-all-sessions`, object type `login_sessions`). Both carry counts only: never a token or digest. A failed audit write rolls everything back.
- The answer is `{ revoked_tokens, revoked_sessions, users, current_kept }`.
- Core takes no typed confirmation and no confirmation field. The browser asks one Yes or No (AD-27).
- The per-user and per-token revoke routes are unchanged.
- Python: `tec_tac.session_security.revoke_all_login_sessions(reason=, requested_by=, requester=, include_current=False, current_digest=None)`. It raises `PermissionError` for a caller who is not an effective superuser.

### Policy fields on client and site records (AU8, AU10)

Tactical's Edit client and Edit site save a workstation policy, a server policy and a "block policy inheritance" flag. Core now reads and writes them. Core holds only the ids and the flag. Automation owns the policy list and everything a policy does.

- New record keys, appended last: `workstation_policy_id` (integer or `null`), `server_policy_id` (integer or `null`) and `block_policy_inheritance` (`true` or `false`, `false` when unset). A client carries them after `sites`. A site carries them after `client_name`. Nested sites carry them too. Anyone who can list clients or sites sees them, as for `alert_template_id`.
- `update_client` and `update_site` take `workstation_policy_id` and `server_policy_id` (a positive whole number sets, `None` clears, leaving the keyword out leaves it alone) and `block_policy_inheritance` (a real `True` or `False` only; `1`, `0` and text are refused). At least one field is still required, and the error text now names all of them.
- A policy id that names no policy fails Tactical's own foreign key. The answer is `400 invalid_resource_request`: `workstation_policy_id does not name an existing policy.`
- The write goes through the model save, so Tactical's own `Client.save` and `Site.save` run: they re-cache the alert template and purge the site policy caches, exactly as Tactical's `PUT`.
- The write rule is the same as a rename: Tactical `can_manage_clients` or `can_manage_sites`, the Core resources permission, a whole-client grant for a client, a site or client grant for a site. Core does not ask for `can_manage_automation_policies`, because Tactical's own `PUT` does not. A policy pushes checks, tasks and scripts to every endpoint under the client or site, so this is filed for Johan (see below).
- The strict audit row carries before and after records, which include the new fields, and the metadata `policy_changed` (the names of the fields whose value changed, ids only).
- `PATCH /api/tfd/resources/clients/<id>/` and `sites/<id>/` accept the three keys. `null` clears a policy id.
- New list filters on `list_clients`, `list_sites` and their routes: `alert_template_id` and `policy_id` (matches the workstation or the server policy). Each is a positive whole number or a 400. Both together mean both must match. They run inside the caller's scope and under the list's own permission. Alerts can find where a template is used, and Automation can build the policy overview, without reading every page.
- An update that changes nothing (the same values sent again) now writes no audit row. Before, a repeat of the same name or the same template wrote a row. This applies to clients and sites.

### Move a site to another client (CO25, the Core half)

The mechanism is older: `update_site(client_id=...)` and `PATCH /api/tfd/resources/sites/<id>/`. What was missing was a documented contract, a clear audit row and tests. The control in the UI is a UI request.

- The agents follow the site, because they point at the site.
- The source needs the site write grant. The destination client needs the same client write grant as `create_site`. A role limited to some clients needs an explicit grant on the destination. That is stricter than Tactical, which checks only the Edit sites permission. We kept the narrow rule (see below).
- A destination outside the caller's scope answers `404 resource_not_found`, the same as a client that does not exist.
- The last site of a client cannot move away: `400`, `A client must retain at least one site.`
- A name already used in the destination client gives `409`: `A site with that name already exists for the selected client.`
- A `client_id` equal to the current one is a no-op: nothing is saved and no row is written. The destination check is skipped too.
- The strict audit row gets the metadata `client_changed` (`true`), `from_client_id`, `to_client_id` and `agents_moved` (a count). Ids and a number only, never a name. The keys are absent when the client did not change. A move together with a rename is one write and one row.
- Tactical's `Site.save` hooks run on a move (`update_fields`: `client`, `modified_by`, `modified_time`).

### The session theme (CO9, the Core half)

A theme chosen in the dropdown becomes a choice held for the signed-in session. It is never written to the saved preference. It dies with the session, so the next person on the same browser starts clean.

- Migration `0028_session_theme` adds one column to the session trust row: `session_theme` (text, 16 characters, empty by default). Existing rows read as empty. The migration depends on `0027_runtime_system_name` and reverses by dropping the column.
- `GET /api/tfd/session/theme/` returns `{ "theme": null }` or the theme. `PUT` with `{ "theme": "dark" | "light" | "high-contrast" }` sets it. `DELETE` clears it. A boolean, `null`, other text or any other body key gives 400 and saves nothing.
- All three need a signed-in session and touch only the caller's own current session row. Another session of the same user, and another user, are never changed. A revoked row is never written.
- `GET /api/tfd/ui/context/` carries `session_theme` (`null` or the theme) next to `preferences`, so the UI applies it at startup with no extra call.
- The saved preference route (`PUT /api/tfd/ui/preferences/`) is not changed, and a theme put there still works. The UI decides when to call which.
- Not audited: a display choice, not a security event.
- A new sign-in creates a new session row, so a second user never sees the earlier user's choice. A revoked row keeps its value only as a tombstone that is never read.

The UI half (stop the dropdown saving, clear browser storage at sign-out, make Save keep the preference) is in `reviews/requests/ui.md`.

## Module-facing changes

Each change below that a module relies on needs `requires.framework >=1.17.24`. Existing keys, query parameters, paging and error codes do not change.

| What | Where | Needs a module change? |
|---|---|---|
| **`core.resources` 1.7.0.** Three appended record keys on clients and sites (`workstation_policy_id`, `server_policy_id`, `block_policy_inheritance`), three optional keywords on `update_client` and `update_site`, two optional filters (`alert_template_id`, `policy_id`) on `list_clients` and `list_sites`. | `docs/resource-directory.md`, `contracts.py`, the generated export | No. 15 modules only read client and site records through `core.resources` and take keys with `.get`. Automation is asked to adopt the policy writes and the `policy_id` filter. Alerts is asked to adopt the `alert_template_id` filter. |
| **An unchanged update writes no audit row** (`update_client`, `update_site`). | `docs/resource-directory.md` | No. No module calls these functions (checked in `modules/`). |
| **Site move rules documented.** The audit metadata of a move gains `client_changed`, `from_client_id`, `to_client_id` and `agents_moved`. | `docs/resource-directory.md` | No. |
| **`session_theme`** is a new additive key in `GET /api/tfd/ui/context/`. | `contracts.py`, `docs/user-preferences.md` | No. Older UI builds ignore it. |
| **New routes** `POST /api/tfd/access/sessions/revoke-all/` and `GET`, `PUT`, `DELETE /api/tfd/session/theme/`. | `contracts.py`, `docs/session-security.md`, `docs/user-preferences.md` | No. |
| **`system_name` is superuser only.** A caller with only `core.runtime_settings.manage` now gets 403 for it. | `docs/runtime-settings.md` | No. No module changes runtime settings (checked in `modules/`). |

I checked `modules/` for each of these. No module calls `update_client`, `update_site`, the runtime-settings route, the login-session routes or the session theme route.

## Decisions for Johan (`reviews/questions/core.md`)

- **C6, end all sessions:** should the administrator's own current session end too? I went on with keeping it by default, with an optional `include_current`.
- **C9, policy assignment:** should Core also require Tactical's `can_manage_automation_policies`? I went on with Tactical parity (AD-25), with the policy ids in the audit row.
- **C5, the session theme:** should Core hold it, or should the UI hold it alone? I built the Core side additively. It is harmless if the UI chooses to hold it alone.
- **C7, move a site:** a limited role may move a site only to a client it holds a grant on. I kept that stricter rule.
- **Runtime settings:** the upload-limit refusal now writes a deny row too. Informational.

## Tests

New: `tests/system-name-superuser-1.17.24.py`, `tests/session-revoke-all-1.17.24.py`, `tests/resource-policy-fields-1.17.24.py`, `tests/resource-move-site-1.17.24.py` and `tests/session-theme-1.17.24.py`.

Dev server only, written but not run: `tests/resource-policy-runtime-1.17.24.py` (the real foreign key and Tactical save hooks), `tests/session-revoke-all-runtime-1.17.24.py` (the real Knox token delete) and `tests/session-theme-runtime-1.17.24.py` (the real migration 0028 and the three calls).

Updated: `tests/system-name-1.17.23.py` (the name is superuser only now), the version and field-order pins in `tests/resource-alert-template-1.17.17.py` (the in-memory Tactical now knows policies, a client move and the unique site name), `tests/resource-client-sites-1.17.22.py`, `tests/resource-custom-field-definitions-1.17.23.py`, `tests/resource-directory-foundation.py` and `tests/resource-scheduler-audit-scope.py`, and the migration-order pins in `tests/runtime-settings-upload-1.17.14.py` and `tests/update-source-1.17.2.py`.

Django, Knox, Celery and a database are not installed on the development PC. The migration, the foreign-key check, the Tactical save hooks and the real token deletes ran only against stubs. The three runtime scripts above are due on the dev server.

## Not in this release

- The terminal WebSocket ticket (C4). Johan left it out.
- Actions before and after as Tactical. It waits on Johan's answer about script arguments and environment values.
- AU2 (the Patching lifecycle failure). It waits on the install log in `debug/`.
- The nested-sites rule (CQ74) and the gate of the custom-field definitions read (CQ75), pending Johan. Nothing changed.
- The UI halves of everything above. They are requests in `reviews/requests/ui.md`.
