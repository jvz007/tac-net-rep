# Tec-Tac Framework 1.17.22

This release fixes first-time two-factor set-up. It lets a person who can only list clients see those clients and their sites. It makes Add client and Add site work the way Tactical's do. It adds an audit row when a role's client and site lists change. It also closes the one Medium finding held from the 1.17.21 review.

Capability: `core.resources` goes from 1.4.0 to 1.5.0. It is still major 1, and everything below is additive except the one narrowing named in the module-facing section.

## Closes

In `reviews/requests/core.md`:

- C1 (CO3, CO8, finding 1): first-time two-factor set-up and "Reset my own two-factor" were refused.
- C2 (finding 2, EP2, EPP1, COP2, COP3, C8): a limited user got "can_list_sites is required" and saw no clients or sites.
- C3 (CO22): Add client takes the first site's name and custom fields, and Add site and Add client extend a limited role as Tactical does.
- "`client_name` on site records" (automation 0.8.0).
- The held Medium of the 1.17.21 review (the object id of a `core_refused` row), and the stale `server_only` pin in `tests/tactical-operations-modules-compat-1.17.18.py`.

It also prepares the contract for UI U1 (pickers for a role's clients and sites). Core has no roles route of its own, so U1 needed a stated contract and an audit row, not new code.

## What went wrong, and the fix

### First-time two-factor set-up (C1)

Tactical issues a setup token with a 180-second life when a new user signs in. Core accepted that token only when its expiry was within five minutes of its creation time. Tactical also runs Knox (its login-token library) with auto refresh on and a five-hour life. On the token's first use Knox renews the expiry to about five hours ahead. So by the time the browser asked for the QR code, the token looked like a normal session and Core refused it with "A fresh Tactical authenticator setup session is required."

"Reset my own two-factor" clears the key and ends the sessions, so the next sign-in takes the same path. It was the same cause.

Core now judges the token by its age. The token is accepted when all of these hold:

- it has a Knox digest and a creation time with a time zone;
- the user has no authenticator key yet and is not an SSO user;
- it was created no more than 5 minutes ago (30 seconds of clock skew is tolerated);
- it has not expired.

A naive or missing time is refused. Nothing else about the set-up changed. The current password is still required before a seed is made, the token is deleted in the same transaction, the seed is shown once with no-store headers, and the throttles and audit rows are as before. The 403 now also carries `"code": "setup_session_required"`, so the page can say "Your setup session ended. Sign in again."

Tactical's own five-hour life of a used setup token is Tactical's behaviour. Core does not change it. `docs/account-security-policy.md` explains the rule.

### Clients and sites for a limited user (C2)

Tactical's own `GET /clients/` needs only List clients. It returns each client with its sites, cut to the caller's scope. Core's client read gave the client alone, and the sites read needed List sites. A role limited to one client with List clients and no List sites therefore saw its client and nothing under it.

Client records now carry `sites`. Site records now carry `client_name`. What each role can read:

| Role holds | Clients read | Sites read |
|---|---|---|
| List clients only | 200, with nested sites | 403 |
| List sites only | 403 | 200, each site with `client_name` |
| Both | 200 | 200 |
| Neither | 403 | 403 (unchanged) |

Nested sites use the same `Site.filter_by_role` rule as the sites read, are ordered by name then id, have the same shape as `list_sites` records, and load with one query per page. Writes still need `can_manage_clients` or `can_manage_sites` plus the Core codenames.

A role with neither flag is still refused both reads. Johan has not answered Question 1 of `reviews/TEST-FINDINGS-12-10-2026.md`, so Core builds nothing that takes names from endpoint rows.

### Add client and Add site as Tactical does (C3)

- `create_client(*, name, context, site_name=None, custom_fields=None)`. `site_name` is the first site's name. Without it the site is called "Default Site" as before (deprecated, kept until Johan asks for a major version). `custom_fields` is a list of `{field_id, value}`, saved in the same transaction with the existing custom-field rules. A bad custom field rolls the client and site back.
- `create_site(*, client_id, name, context, custom_fields=None)` takes the same optional `custom_fields`.
- Names may not contain `|`, as in Tactical. Core refuses it on create and rename: `Client name cannot contain the | character`.
- A new client joins the creator's `can_view_clients` only when that list is not empty. A new site joins `can_view_sites` only when that list is not empty. Superusers and unrestricted roles change nothing. This is Tactical's rule exactly.
- The audit row carries `first_site_id`, `role_scope_extended` and `custom_field_ids` (ids only, never values). Audit before and after snapshots keep their earlier shape, without `sites` and `client_name`.

### Role client and site lists (for UI U1)

Tactical's routes `GET|POST /accounts/roles/` and `GET|PUT|DELETE /accounts/roles/<id>/` already read and save `can_view_clients` and `can_view_sites` as lists of ids. Core's account guard already passes them through. What was missing was an audit row: Tactical's own audit compares a snapshot at save time, and the serializer sets many-to-many fields afterwards, so a change that touched only these lists left no row.

Core now writes one strict row inside the guard's transaction when the lists change: module `core`, action `add` or `modify`, object type `role_scope`, object id the role id, `before` and `after` as sorted id lists (capped at 1000, with a count and a `truncated` flag). It is written only when a list changed, and a failed write rolls the role save back. Core does not change who may edit these lists (see CQ72).

The contract is in `resource_contract_metadata()["role_scope_lists"]` and `docs/resource-directory.md`. An empty pair means unrestricted. `PUT` replaces both lists, so a picker must send back the ids it loaded and could not show.

### The `core_refused` row's object id (held Medium)

The 1.17.21 row for a refusal made before Tactical is called took its object id from a hint built from the raw call, before the parameters were cleaned. A body-sourced scope value or an uncleaned path value could become the row's object id. That broke AD-19 condition 4 (second amendment): never body values.

The id is now set only after the path parameters were cleaned, from `audit.object_param` or the first path-sourced scope entry, and never from a body field. A refusal that happens before that step (`invalid_correlation_id`, `invalid_audit_before`, `invalid_params`) or an operation scoped by its body writes a row with no object id. The deny rows that existed before 1.17.21 are unchanged.

## Module-facing changes

Each change below needs `requires.framework >=1.17.22` in a module that relies on it. Existing keys, query parameters, paging and error codes do not change.

| What | Where | Needs a module change? |
|---|---|---|
| **`core.resources` 1.5.0.** Client records gain `sites` (appended last): the client's site records inside the caller's scope. Site records gain `client_name` (appended last). Python and HTTP (`GET /api/tfd/resources/clients/`, `clients/<id>/`, `sites/`, `sites/<id>/`, and the create and update results). | `docs/resource-directory.md`, `contracts.py`, `resource_contract_metadata()` keys `client_sites`, `site_client_name`, `role_reads` | No. Modules that read id, name and client_id are unaffected. I re-checked `modules/`: none compares or hashes a whole client or site record. A module that reads every client (huntress, cyberhoot, scoutdns) now gets each page a little larger. It is one extra query per page, bounded by the 500-row page size. |
| **Endpoints can build its tree from the client read.** | | Yes: Endpoints E1 (`core-modules.md`). |
| **`create_client` gains `site_name` and `custom_fields`. `create_site` gains `custom_fields`.** HTTP bodies accept the same fields. Unknown fields stay refused. | `contracts.py`, metadata `mutation_contracts` | No module under `modules/` calls `create_client` or `create_site`. UI sends `site_name` (required in the form) and optional `custom_fields` (UI U2). |
| **Narrowed: a role limited only by sites no longer gets a client it creates.** Core 1.17.21 added the new client to the creator's `can_view_clients` whenever the creator was restricted. Core now follows Tactical: only when that list is not empty. | `docs/resource-directory.md` | A site-only role that adds a client must be given it by an administrator. See CQ73. |
| **Names may not contain `|`** (create and rename, client and site). A new `invalid_resource_request` message. | | UI shows Core's message. |
| **`role_scope` audit row** when a role's client or site list changes. | `docs/account-security-policy.md` | No. |
| **The enrollment 403 carries `code: "setup_session_required"`.** | `docs/account-security-policy.md` | UI maps it to a plain message (UI U4). |
| **A `core_refused` row names an object only from cleaned path values.** | `docs/tactical-operations.md` | No. A module must not expect an object id on these rows when the call was refused before the path parameters were cleaned. |
| Capability `core.resources` is 1.5.0, inside the installer's `>=1.1.0,<2.0.0` check. No module under `modules/` pins `core.resources` in a manifest. | `install.sh` (unchanged) | No. |

## Review notes

- AD-12 says denied means hidden and refused. A role with List clients but not List sites now sees site names inside client records. That is Tactical's own `/clients/` behaviour (AD-5, AD-25) and opens no data beyond Tactical. The sites read itself stays refused without List sites.
- The nested sites are scoped by the same `filter_by_role` rule as the sites read. A site-only role sees only its granted sites, under the parent client that rule already shows.
- The first-login fix keeps the short-lived, one-time, password-proved design. It changes only how "short-lived" is measured.

## Decisions for Johan (`reviews/questions/core.md`)

- **CQ72:** who may change a role's client and site lists. I went on with Tactical's rule plus the new audit row.
- **CQ73:** whether a site-only role is widened when it adds a client. I went on with Tactical's rule (not widened).

## Tests

New: `tests/totp-setup-token-age-1.17.22.py`, `tests/resource-client-sites-1.17.22.py`, `tests/resource-create-client-site-1.17.22.py`, `tests/role-scope-lists-1.17.22.py`.

Dev server only, written but not run: `tests/totp-setup-token-runtime-1.17.22.py`, `tests/resource-client-sites-runtime-1.17.22.py`, `tests/role-scope-lists-runtime-1.17.22.py`.

Updated: `tests/resource-alert-template-1.17.17.py`, `tests/resource-directory-foundation.py`, `tests/resource-directory-write-hardening.py` and `tests/resource-scheduler-audit-scope.py` (new version, key tuples and the create return shape; the write-hardening test no longer expects a site-only creator to be widened), `tests/tactical-superuser-guard.py` (stub methods only), `tests/tactical-operations-core-refused-rows-1.17.21.py` (object ids and new sentinel cases) and `tests/tactical-operations-modules-compat-1.17.18.py` (the `server_only` pin).

These tests stub Django. Django, Knox, Celery and a database are not installed on the development PC, so nothing ran against a real Django, Knox or a database. The three runtime scripts above are due on the dev server. The first one is the proof that a real Knox token with auto refresh still enrols. `tests/resource-directory-custom-fields-postgres.py` was not run, and nothing in it assumes the old widening.

## Not in this release

- Names built from endpoint rows, and anything for a role with neither List clients nor List sites (Johan's Question 1 is open).
- Policy fields on client and site records (`workstation_policy_id`, `server_policy_id`, `block_policy_inheritance`) and the Alerts template filter: next in line, a separate and larger change to the same records.
- The Tactical WebSocket ticket for the terminal (C4), end all sessions (CO17), the session theme choice (CO9) and the "System name" setting for the authenticator label.
- Any change to who may edit a role's client and site lists (CQ72).
