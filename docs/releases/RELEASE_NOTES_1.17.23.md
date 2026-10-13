# Tec-Tac Framework 1.17.23

This release gives the authenticator app a name you choose. It adds the contract rows for popup windows and the shell's Yes or No dialog. It lets a caller put a list in the audit "before" value. It adds a read of the custom fields before a client or site exists. It also closes the two Low findings held from the 1.17.22 review.

Capabilities: `core.tactical_operations` goes from 1.7.0 to 1.8.0 and `core.resources` from 1.5.0 to 1.6.0. Both are still major 1, and everything below is additive.

Date: 13 October 2026.

## Closes

In `reviews/requests/core.md`:

- "from ui 0.12.95 (popup mode)" and "browser contract rows: the shell confirm dialog" (ui 0.12.96, the router part included).
- "MFA name (issuer)", with Johan's answer (b) of 12 October 2026.
- "from automation 0.8.1" and "from Core 1.17.21 review" (list values in `audit_before`).
- "resources: a read of custom-field definitions without an id" (ui 0.12.96, CO22).
- "from ui 0.12.95: batch intake in use", and with it "from ui 0.12.94: Module intake" (shipped in 1.17.18).

Held from the 1.17.22 review: the role-create audit row that could be skipped, and the custom-field id that was not checked before the create.

Confirmed shipped in 1.17.22 and needing nothing more: the `core_refused` row takes its object id only from cleaned path values, and the Agents compatibility test asserts that `server_only` is a boolean.

## What changed

### The system name in the authenticator app

Before, the authenticator showed the server address, for example `app.test.techxflow.net.za/tec-tac`. Johan chose option (b): a name set in Core settings.

- New runtime setting `system_name`. Default `Tec-Tac`. Plain text, 1 to 60 characters. Migration `0027_runtime_system_name` adds one column. The existing row reads `Tec-Tac`.
- Core trims the name and normalises it (NFC). It refuses an empty name, a control character, a zero-width or other invisible character, a colon, and any value that is not text. JSON `null` resets it to `Tec-Tac`.
- We refuse a colon with a plain 400. We never change it silently. An authenticator label uses a colon to separate the name from the account, so a stored colon would break the label.
- Who may change it: an effective superuser or a role with `core.runtime_settings.manage`, the same rule as the register time limit. The upload limit and the update source stay superuser only.
- Each change writes its own strict audit row (`object_id` `system_name`, the name before and after). The name is not a secret. Sending the value it already has writes no row.
- The authenticator label and the `issuer` of the set-up answer (`POST /api/tfd/auth/totp/enrollment/`) now carry the name. They never carry a host and never `/tec-tac`. This covers first-time set-up and "Reset my own two-factor", because Reset signs the person out and the next sign-in takes the same path.
- The `ui_url` field of the answer stays, so older UI builds keep working.
- The secret does not change. Existing authenticator entries keep working. Only a new set-up carries the new label.
- `GET /api/tfd/ui/context/` carries `system_name`, and `GET /api/tfd/system/runtime-settings/` carries `system_name: { value, maximum_length, default }`. We built no unauthenticated read, because that would be a new public route. The sign-in set-up screen takes the name from the `issuer` of the answer, which Core builds.

The UI half (a field on the settings page, and `tecTacTotpIssuer()` showing the name Core returns) is in `reviews/requests/ui.md`.

### Contract rows for popup windows and the confirm dialog

Documentation only. No behaviour changed in Core.

- `ui.authenticated.popup`: `context.popupHref(path)` and the route `meta` fields `popup`, `permission` and `permissions` (UI 0.12.95).
- `ui.authenticated.confirm`: `register(context).confirm(options)` and the `confirm` key on a context action handler's argument, with every option and its limit (UI 0.12.96).
- `ui.authenticated.module-descriptor`: the additive `dependencies` field of `modules.json`. Core writes no descriptor itself.
- The router row now says that, since UI 0.12.96, the guard refuses a route or alias under `/popup/` and an alias another owner already holds.

### A list in the caller's `audit_before`

The Python-only `audit_before` of `run_tactical_operation` accepts, per field, a list of whole numbers or texts of at most 256 characters. Core keeps the first 1000 entries. The row carries `<field>_count` (the full length) and, when the list was cut, `<field>_truncated: true`, as declared before fields do. A list holding anything else is refused 400 `invalid_audit_before`, and so is a tuple. A caller field named `<list>_count` or `<list>_truncated` next to a list is refused, because Core writes those two itself. The 16-field limit counts the caller's own fields only. Automation's Run now can now put its endpoint ids in the row.

### Role-create audit never skipped silently (held Low)

The 1.17.22 wrapper found the new role by "newest id, then ids above it, then name". On an empty role table, or when Tactical accepted a blank name, it found nothing and wrote no row without saying so. The wrapper now compares the set of role ids before and after Tactical's create, inside the same transaction. One new id is the created role. When a concurrent create added more, the ones whose name equals the request name are kept, and exactly one must remain. Zero new roles, or an ambiguous set, raises and rolls Tactical's create back, as a failed audit write does. A failed Tactical answer still writes nothing.

We did not touch the nested-sites rule for a role that holds only List clients. That is Johan's open question (CQ74).

### Custom-field ids are validated before the create (held Low)

`create_client`, `create_site` and `update_custom_fields` now require every `field_id` to be a positive whole number: a real integer of 1 or more, or text made only of ASCII digits that is at least 1. `abc`, `1.5`, `true`, `null`, `0`, a negative number, a list, `'1.5'` and `' 1'` give a 400 (`field_id must be a positive whole number.`) before anything is created. Before, the adapter's `int()` took `true` and `1.5` as 1, and `abc` gave a 500 after the create. The cleaned integer is what the adapter and the audit row see. Duplicate ids are still refused by the adapter. `update_custom_fields` now also refuses more than 200 items, as the create calls already did.

### A read of the custom-field definitions without an id

`list_custom_field_definitions(resource_type, *, context)` and `GET /api/tfd/resources/custom-fields/?resource_type=client|site` return `{ resource_type, fields: [{ field_id, name, type, options, required, value }] }`. `value` is the field's default. The order and shape match the read that needs an id. Hidden fields never appear. No per-client data is read, so nothing is scoped.

- The gate is the create's own: Tactical `can_manage_clients` or `can_manage_sites` plus the Core permission. A superuser passes. A service context is refused. A role with only List clients is refused.
- `resource_type` must be exactly `client` or `site`. Anything else is a 400, and so is an unknown query name.
- The UI asked for the List clients or List sites check. We chose the create's own gate, because only a person who can add a client needs the form, and it matches the read that needs an id. Johan decides this one (CQ75).

### Batch intake: where the UI reads trust

No behaviour change. A row of `packages` for a standalone package is the stage answer plus the `source_*` keys, so it carries its own `publisher_trust`. A bundle child row has no `publisher_trust` of its own. Its trust is the `publisher_trust` of the entry in `artifacts` whose `upload_id` equals the row's `source_upload_id`. A test pins this. UI 0.12.95 can rely on it.

## Module-facing changes

Each change below that a module relies on needs `requires.framework >=1.17.23`. Existing keys, query parameters, paging and error codes do not change.

| What | Where | Needs a module change? |
|---|---|---|
| **Browser contract rows** `ui.authenticated.popup`, `ui.authenticated.confirm`, `ui.authenticated.module-descriptor`, and the `/popup/` text on `ui.authenticated.router`. Documentation only. | `contracts.py` (`BROWSER_CONTRACTS`), the generated export | No. endpoints, take-control and remote-background already use `popupHref` and `meta.popup`. endpoints 0.5.3 uses `context.confirm`. |
| **`system_name`** in `GET /api/tfd/ui/context/` and `GET /api/tfd/system/runtime-settings/`. Additive. | `docs/runtime-settings.md`, the runtime-context row | No. Display only. |
| **`core.tactical_operations` 1.8.0.** `audit_before` accepts a list per field. Feature-detect with `>= 1.8.0`. | `docs/tactical-operations.md`, the `run_tactical_operation` row | Optional. Automation is asked to adopt it (`core-modules.md`). agents, patching, globalsettings, remote-background and reportmanager send scalars and are unchanged. |
| **`core.resources` 1.6.0.** New `list_custom_field_definitions` and its route. No record shape changed. | `docs/resource-directory.md`, `contracts.py` | No module calls the custom-field functions. The installer's `>=1.1.0,<2.0.0` check still holds. |
| **Stricter `field_id`** in `create_client`, `create_site` and `update_custom_fields`. | `docs/resource-directory.md` | No module calls them. A caller that sent a boolean, a float or text that is not whole digits now gets a 400. |
| **The authenticator label and the enrollment `issuer`** are the system name. | `docs/account-security-policy.md` | No. |

I checked `modules/` for each of these. No module reads the authenticator issuer, and no module calls `create_client`, `create_site` or the custom-field functions.

## Decisions for Johan (`reviews/questions/core.md`)

- **CQ74:** may a client read nest sites for a role that holds only List clients (AD-12)? I changed nothing and left the 1.17.22 behaviour as it was.
- **CQ75:** which permission gates the custom-field definitions read? I went on with the create's own gate.

## Tests

New: `tests/browser-contract-popup-confirm-1.17.23.py`, `tests/system-name-1.17.23.py`, `tests/tactical-operations-audit-before-lists-1.17.23.py`, `tests/role-create-audit-1.17.23.py`, `tests/custom-field-validation-1.17.23.py`, `tests/resource-custom-field-definitions-1.17.23.py` and `tests/module-intake-batch-trust-1.17.23.py`.

Dev server only, written but not run: `tests/system-name-runtime-1.17.23.py` (the real migration and PATCH) and `tests/role-create-runtime-1.17.23.py` (the real transaction rollback).

Updated: the capability and contract version pins in `tests/audit-correlation-1.17.16.py`, `tests/contract-export-1.17.16.py`, `tests/tactical-operations-1.17.7.py`, `tests/tactical-operations-before-scope-1.17.14.py`, `tests/tactical-operations-core-refused-rows-1.17.21.py`, `tests/tactical-operations-failed-rows-1.17.20.py`, `tests/resource-alert-template-1.17.17.py`, `tests/resource-client-sites-1.17.22.py` and `tests/resource-directory-foundation.py`. `tests/tactical-operations-audit-before-1.17.16.py` no longer expects a list of numbers to be refused (a list of objects still is), and `tests/tactical-operations-audit-before-lists-1.17.18.py` uses a list of objects for the same check. `tests/role-scope-lists-1.17.22.py` and `tests/tactical-superuser-guard.py` have stub changes only, for the id-set lookup. `tests/browser-contract-catalog-1.15.170.py` and `tests/browser-contract-runtime-surface-1.17.2.py` list the new rows, and the first also lists the three `tactical-*` rows that were already in the export and missing from its list.

These tests stub Django. Django, Knox, Celery and a database are not installed on the development PC, so the migration, the real PATCH and the real role-create rollback ran only against stubs. The two runtime scripts above are due on the dev server.

## Not in this release

- The terminal WebSocket ticket (C4), end all sessions (CO17), the session theme choice (CO9) and move a site to another client (CO25).
- Policy fields on client and site records (AU8, AU10). They stay next in line.
- Actions before and after as Tactical. It waits on Johan's answer about script arguments and environment values.
- AU2 (the Patching lifecycle failure). It waits on the install log in `debug/`.
- The nested-sites rule (CQ74), pending Johan.

## Fixed after review

Round 1 blocked the release on the `ruff` errors check. `tests/custom-field-validation-1.17.23.py` used names (`User`, `Role`, `adapter`, `AUDITS`, `resources`, `ctx_for`, `must`, `SAVED`, `Client`, `Site`, `FIELD_DEFS`) that the harness creates at run time, so ruff saw them as undefined (F821). The test now binds each one explicitly from the harness, the same way `tests/resource-create-client-site-1.17.22.py` does. The test logic is unchanged. No Core code changed and nothing module-facing changed.
