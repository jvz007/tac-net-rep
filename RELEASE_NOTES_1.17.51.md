# Tec-Tac Framework 1.17.51

Security and review fixes for the universal filters, a stricter record of the event-job refusal report, a compare-and-set guard for client and site policy
writes, and documentation that closes two open requests.

A shared filter set no longer shows a client or site you cannot see. Nothing a module does today breaks: every change is additive, and a module that does not use
the new keywords or keys behaves exactly as before.

## Module-facing changes

- **Shared filter sets withhold out-of-scope values (core.filter_sets 1.0.0, additive).** A reader who is not the owner of a shared set sees a rule value only when it
  is inside their scope. Otherwise the rule comes back as `{kind, field, operator, value: null, withheld: true}`, and the set carries a top-level `values_withheld`
  count (0 for the owner and when nothing is withheld). The definition keeps its shape. The owner's view, `resolve_filter_set`, `build_q` and `matches` are unchanged.
  - **New optional field declaration key `scope_kind`** (`"client"` or `"site"`, on a field of kind `id` only) on `<module id>.filter_fields` 1.0.0. It is checked in
    the declaration and never shown to the browser. An `id` field **without** it is always withheld from a non-owner, so a module that offers a client or site field
    should declare it.
  - **`list_filter_sets(user, module_id, view_key, *, fields=None)` and `get_filter_set(user, set_id, *, fields=None)`** take the module's own field declarations. Core
    calls no provider from Python. With no `fields`, every value of a set the person does not own is withheld.
  - The two GET routes read the signed-in person's fields only when a set the person can read but does not own has rules. A missing or failing provider never fails
    the GET: every such value is withheld.
  - A module that uses filter sets and wants the withholding needs `requires.framework >=1.17.51`. The capability stays 1.0.0 and `requires_framework` in its metadata
    stays `>=1.17.50`.
- **`core.resources` 1.10.0 -> 1.11.0 (additive, still major 1, framework >=1.17.51).** `update_client` and `update_site` take the optional compare-and-set guard
  `expected_workstation_policy_id`, `expected_server_policy_id` (a positive integer, or `None` for "must be unset") and `expected_block_policy_inheritance` (a real
  bool), all `UNSET` by default. `PATCH /api/tfd/resources/clients/<id>/` and `sites/<id>/` accept the same three keys. The compare runs inside the write
  transaction against the locked record. A stale guard writes nothing, writes no audit row and answers `409` with the code `record_changed` and a sentence that names
  the field and no value (in Python `ResourceConflict.code`). A guard alone is not a change. A call with no guard behaves as before. `install.sh` accepts any 1.x from
  1.1.0, so it needs no change. Details: `docs/resource-directory.md`, "Compare-and-set guard (since 1.11.0)".
- **Audit: an event-log export by a person who holds only List checks. No Core behaviour changed.** Core has accepted this row since 1.17.20
  (`declared-operation-owner`). Checks needs to declare its event-log read as a GET Tactical operation with audit action `export`, permissions
  `["can_list_checks"]` and no `module_permission`, then write its export row from the backend. It can adopt this with `requires.framework >=1.17.51`. This release
  adds a pinning test, a worked example in `docs/module-audit.md` and the same example in the `audit.record` contract row. Core does not loosen the rule: any module
  could otherwise claim a flag it never declared. The Checks release still waits for Johan's answer to the open question in `reviews/questions/core-modules.md`.
- **Contract rows (documentation only).** `ui.authenticated.components` now also says where each `EditorWindow` area draws (`actions`, `properties`, `content`,
  `footer`), that the `FormRow` control goes in the default slot and that its ids are `forId + '-hint'` and `forId + '-error'`, the `DataTable` width unit (a number
  with `px` or `%`), the footer "Showing the first 2000 rows.", that a `cell(row, column)` that throws shows an empty cell, and the keyboard keys. The rows of 1.17.50
  already listed the four kit components, the three `SearchSelect` props and `ui.authenticated.styleTokens`.
- **Event-job wording (documentation and capability text).** The 1.17.49 sentence that put a time limit on unsent counts is gone, because no such limit holds.
  The limits are now stated as they are: counts wait in the web process's memory until that process's next publish or refusal sends them, and are lost if it restarts
  first; a count that reaches the worker after its hour has already been reported is not reported; a cache flush or fault loses a count. `core.event_jobs` stays 1.1.0.
- **Saved views.** Nothing changes for a module's own saved views. A saved view made before 1.17.50 under a key that starts with `fs-` is no longer read as a filter set
  and returns to its owner's saved views list under the key `fs_` + the rest (see below).

## What changed and why

### Out-of-scope values in shared filter sets (1.17.50 review, MEDIUM, CQ144)

The 1.17.50 review found that a person who can use a module but cannot see client B could open a shared set whose rule says "client equals B" and read that id or name.
Johan took the secure default for this release (CQ144 option b).

`serialize_filter_set(row, viewer, *, fields=None)` keeps the full definition for the owner. For anyone else each rule value is checked.

| Value | Shown to a non-owner when |
|---|---|
| `id` field with `scope_kind`, Equals or Does not equal | the reader is unrestricted, or the id is in their `whole_client_ids` (client) or `site_ids` (site), or `resources.get_client` or `get_site` finds it in their scope |
| `id` field with `scope_kind`, a name operator | `resources.list_clients` or `list_sites` (`search`, one row) finds a client or site the reader may see whose name contains the text |
| `id` field with no `scope_kind` | never (Core cannot prove its scope) |
| `text` or `bool` field | always (text values such as an operating system are not scope-limited here) |
| unknown field, or a value that is not text, a whole number or a bool | never |

Any lookup that fails, including a missing List clients or List sites flag, withholds the value. Lookups are remembered for the call, and at most 200 distinct lookups run
in one call. Past that the value is withheld. The set's name is a label its owner typed and stays visible. The UI request for a warning next to the Shared choice stays.

### A non-owner PUT is refused before any provider call (1.17.50 review, LOW)

`PUT /api/tfd/filter-sets/<id>/` now reads the set first. A reader who is not the owner gets `403 permission_denied` before the module's provider is called, with or
without a `definition`. Before, a non-owner PUT with a definition called the provider first, so a failing provider answered 502 and the module did work for a person who
could not change the set. A set the person cannot read is still 404.

### Old `fs-` saved views (1.17.50 review, LOW)

A saved view made before 1.17.50 under a key that starts with `fs-` became a filter set by accident. Core now reads an `fs-` row as a filter set only when its payload has
the shape Core writes (`kind` `filter_set`, `version` the whole number 1, `match` `all` or `any`, `rules` a list). Any other `fs-` row is not found.

`install.sh` runs `repair_stray_saved_views()` after the migrations. It renames each such row to `fs_` + the rest (the same length, a valid saved view key), so the owner's
old view returns to their saved views list. It never deletes. A row whose new key would clash with the owner's unique (module, key, name) is left as it is and counted. It
is idempotent, logs `renamed` and `skipped`, and only warns if it fails. No migration is written (CQ150).

### The event-job refusal report counts only a confirmed write (held 1.17.49 MEDIUM)

`audit.record` is not strict in the event-job code, so a failed write comes back as `recorded: False` without raising. `_audit` returned True for it, so the hourly
refusal report kept its claim and the count was lost. `_audit` now returns True only when `audit.record` answers a dict whose `recorded` is exactly `True`. A `recorded:
False` answer, any other answer and an exception are failures and are logged. The report releases its claim after a failed write, and the next tick writes one
`custom:event-job-refused` row with the full count. The outcome-row callers ignore the return value and behave as before.

### Compare-and-set guard (request from automation 0.10.0)

Automation's Remove from policy, Assign client or site and Edit policies ask one Yes or No and then write. A gap remained between its own re-read and the write. The guard
closes it inside the write transaction. See the module-facing section above.

## What could not run here

Django, DRF, Redis and Celery are not installed on this PC. The new tests run through the in-memory boundary of `tests/filter_sets_boundary_1_17_50.py`, the event-job stub
set and the in-memory Tactical of `tests/resource-alert-template-1.17.17.py`. Two things only run on a real server: the `select_for_update` row lock under the guard (the
compare itself is tested on the locked object with stub rows and with the fake models) and the `install.sh` repair step against the real database.

## Requests closed or answered

- Closed: "UI 0.12.114 contract rows" (shipped in 1.17.50 and 1.17.51), "from automation 0.10.0: a compare-and-set guard" (the Core half) and "checks: audit row for an
  export by a person with only Tactical's List checks flag" (the Core half: no change was needed, now documented and pinned).
- Questions recorded with their assumptions in `reviews/questions/core.md`: CQ144 (updated), CQ149 to CQ153.
- Left for a later release: names-only or `***` for `audit_lists` of nested lists (Tasks 0.10.1), a correlation id for bulk actions on the browser route (CQ151), and Core
  enforcement of "only a SuperAdmin may invite" (CQ152).

## Fixed after review

Round 1 (review of 1.17.51) blocked the build on one item: the `ruff (errors)` structure check.

- `tests/event-jobs-audit-claim-1.17.51.py` ran the setup of the 1.17.49 test with `exec(..., globals())`. That works at run time, but ruff cannot see the names it creates and reported F821 (undefined name) for `reset`, `register`, `beta`, `key`, `window`, `ej`, `deliver`, `must`, `WALL`, `HOUR`, `tick_only`, `CACHE`, `rows`, `AUDIT` and others. The setup now runs in its own namespace and the test binds each name it uses explicitly. No product code changed and the test's cases are the same.
- The release notes file is renamed to `RELEASE_NOTES_1.17.51.md`, and the two tests that read it now use the new name.
- Sibling check: `ruff check --select F821,E9` now passes on the whole repository. `tests/resource-expected-guard-1.17.51.py` also execs a harness into `globals()` but its names resolve for ruff, so it is unchanged.
