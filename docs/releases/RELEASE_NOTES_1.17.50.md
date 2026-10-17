# Tec-Tac Framework 1.17.50

Universal filters, Core half. One operator vocabulary, one safe validator, saved filter sets with sharing, and a scope-safe value lookup for "Equals"
pickers. Core also lists the UI 0.12.114 component kit and style tokens in the public contract export.

A module that wants to offer filters declares them and calls these functions. Nothing a module does today changes.

## Module-facing changes

This is a pure addition. Every existing capability, function and route works as before. One small hardening touches saved views (see the last point).

- **New capability `core.filter_sets` 1.0.0** (owner `core`). Operations: `operators_for`, `validate_filter_set`, `build_q`, `matches`, `from_legacy_formula`,
  `list_filter_sets`, `get_filter_set`, `create_filter_set`, `update_filter_set`, `delete_filter_set`, `resolve_filter_set`. Python module `tec_tac.filter_sets`.
  A module that uses any of it sets `requires.framework` to `>=1.17.50`. Details: `docs/filter-sets.md`.
- **New provider shape `<module id>.filter_fields` 1.0.0.** A module that offers filters registers it with `describe_fields(*, context)` and
  `distinct_values(field_id, *, context, search, page, page_size)`. A core or server module also lists it in its manifest `capabilities`. **The provider must
  filter at the source inside `context.scope`.** Core cannot check what a value means.
- **New routes:** `GET/POST /api/tfd/filter-sets/`, `GET/PUT/DELETE /api/tfd/filter-sets/<uuid>/`, `GET /api/tfd/filter-sets/fields/` and
  `GET /api/tfd/filter-values/`. Writes are limited to 60 a minute and 2000 a day. The two reads are limited to 240 a minute.
- **Where the plan and the code differ.** `create_filter_set`, `update_filter_set` and `resolve_filter_set` take the module's own `fields` as an argument.
  Core never calls a module's provider from Python, so no module can make Core call another module's provider (rule 1.10, checklist C6). Only the two HTTP
  routes call a provider, for the signed-in person. `resolve_filter_set` returns the checked tree, not a pair.
- **Saved views refuse the view key prefix `fs-`.** Filter sets live on the saved views table under that prefix. Saved views now refuse to create, list, read,
  change or delete a row under it, so a filter set only changes through its own checked, audited path. No module in `modules/` uses a key that starts with
  `fs-`. Audit, Debug and Endpoints use their own keys and are not affected. This is the only change to existing behaviour.
- **Browser contract rows** (documentation only): `ui.authenticated.components` now lists `DataTable`, `FormRow`, `EditorWindow` and `Stepper`, and the
  `SearchSelect` props `required`, `invalid` and `describedBy`. A new row `ui.authenticated.styleTokens` lists the eleven size and density tokens and the
  `tt-ws` class. `registerPublic` still gets no components.

## What changed and why

### One vocabulary (`tec_tac.filter_sets`)

Core owns six operators: equals, does not equal, contains, does not contain, starts with, ends with. The ids and labels are the ones Groups already uses, so
nothing a module saved changes meaning. Which operators a field offers depends on its kind.

| Kind | Operators |
|---|---|
| `text` | All six |
| `bool` | Equals only |
| `id` (client, site) | Equals and does not equal on the ID. The four text operators too, matched on the display name, when the field declares a name. |

There are no number or date ranges in this release. Nobody asked for them.

### Field declarations

A module returns the fields a person may filter on. Each has an id, a label, a kind and a way to find it: a Django `lookup`, a dict `row_key`, or both. Core
checks each declaration and drops a bad one with a log line. The browser sees the id, label, kind, operators and value source. It never sees a lookup or a key.

### A safe validator and two evaluators

`validate_filter_set` refuses what it cannot accept and never drops a rule quietly. At most 50 rules and 20 groups. Groups nest 3 deep. A value is at most
200 characters with no control characters. An ID is a whole number above zero. A field the person may not use is refused.

`build_q` makes a Django `Q` from the declared lookups only, with `iexact`, `icontains`, `istartswith` and `iendswith`. Django escapes `%`, `_` and `\` in these,
so a typed `%` matches only a literal `%`. There is no raw SQL and no regular expression. The `not_` operators negate, so an empty value still matches
"does not equal", as Groups does. `matches` is the same test for a plain dict. A filter is added to the module's own role-scoped list with AND, so it can only narrow.

`from_legacy_formula` turns a Groups membership formula into the same tree with identical results. Groups reads left to right with no precedence, and the tree
nests the same way. Groups' own validator and resolver are not touched. A formula that is too complex for a filter set raises an error, and Groups keeps
evaluating it.

### Saved filter sets

A set has a name, an owner, readers and a definition, per module and view key. It is stored on the saved views table, so there is no new table and no migration.
Only the owner edits, shares or deletes. There is no administrator override. A private set a person cannot read is "not found". A person can have 100 sets per
module and key.

Every create, change, share change and delete writes a strict Core audit row in the same transaction (`add`, `modify`, `custom:filter-set-share`, `delete`). The
row holds counts. It never holds a rule value or a reader id. A failed audit write rolls the change back.

`resolve_filter_set` checks the stored definition again against the module's current fields for the person. A rule on a field the person may no longer use makes
the set refuse with "This filter set uses a field you cannot use." It never drops the rule and never widens the filter.

A set shows its rule values to everyone it is shared with. `docs/filter-sets.md` says so in plain words. This is a decision for Johan (see
`reviews/questions/core.md`); the release goes on with the safest simple choice.

### The value lookup for "Equals" pickers

`GET /api/tfd/filter-values/` asks the module that owns the field for a page of 25 distinct values. The provider filters inside the person's scope. Core adds:

- module access, and only that module's own capability answers;
- the field must be one the person was offered with `values.source` `distinct`;
- an empty answer, **without calling the provider**, when the person's scope mode is `none` or cannot be read;
- an answer cut to the page size, only text and whole numbers, no repeats, bounded text;
- a 502 `values_unavailable` when the provider fails, with no stack text and **no fallback** to any other source;
- a 30 second cache in the web process, at most 256 entries, keyed by person, a hash of their scope, module, field, search text and page. It makes no Redis call,
  the lesson of 1.17.48 and 1.17.49. An operating system seen only on another client's agents is never served from someone else's cached answer. A role change takes
  effect at once.

## Requests closed

- **Universal filters (Core half)**, from Johan's answers of 9 October 2026. The UI half, the Agents provider, the Endpoints and Groups adoption wait for this
  release and are in `reviews/requests/ui.md`, `reviews/requests/core-modules.md` and `reviews/requests/premium-modules.md`.
- **UI 0.12.114 contract rows**, also asked by scriptmanager 0.4.6.

The release manager removes both entries from `reviews/requests/core.md` after signing, naming 1.17.50.

## What is not in this release

- Number and date ranges.
- A provider timeout Core enforces in-process. Core has no thread or timer for it. The contract limits a provider to one indexed query of at most `page_size + 1` rows.
- Export of a filter set.
- A dedicated table for filter sets. Django is not installed on the PC that prepares releases, so a migration cannot be generated or checked here.
- The two held 1.17.49 findings in `event_jobs.py` stay with the backlog. They are not filter code.

## Checks run here

Django and DRF are not installed on this PC. The new tests use a fake Django boundary, as the saved views tests do. They run the real `filter_sets.py`, `saved_views.py`,
`audit.py`, `registry.py` and `capabilities.py`. Migration, the real ORM, the real DRF throttles and the dev server are not exercised. Johan should export the public
contract on the dev server after install and check that `core.filter_sets` and the four routes are listed.
