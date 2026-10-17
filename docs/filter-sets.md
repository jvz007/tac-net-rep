# Filter sets: one way to filter a list

**Status:** Public Core developer contract, added in Core 1.17.50
**Python:** `tec_tac.filter_sets`
**Capability:** `core.filter_sets` 1.0.0 (major 1), owner `core`
**HTTP:** `GET/POST /api/tfd/filter-sets/`, `GET/PUT/DELETE /api/tfd/filter-sets/<uuid>/`, `GET /api/tfd/filter-sets/fields/`, `GET /api/tfd/filter-values/`
**Provider capability a module implements:** `<module id>.filter_fields` 1.0.0
**Needs:** framework `>=1.17.50` (`requires.framework`). No migration.

## What this is for

A person filters a list: "operating system equals Windows 11", "hostname contains SRV", "client does not equal Acme". Every module used to
build its own operators, its own value lists and its own saved filters. Core now holds one of each, so a filter works the same everywhere
and a module cannot send a field name or a piece of SQL from the browser.

Core owns four things:

1. **One set of operators.**
2. **Field declarations.** A module says which fields a person may filter on.
3. **A safe validator and two evaluators** a module reuses.
4. **Saved, named filter sets** with an owner and sharing, and a **value lookup** for "Equals" pickers.

A module keeps its own list and its own data. Core never reads a module's rows.

## The operators

| Id | Label |
|---|---|
| `equals` | Equals |
| `not_equals` | Does not equal |
| `contains` | Contains |
| `not_contains` | Does not contain |
| `starts_with` | Starts with |
| `ends_with` | Ends with |

These are the ids and labels Groups has used from its first release, so nothing a module saved changes meaning.

Which operators a field offers depends on its kind. `operators_for(kind, has_name=False)` answers.

| Kind | Operators |
|---|---|
| `text` | All six |
| `bool` | `equals` only (the value is true or false) |
| `id` (a client or site) | `equals` and `not_equals` on the ID. The four text operators too, matched on the **display name**, but only when the field declares a name. |

This release has no "greater than", "less than" or date ranges. They are not in the vocabulary yet.

## Declaring fields

The module returns a list of declarations. Core checks each one and drops a bad one with a log line.

```python
{
    "id": "operating_system",            # lowercase slug, up to 64 characters
    "label": "Operating system",         # up to 80 characters
    "kind": "text",                      # text | id | bool
    "lookup": "operating_system",        # the Django field path, for build_q
    "row_key": "operating_system",       # the dict key, for matches (a list that is not a model)
    "name_lookup": "site__client__name", # kind "id" only: the display name path
    "name_key": "client_name",           # kind "id" only
    "values": {"source": "distinct"},    # distinct | static | none
}
```

- A field needs a `lookup`, a `row_key`, or both.
- `values.source` says where the Equals picker gets its values. `distinct` asks the provider (see below). `static` carries up to 50
  `{value, label}` options in the declaration. `none` gives a plain box. A `bool` field always uses `none`.
- A `lookup` is a plain model field path. It is never a lookup suffix, and it never comes from the browser.

**The browser never sees a lookup or a key.** `GET /api/tfd/filter-sets/fields/?module=<id>` returns only `id`, `label`, `kind`, the
operators and the value source (plus static options).

## Checking a filter

```python
from tec_tac import filter_sets

tree = filter_sets.validate_filter_set(raw, fields)
```

A filter looks like this:

```json
{"version": 1, "match": "all", "rules": [
  {"kind": "rule", "field": "operating_system", "operator": "equals", "value": "Windows 11 Pro"},
  {"kind": "group", "match": "any", "rules": [
    {"kind": "rule", "field": "hostname", "operator": "starts_with", "value": "SRV"},
    {"kind": "rule", "field": "hostname", "operator": "starts_with", "value": "DC"}
  ]}
]}
```

The validator **refuses** what it cannot accept. It never drops a rule quietly.

| Limit | Value |
|---|---|
| Rules in a filter | 50 |
| Groups in a filter | 20 |
| Nesting of groups | 3 |
| Characters in a value | 200 |
| Control characters in a value | none |
| An ID value | a whole number above zero |
| A yes/no value | `true` or `false` |

It also refuses a field that is not in the list the person may use, and an operator the field's kind does not offer. A filter with no rules
matches nothing, as in Groups.

## Using a filter in a list

For a list backed by a Django model:

```python
q = filter_sets.build_q(tree, fields)
queryset = my_role_scoped_queryset.filter(q)
```

`build_q` validates the tree again. It uses only the lookups the module declared, with `iexact`, `icontains`, `istartswith` and `iendswith`.
Django escapes `%`, `_` and `\` in these lookups, so a typed `%` matches only a literal `%`. There is no raw SQL and no regular expression.
The `not_*` operators negate, so an empty value still matches `not_equals`, exactly as Groups does today.

For a list that is not model-backed:

```python
keep = [row for row in rows if filter_sets.matches(tree, row, fields)]
```

`matches` compares ignoring case, and treats `None` as empty text.

**A filter only narrows.** The module's own list is already limited to what the person's role can see. A filter is added to that list
with AND, so it can never show a row the person could not already see.

## The value lookup for "Equals" pickers

`GET /api/tfd/filter-values/?module=<id>&field=<field id>&search=<text>&page=<n>` answers `{values: [{value, label}], has_more, page, page_size}`.
The page size is fixed at 25. `search` is at most 100 characters. `page` is 1 to 200.

The module that owns the field answers. It registers the capability `<module id>.filter_fields` 1.0.0 (a core or server module also lists
it in its manifest `capabilities`). It has two operations:

```python
class FilterFieldsProvider:
    def describe_fields(self, *, context):
        """Return the field declarations this person may use. Decide per permission."""

    def distinct_values(self, field_id, *, context, search, page, page_size):
        """Return {"values": [{"value": ..., "label": ...}], "has_more": bool}."""
```

`context` is `tec_tac.resources.user_context(user)`.

### The scope duty (the provider's job)

**The provider must filter at the source, inside the person's scope.** Read `context.scope` and ask the module's own role-scoped list. A
person limited to one site must never see an operating system that exists only on another client's agents. Run one indexed query that
returns at most `page_size + 1` rows. Do not load a whole list and cut it afterwards. Core cannot know what a value means, so Core cannot
check this for you.

### What Core adds

- The person must be signed in and allowed to use the module.
- Only that module's own capability answers. A module can never serve another module's field.
- The field must be in the answer of `describe_fields` for this person and have `values.source` `distinct`. Otherwise: 404.
- If the person's scope mode is `none`, or cannot be read, Core answers an empty list **without calling the provider**.
- Core cuts the answer to the page size. It keeps only text and whole-number values, drops repeats, drops a value over 200 characters
  or with a control character, and cuts a label to 300 characters.
- A provider error answers 502 `values_unavailable`, with no stack text. **There is no fallback** to a Core or private path.
- A short cache: 30 seconds, at most 256 entries, in the web process (no Redis call on the request path). The key holds the person,
  a hash of their scope, the module, the field, the search text and the page. An operating system seen only on another client's agents
  can never be served from someone else's cached answer, and a role change takes effect at once.
- A read limit of 240 a minute per user and IP.

Core publishes **no Python function** that calls a provider for another module. The lookup is private to this route.

## Saved filter sets

A filter set is a named filter a person keeps, per module and view key, with an owner and sharing.

| Field | Meaning |
|---|---|
| `id` | UUID, set by Core |
| `module_id` | The module the set belongs to |
| `view_key` | The screen or list, a lowercase slug up to 61 characters |
| `name` | 1 to 160 characters, unique for one owner, module and view key |
| `definition` | `{version, match, rules}` as above |
| `shared`, `mine`, `can_edit`, `owner` | As for saved views |
| `readers` | User ids, returned to the owner only |

Rules:

- `readers` empty means shared with everyone who can use the module. A list of ids makes it private to the owner and those people.
- **Only the owner edits, shares or deletes.** There is no administrator override. Another person can use the set or save their own copy.
- A person who cannot read a private set gets "not found", so its existence does not leak.
- At most 100 sets per owner, module and view key.
- A set is stored on the saved views table (no new table, no migration) under the view key `fs-` + your key. Saved views refuse the
  prefix `fs-`, never list those rows and never change them.

### Rule values are visible to the people a set is shared with

A shared set shows its rule values to everyone it is shared with. A person who can use the module but cannot see client B could open a
set whose rule says "client equals B" and read that name. The value pickers never offer a value outside a person's scope, but a set
carries what its owner typed or picked. The set shows no rows, and it can only narrow the reader's own list. Share only what you mean to share.

### Checked again on every use

`resolve_filter_set(user, module_id, filter_set_id, fields)` returns the tree for a module's list to evaluate. The stored definition is
checked against the module's **current** fields for this person. A rule on a field the person may no longer use, or one the module no
longer declares, refuses with "This filter set uses a field you cannot use." (422). It is never dropped and never widened.

The module passes its own `fields`. Core does not call a provider here.

### Audit

Each change writes a strict Core audit row in the same transaction. A failed audit write rolls the change back. Module `core`, object
type `filter_set`, object id = the set id.

| Action | When |
|---|---|
| `add` | A set is saved |
| `modify` | The name or definition changes |
| `custom:filter-set-share` | The sharing changes |
| `delete` | A set is deleted |

The row holds the module, view key, name, a shared flag, a rule count and a readers count. **Never a rule value, never a reader id.**

## HTTP

| Route | What |
|---|---|
| `GET /api/tfd/filter-sets/?module=&view_key=` | The sets the person can read |
| `POST /api/tfd/filter-sets/` | Save a set. The body: `module_id`, `view_key`, `name`, `definition`, optional `readers`. |
| `GET/PUT/DELETE /api/tfd/filter-sets/<uuid>/` | One set. Change and delete are owner only. |
| `GET /api/tfd/filter-sets/fields/?module=` | The fields the person may use, with operators |
| `GET /api/tfd/filter-values/?module=&field=&search=&page=` | Values for an Equals picker |

Writes are limited to 60 a minute and 2000 a day per user and IP. Unknown body fields are refused. Status codes follow saved views, plus
422 `field_unavailable` and 502 `values_unavailable`. Every error body carries `detail` and `code`.

## Python

The functions take the signed-in user first and raise a `FilterSetError` subclass with a `status_code`.

```python
filter_sets.operators_for(kind, has_name=False)
filter_sets.validate_filter_set(raw, fields)
filter_sets.build_q(tree, fields)
filter_sets.matches(tree, row, fields)
filter_sets.from_legacy_formula(formula)
filter_sets.list_filter_sets(user, module_id, view_key)
filter_sets.get_filter_set(user, set_id)
filter_sets.create_filter_set(user, module_id, view_key, name, definition, readers=None, *, fields)
filter_sets.update_filter_set(user, set_id, *, name=..., definition=..., readers=..., fields=None)
filter_sets.delete_filter_set(user, set_id)
filter_sets.resolve_filter_set(user, module_id, filter_set_id, fields)
```

`fields` are the module's own declarations for this person. Feature-detect with `has_capability("core.filter_sets")` and set
`requires.framework` to `>=1.17.50`.

## Groups

Groups keeps its own membership formula, validator and resolver. Nothing it saved changes. `from_legacy_formula(formula)` turns a Groups
formula into a filter tree with the same results: Groups reads items strictly left to right with no precedence, so `A or B and C` means
`(A or B) and C`, and the tree nests the same way. Values are kept as they are for `validate_filter_set` to check. A formula that is too
complex for a filter set (more than 50 rules, or more than 3 levels of groups once nested) raises an error. Groups keeps evaluating it
with its own resolver.

## Not in this release

- Number and date ranges (greater than, less than, between).
- A timeout Core can enforce on a provider. Core has no thread or timer for it. The contract limits a provider to one indexed query of
  at most `page_size + 1` rows, and the 502 path covers failure.
- Export of a filter set.
- A dedicated table. Sets live on the saved views table until a later release can generate and check a migration.
