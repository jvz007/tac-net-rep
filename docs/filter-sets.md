# Filter sets: one way to filter a list

**Status:** Public Core developer contract, added in Core 1.17.50
**Python:** `tec_tac.filter_sets`
**Capability:** `core.filter_sets` 1.1.0 (major 1), owner `core`. 1.1.0 (Core 1.17.52) adds the date and number kinds.
**HTTP:** `GET/POST /api/tfd/filter-sets/`, `GET/PUT/DELETE /api/tfd/filter-sets/<uuid>/`, `GET /api/tfd/filter-sets/fields/`, `GET /api/tfd/filter-values/`
**Provider capability a module implements:** `<module id>.filter_fields` 1.0.0
**Needs:** framework `>=1.17.50` (`requires.framework`). A module that declares a `date` or `number` field needs `>=1.17.52`. No migration.

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

Six operators are the base vocabulary (`OPERATORS`). Date and number fields add more (see "Date and number fields").

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
| `date` (1.17.52) | `equals` ("Is"), `not_equals` ("Is not"), `before`, `after`, `on_or_before`, `on_or_after`, `between`, `in_the_last`, `not_in_the_last` |
| `number` (1.17.52) | `equals`, `not_equals` ("Does not equal"), `greater_than`, `less_than`, `at_least`, `at_most`, `between` |

The six text ids and labels never change. The new ids live in their own tables (`DATE_ONLY_OPERATORS`, `NUMBER_ONLY_OPERATORS`; all of them
in `ALL_OPERATORS`), so `OPERATORS` and the route's `operators` key stay the six. An unknown kind still raises.

## Date and number fields (Core 1.17.52)

Both kinds are additive. Nothing stored before 1.17.52 holds them, so no existing set changes.

### Date values

A date value is a whole day, written as an ASCII `YYYY-MM-DD` string. It must be a real date from 1970-01-01 to 2100-12-31. There is no
time of day.

| Operator | Value | Meaning |
|---|---|---|
| `equals` | a day `D` | the whole day: from `D` 00:00 up to, not including, `D+1` 00:00 |
| `not_equals` | a day | not that day |
| `before` | a day | earlier than `D` 00:00 |
| `on_or_before` | a day | earlier than `D+1` 00:00 (the whole of `D` counts) |
| `after` | a day | `D+1` 00:00 or later |
| `on_or_after` | a day | `D` 00:00 or later |
| `between` | `{"from": D1, "to": D2}` | both days included, `D1` no later than `D2` |
| `in_the_last` | `{"amount": N, "unit": "minutes", "hours" or "days"}` | from now minus N up to now, both included. A time in the future does not match. |
| `not_in_the_last` | the same | the exact opposite of `in_the_last` |

`amount` is a whole number from 1 to 525600 for minutes, 8760 for hours or 3650 for days. A bool, a decimal, text or any other unit is refused.

**Days are UTC days.** "Last seen on 17 October" means 17 October 00:00 to 24:00 UTC, not South African time. Show that in the help text.

**Relative rules stay relative.** The stored set keeps `{amount, unit}`, never a calculated time. `now` is read once per call, so a saved
"last 7 days" set is always about the last 7 days from when it runs. `build_q` and `matches` take an optional keyword-only `now` for tests.

### Number values

A number value is a JSON integer or a finite decimal. A bool, `NaN`, infinity, numeric text and any magnitude above 10**15 are refused.
`between` is `{"from": A, "to": B}`, both included, `A` no larger than `B`.

### NULL and unreadable values

A row with no value, or one Core cannot read, **never satisfies a positive operator**. It does satisfy `not_equals` and `not_in_the_last`.
`build_q` (Django's `~Q`) and `matches` give the same answer.

### The query a module gets

`build_q` emits only plain equality, `__gte`, `__lt`, `__lte` and `__gt` on the declared `lookup`. For a date on a datetime column the
bounds are timezone-aware UTC datetimes. With `stored_as: "date"` they are plain dates (a day stands for its 00:00 UTC).

The `lookup` may name an **annotation** the module added to its queryset, such as a count of pending actions, as long as the module applies
the annotation before it filters. Core never sees the queryset.

`matches` reads a date row value that is a datetime (naive counts as UTC), a date (its UTC midnight), an ISO string, or an int, float or
Decimal (Unix seconds). It reads a number row value that is an int, float, Decimal or numeric text. A bool is no value.

### Who sees the values

Date and number values are not scope-limited, so a reader who is not the owner sees them. Core still checks each one against the reader's
own declaration and withholds anything that does not validate (fail closed).

## Declaring fields

The module returns a list of declarations. Core checks each one and drops a bad one with a log line.

```python
{
    "id": "operating_system",            # lowercase slug, up to 64 characters
    "label": "Operating system",         # up to 80 characters
    "kind": "text",                      # text | id | bool | date | number
    "lookup": "operating_system",        # the Django field path, for build_q
    "row_key": "operating_system",       # the dict key, for matches (a list that is not a model)
    "name_lookup": "site__client__name", # kind "id" only: the display name path
    "name_key": "client_name",           # kind "id" only
    "scope_kind": "client",              # kind "id" only, optional (1.17.51): client | site
    "stored_as": "datetime",             # kind "date" only, optional (1.17.52): datetime (default) | date
    "integer": True,                     # kind "number" only, optional (1.17.52): refuses a decimal
    "minimum": 0, "maximum": 100000,     # kind "number" only, optional (1.17.52): finite, minimum <= maximum
    "values": {"source": "distinct"},    # distinct | static | none
}
```

- A field needs a `lookup`, a `row_key`, or both.
- `values.source` says where the Equals picker gets its values. `distinct` asks the provider (see below). `static` carries up to 50
  `{value, label}` options in the declaration. `none` gives a plain box. A `bool` field always uses `none`.
- A `lookup` is a plain model field path. It is never a lookup suffix, and it never comes from the browser.
- `scope_kind` (1.17.51, optional, `id` fields only) says the id is a client or a site, so Core can keep an out-of-scope id out of a
  shared set (see "What a reader sees of a shared set's values"). Without it an id value is never shown to anyone but the owner.

- A `date` or `number` field takes `values.source` `none` only, and may not declare `name_lookup`, `name_key` or `scope_kind`. The date and
  number keys on the wrong kind drop the declaration with a log line. A rule outside a number field's `minimum` or `maximum` is refused.
- A provider on a Core older than 1.17.52 drops a date or number declaration with a log line. Set `requires.framework` to `>=1.17.52` before you declare one.

A worked example, the two fields Agents would declare:

```python
{"id": "last_seen", "label": "Last seen", "kind": "date", "stored_as": "datetime",
 "lookup": "last_seen", "row_key": "last_seen"},
{"id": "pending_actions", "label": "Pending actions", "kind": "number", "integer": True, "minimum": 0,
 "lookup": "pending_actions_count", "row_key": "pending_actions_count"},
```

`pending_actions_count` is an annotation, for example `Count("pendingactions", filter=Q(status="pending"))`, added to the role-scoped queryset
before `build_q` runs.

**The browser never sees a lookup or a key.** `GET /api/tfd/filter-sets/fields/?module=<id>` returns only `id`, `label`, `kind`, the
operators and the value source (plus static options). A date or number field also carries `constraints` (`stored_as`; or `integer`,
`minimum`, `maximum`). The answer's `operators` key stays the six; `date_operators`, `number_operators` and `relative_units` are new.

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
| A date value | `YYYY-MM-DD`, a real date from 1970-01-01 to 2100-12-31 |
| A `between` value | an object with exactly `from` and `to`, `from` not after `to` |
| A relative amount | a whole number, 1 to 525600 minutes, 8760 hours or 3650 days |
| A number value | an int or finite float, at most 10**15 in size, inside the field's `minimum` and `maximum` |

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
| `definition` | `{version, match, rules}` as above. For a reader who is not the owner a rule value that is not theirs to see is `null` with `withheld: true` (1.17.51) |
| `values_withheld` | How many rule values were withheld from this reader (0 for the owner), since 1.17.51 |
| `shared`, `mine`, `can_edit`, `owner` | As for saved views |
| `readers` | User ids, returned to the owner only |

Rules:

- `readers` empty means shared with everyone who can use the module. A list of ids makes it private to the owner and those people.
- **Only the owner edits, shares or deletes.** There is no administrator override. Another person can use the set or save their own copy.
- A person who cannot read a private set gets "not found", so its existence does not leak.
- At most 100 sets per owner, module and view key.
- A set is stored on the saved views table (no new table, no migration) under the view key `fs-` + your key. Saved views refuse the
  prefix `fs-`, never list those rows and never change them.

### What a reader sees of a shared set's values (Core 1.17.51)

A rule value can name a client or a site. A person who can use the module but cannot see client B must not learn that name from a set
someone shared. From 1.17.51 Core checks every rule value before it shows it to anyone but the owner.

- **The owner always sees the full definition.** Nothing changes for the owner, and `resolve_filter_set`, `build_q` and `matches` are
  unchanged, so evaluating a set never leaks a value.
- **Everyone else sees each value only when Core can prove it is theirs to see.** A value that cannot be shown is withheld with a plain
  marker: the rule comes back as `{kind: "rule", field, operator, value: null, withheld: true}`. The set also carries a top-level
  `values_withheld` count (0 when nothing is withheld). The definition keeps its shape, so a reader cannot copy a hidden value.
- **Rules by field kind**, using the module's own declared fields:
  - An `id` field with the optional declaration key `scope_kind` (`"client"` or `"site"`). For Equals and Does not equal the id is shown
    when the reader is unrestricted, or the id is in the reader's `whole_client_ids` (client) or `site_ids` (site), or the Resource
    Directory finds that client or site in the reader's scope. Any failure, including a missing List clients or List sites flag, withholds
    the value. For the four name operators (contains, starts with and so on) the text is shown only when a client or site the reader may see
    has a name that contains it. Otherwise it is withheld.
  - An `id` field **with no `scope_kind`** is always withheld from everyone but the owner, because Core cannot prove its scope. If your
    module offers a client or site field, declare `scope_kind`.
  - `text` and `bool` values are shown as before. A text value such as an operating system is not a scope-limited value.
  - Fail closed: a rule on a field the reader does not know, or a value that is not text, a whole number or a bool, is withheld.
- **The set's name is a label its owner typed and stays visible.** Do not put a client's name in a set name you share. The browser
  should warn next to the Shared switch. That is a UI request.
- **Where the module's fields come from.** Core calls no provider from Python. `list_filter_sets(user, module_id, view_key, *, fields=None)`
  and `get_filter_set(user, set_id, *, fields=None)` take the module's own fields. With no `fields`, every value of a set the person does
  not own is withheld. The two GET routes read the signed-in person's fields from the module's provider, but only when a set the person
  can read but does not own has rules. If the provider is missing or fails, the GET still answers, with every such value withheld.
- Core looks each id or name up once per call and does at most 200 lookups. Past that, the remaining values are withheld.

### Rule values and the old wording

Before 1.17.51 a shared set showed every value to everyone it was shared with (1.17.50). That is replaced by the rules above.

### Declaring `scope_kind`

`scope_kind` is an optional key on a field declaration of kind `id`: `"client"` or `"site"`. It is additive on `<module id>.filter_fields`
1.0.0, so no module needs to change, and a declaration without it works as before (its values are simply never shown to a non-owner). The
browser never sees it. Any other value, or the key on a field that is not an `id` field, drops that declaration with a log line.

### Saved views that start with `fs-` from before 1.17.50

A saved view made before 1.17.50 whose key starts with `fs-` was hidden from saved views when Core reserved that prefix. From 1.17.51 Core
treats a row under `fs-` as a filter set only when its payload has the shape Core writes (`kind` `filter_set`, `version` the whole number 1,
`match` `all` or `any`, and a list of `rules`). Any other `fs-` row is not found: not listed, read, changed, deleted or resolved.

`install.sh` runs `tec_tac.filter_sets.repair_stray_saved_views()` after the migrations. It gives each such row the key `fs_` + the rest
(the same length, a valid saved view key), so the person's own old saved view returns to their saved views list under the new key. It never
deletes. When the new key would clash with the owner's unique (module, key, name), the row is left as it is and counted. The step returns
`{'renamed': n, 'skipped': m}`, logs both numbers, is safe to run again, and only warns if it fails. No migration is involved.

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
filter_sets.build_q(tree, fields, *, now=None)
filter_sets.matches(tree, row, fields, *, now=None)
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

## Browser editor

Core UI 0.12.116 gives every module a shared filter editor, `context.components.FilterEditor`, bound to the module's own id. It needs Core 1.17.50 (`core.filter_sets` 1.0.0); its date and number controls need UI 0.12.117 and Core 1.17.52 (`core.filter_sets` 1.1.0). Core lists it as a member of the browser contract row `ui.authenticated.components` (since 1.17.53). That row is documentation: it adds no route and no capability. Core still validates every definition and every saved set, whatever the editor sends. The editor's own guide is `tec-tac-ui/docs/module-filters.md`.

## Not in this release

- A time of day in a date rule. Dates are whole UTC days. A person's own time zone is not used.
- Text-to-number or text-to-date conversion of a rule value. The validator refuses numeric text and a date with a time.
- A timeout Core can enforce on a provider. Core has no thread or timer for it. The contract limits a provider to one indexed query of
  at most `page_size + 1` rows, and the 502 path covers failure.
- Export of a filter set.
- A dedicated table. Sets live on the saved views table until a later release can generate and check a migration.
