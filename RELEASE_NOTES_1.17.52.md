# Tec-Tac Framework 1.17.52

Date and number filters, names without values for audit lists, and a way for a create to name its own record in the audit row.

Filter sets can now filter on dates ("last seen in the last 7 days") and numbers ("more than 3 pending actions"). A task's script arguments and environment variables can
be recorded as names only. A create that checks a client's scope can still name the record it made. Nothing a module does today breaks: every change is additive and
opt-in, and a declaration or saved set that uses none of the new keys behaves exactly as in 1.17.51.

## Module-facing changes

- **`core.filter_sets` 1.0.0 -> 1.1.0 (additive, still major 1; the new parts need framework >=1.17.52).** The field kinds `date` and `number`, each with its own
  operators. Request: "From agents 0.13.0" (Johan, 17 October 2026).
  - **Operators.** `OPERATORS` is still the six Groups has always had (`equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`); the ids and labels
    did not change, and the route's `operators` key and `meta['operators']` are still those six. The new ids live in their own tables (`DATE_ONLY_OPERATORS`,
    `NUMBER_ONLY_OPERATORS`, all of them in `ALL_OPERATORS`). `operators_for('date')` gives `equals` ("Is"), `not_equals` ("Is not"), `before`, `after`,
    `on_or_before`, `on_or_after`, `between`, `in_the_last`, `not_in_the_last`. `operators_for('number')` gives `equals`, `not_equals`, `greater_than`, `less_than`,
    `at_least`, `at_most`, `between`. An unknown kind still raises. The capability metadata adds `all_operators`, `date_operators`, `number_operators`, `relative_units`,
    `date_range`, `number_limit`, `date_and_number_requires_framework` and the new limits. `requires_framework` stays `>=1.17.50` for the old parts.
  - **Values** (held in the rule's single `value`; no new rule keys). A date is a strict ASCII `YYYY-MM-DD` string, a real date from 1970-01-01 to 2100-12-31, whole days
    only. `between` is `{"from", "to"}`, both days included, `from` not after `to`. `in_the_last` and `not_in_the_last` are `{"amount", "unit"}`, unit `minutes`,
    `hours` or `days`, amount a whole number from 1 to 525600 minutes, 8760 hours or 3650 days. A number is a JSON int or a finite float (never a bool, text, NaN or
    infinity, and at most 10**15 in size). A number `between` is `{"from", "to"}`. A dict with any other key is refused, and so is an operator the kind does not offer.
  - **Declaration keys** (all optional, additive on `<module id>.filter_fields` 1.0.0, which stays 1.0.0). A date field takes `stored_as` (`"datetime"`, the default, or
    `"date"`). A number field takes `integer` (a bool; a decimal is refused), `minimum` and `maximum` (finite numbers, `minimum <= maximum`; a rule outside them is refused).
    A date or number field takes `values.source` `none` only and may not declare `name_lookup`, `name_key` or `scope_kind`. Each new key is refused on the wrong kind.
    The browser field entry gains an additive `constraints` object (`stored_as`, or `integer`, `minimum`, `maximum`), never a lookup or a key. The fields route answer adds
    `date_operators`, `number_operators` and `relative_units`.
  - **What a day means.** Days are UTC days (CQ154): `equals` is the whole day, from `D` 00:00 up to but not including `D+1` 00:00. `before` is earlier than `D` 00:00,
    `on_or_before` is earlier than `D+1`, `after` is `D+1` or later, `on_or_after` is `D` or later, `between` is `from` up to but not including `to+1`. `in_the_last` is
    now minus N up to now, both included, so a time in the future does not match. `not_in_the_last` is its exact opposite. The stored set keeps the relative form, so a
    saved "last 7 days" set stays live.
  - **A row with no value.** A NULL or unreadable value never satisfies a positive operator. It does satisfy `not_equals` and `not_in_the_last`. `build_q` (Django's `~Q`)
    and `matches` give the same answer.
  - **`build_q(tree, fields, *, now=None)` and `matches(tree, row, fields, *, now=None)`.** `now` is keyword only and defaults to the real clock; it is read once per call
    (a naive value counts as UTC). `build_q` emits only plain equality, `__gte`, `__lt`, `__lte` and `__gt` on the declared `lookup`. **A module may point `lookup` at an
    annotation it added to its queryset** (Agents' count of pending actions) as long as it applies the annotation before it filters. `matches` reads a date row value that
    is a datetime (naive counts as UTC), a date (its UTC midnight), an ISO string, or an int, float or Decimal (Unix seconds), and a number row value that is an int, float,
    Decimal or numeric text. A bool is no value.
  - **Sharing.** A reader who is not the owner sees valid date and number values (they are not scope-limited), including the dict forms and floats. Core checks each value
    against the reader's own declaration and withholds anything that does not validate. An `id` field with no `scope_kind` is still withheld.
  - **Adopting.** A module that declares a date or number field must require framework `>=1.17.52`: a Core older than that drops such a declaration with a log line. Agents
    adopts `last_seen` and the pending-actions count (request in `reviews/requests/core-modules.md`). The shared filter editor needs a date picker and a number input before
    any module declares one (request in `reviews/requests/ui.md`). Groups' `from_legacy_formula` and the six-operator formulas are untouched.
  - Details: `docs/filter-sets.md`, "Date and number fields".
- **`core.tactical_operations` 1.14.0 -> 1.15.0 (additive, still major 1, framework >=1.17.52).** Two optional additions. A declaration that uses neither behaves exactly as before.
  - **`audit_list_masks` (Python keyword, `{list name: {key: "names"|"mask"}}`).** Requests: "From tasks 0.10.1" and AD-39 (Johan, 17 October 2026: names first, `***` second).
    The list must already be in `audit_lists`, which keeps its signature and behaviour: a list with no mask is still recorded in clear. `names` records only the name of each text
    item (`KEY=VALUE` gives `KEY`, `--flag=value` gives `--flag`, `-Name value` gives `-Name`; a positional argument has no name and is `***`). `mask` keeps the name and shows
    `***` for the value (`KEY=***`, `--flag=***`, `-Name ***`; a scalar text key such as a cmd action's `command` is `***`). It covers both sides of the row, the cleaned body and
    Tactical's own before answer, and the unmasked text never reaches the row. A masked key whose value is not text or a list of scalars is `***`, `None` stays null, and
    `names` on a scalar key is `***`. The `audit_lists` bounds (50 entries, 24 keys, 100 items, 4096 characters, 64 KiB, `<name>_count`, `<name>_truncated`) apply after masking.
    **Core adds a shape check** so a secret is never recorded as a name: an item is a name only when it looks like one (letters, digits, `_`, `.`, `-`, up to 64 characters, with
    leading dashes or one leading `/` for a switch), and `KEY=` with an empty value, or a value that is only `=` (base64 padding), is `***` (CQ156). Registration refuses a list
    that is not in `audit_lists`, more than 8 keys per list, a key that is not a field name, a mode other than `names` or `mask`, and a mapping that is not a dict.
    `describe()` and `list_operations` show `audit.list_masks` (an empty object when none). The exported contract adds `declaration_keys_added_in_1_15_0`, the rule text and
    `limits_added_in_1_15_0`.
  - **Scope `names_object: false`** (a strict bool, default true). Request: "from reportmanager 0.6.2 round 3". The entry is resolved and checked exactly as before (the scope
    check, the deny rows and the 400s are unchanged, and a scope deny row still names the entry it denied), but it does not name the object of the success, failed, Tactical-denied
    and outcome-unknown rows. A create that checks `body:dependencies.client` can then have `audit.object_field` or `audit.object_body_field` name the created record.
    Registration refuses a non-bool, and a scope whose entries are all `names_object: false` unless the declaration has `audit.object_param`, `audit.object_field`,
    `audit.object_body_field` or `audit.object_id`. `describe()` shows `names_object: false` only when false. **Not built:** making `audit.object_field` win over every scope
    object (CQ157), because that would change the rows of declarations that exist today. The request stays open for that half only if Johan wants it.
  - **Adopting.** Tasks passes `audit_list_masks` (add it to the `extra` keys in `apps.py`) with `audit_lists: ["actions"]` on create, create-policy-task, edit and delete, and requires
    framework `>=1.17.52`. Report Manager declares the dependency scope on `schedule-add` with `names_object: false`. Both are requests in `reviews/requests/core-modules.md`. The
    AD-32 and AD-39 exception for task action content ends only when a signed Tasks release uses the masks.
  - Details: `docs/tactical-operations.md`, "Added in 1.17.52".
- **Contract rows.** `operators_for`, `validate_filter_set`, `build_q`, `matches`, the provider shape, the `GET /api/tfd/filter-sets/fields/` row and the Tactical operations row
  say what is new. The public contract in `docs/contracts` cannot be regenerated on this PC: export a fresh one after installing 1.17.52 (it must list `core.filter_sets` 1.1.0 and
  `core.tactical_operations` 1.15.0).

## What changed and why

### Date and number filters (request "From agents 0.13.0")

Agents 0.13.0 could only offer text operators, so "last seen" and the pending-actions count were left out rather than offered in a reduced form. Core now has the kinds and the
operators. The dates are whole UTC days because that is deterministic and testable, and the stored set never changes meaning. The six text operators did not move, so every set
and test that pins them still passes.

### Names without values in the audit row (request "From tasks 0.10.1")

Tactical records a whole task, arguments and environment values included. Johan's order was names first and `***` second. Core cannot tell a secret from a harmless value, so the
masks are explicit, opt-in and per key, and a masked key never reaches the row in clear on either side.

### A create that names its own record (request "from reportmanager 0.6.2 round 3")

A create that checks a client's scope named the client on its row, so the created record could not be named. The flag keeps the check and moves the naming.

### Tests-only fix that ships with this release

Commit 90ab025 (tests only) strips the `-N` retry suffix before four tests parse the version. It was made after 1.17.51 was signed, so it is not in the signed 1.17.51 tree and ships
here.

## Tests

New: `tests/filter-sets-date-number-1.17.52.py`, `tests/tactical-operation-audit-list-masks-1.17.52.py`, `tests/tactical-operation-names-object-1.17.52.py`.

Changed (pins moved, no behaviour assertion weakened): the capability pins in the tactical-operation tests moved from 1.14.0 to 1.15.0; `tests/filter-sets-1.17.50.py` and
`tests/filter-sets-scope-1.17.51.py` (the capability is 1.1.0; `operators_for('money')` is the unknown kind now that `number` is valid; the note for "Number and date ranges" is gone
because the docs now describe them); `tests/tactical-operations-object-field-1.17.21.py` (the whole `audit` block now carries `list_masks`); `tests/filter_sets_boundary_1_17_50.py`
(the recording Q compares with `__gte`, `__lt`, `__lte` and `__gt`); two 1.17.51 tests read the 1.17.51 notes from `docs/releases/`, where they moved.

## What could not run here

Django, DRF, Redis and Celery are not installed on this PC. The filter-set tests run through the in-memory boundary of `tests/filter_sets_boundary_1_17_50.py` with a recording `Q`, and
the Tactical operation tests run on the stubs of `tests/tactical-operations-1.17.7.py`. Two things only run on a real server: Django's `~Q` keeping rows with a NULL (the tests model
it), and a queryset annotation used as a `lookup` (Agents' pending-actions count).

## Requests closed or answered

- Closed: "From agents 0.13.0" (date and number operators, the Core half), "From tasks 0.10.1" (names without values, the Core half) and "from reportmanager 0.6.2 round 3" (the opt-in
  flag; the other half is not built).
- Questions recorded with their assumptions in `reviews/questions/core.md`: CQ154 to CQ157.
- Left for a later release: a correlation id for bulk actions on the browser route (CQ151), Core enforcement of "only a SuperAdmin may invite" (CQ152), and the text-value rule for shared
  filter sets (Johan's call).
