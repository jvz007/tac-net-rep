# Module user preferences (core.module_preferences 1.2.0)

Core 1.17.35 adds one per-person choice a module can keep through Core. Core 1.17.37 makes the Python functions verify the calling module.
Core 1.17.38 audits every real change, checks that the person may use the module, and lists what Core can and cannot prove about the
module id (capability 1.2.0, see "Versions" below). The first use is the collapse control of a window (Remote Background's header and
tabs), which Johan asked to be remembered per person. Browser storage is refused for UI modules, so the choice cannot live in the browser.

## What it is

A preference belongs to one person, one module id and one name. It holds one JSON value: a scalar, a list or an object.

- Table `TecTacModulePreference`: user (cascade on account delete), `module_id`, `name`, `value` (JSON) and `updated_at`. One row per
  person, module and name (unique). Migration `0031_module_preferences` adds the table and nothing else. Core 1.17.38 adds no migration.
- It is a separate table, not the reserved `extensions` object of `/api/tfd/ui/preferences/`. That document is replaced as a whole on
  every PUT, so a stale browser tab would overwrite a module's choice. See `user-preferences.md`.

## Limits

| Limit | Value |
| --- | --- |
| Name | `[a-z0-9][a-z0-9._-]{0,63}` (a lower-case letter or digit first, then letters, digits, `.`, `_` or `-`) |
| Value | a JSON scalar, list or object, at most 4 KiB when stored (`json` text, UTF-8) and at most 5 levels deep |
| Names per person and module | 50. The 51st is refused with `preference_limit` |
| Writes | 120 changes (PUT or DELETE) a minute per person. Reads are not throttled |

A value nested six levels deep, a value over 4 KiB, a value that is not plain JSON, or a name that does not match is refused. Nothing is
written when a value is refused.

## What may be stored

Only the person's own display choice, such as a collapsed header or a sort order. **No secret, token, password, key or personal data may
be stored.** Core does not check the content; this is a rule for module authors, and it is stated in the contract.

## Who may read and write

- Only the signed-in person. A row of another person is never read or changed by these routes or functions.
- The module id must be an installed, enabled extension. `core` and `tec-tac` are refused (`module_not_found`, 404), and so is an
  unknown or disabled module. The check is the same one `notices.publish` uses.
- **The person may use the module (since 1.17.38).** The person needs the same access as saved views use: a superuser or a role
  superuser may use any module; a module with no permission groups is open to every signed-in person; any other person needs one of the
  module's permissions. A person without that access gets `module_not_allowed` (403) before any row is read or written.
- A module that is removed later keeps its rows. They do no harm, and they go with the person when the account is deleted. A module
  that is installed again finds its choice back.

The order of the checks, for the browser routes and the Python functions alike: signed in (401), the module is installed and enabled
(404), the person may use it (403), then the name, the value and the limit (400).

## Audit (since 1.17.38)

Each real change writes one strict Core audit row, in the same database transaction as the save. The rule is AD-19 condition 5, and the
row is written the way saved views write theirs (AD-26 and AD-31 condition 2 are the model for the verified caller).

| Field | What it holds |
| --- | --- |
| action | `add` (a new name), `modify` (an existing name with a different value) or `delete` |
| object type | `module_preference` |
| object id | `<module_id>/<name>`, for example `windows-patching/sidebar.collapsed` |
| actor | the signed-in person (the username) |
| message | `Tec-Tac module preference add.`, `... modify.` or `... delete.` |
| metadata | `module` (the module id), `name`, `source`, `module_verified`, `user_id`, and `size_bytes` (add and modify only) |

- **`source`** is `module_python` when the Python functions ran (Core verified the calling module, AD-26), or `browser` when the browser
  route ran (the browser named the module id).
- **`module_verified`** is `true` only for `module_python`. For `browser` it is `false`: the browser's module id is a claim, recorded as a
  claim.
- **`size_bytes`** is the size of the stored value as UTF-8 text. It is the size only.
- The row is written under `module_id` `core`, so the person does not need the module's permissions for the row to be written.

**The row never holds the value.** Neither the value nor any part of it appears in the row's before or after, its message or its
metadata. A delete row holds nothing about the value.

**What is not audited.** A read (`get`, `list_for`, the GET route) writes no row. A write that changes nothing (the same value as the one
stored, so `true` and `1` are different values, and `1` and `1.0` are different too) writes no row and no database update. A delete of a
name that does not exist writes no row. A refused call writes no preference row and no deny row.

**If the row cannot be written.** The change is rolled back and the answer is `audit_failed` (503), so no change is kept without its audit
row. A display toggle therefore fails while the audit store is down. The release notes say so.

Retention of these rows is the audit log's own: they are kept as long as Tactical's audit retention keeps audit rows. Core does not set that
period in this release.

## Python contract (`tec_tac.module_preferences`)

```python
from tec_tac.module_preferences import get, set as set_preference, delete, list_for

value = get(request.user, "header-collapsed", module_id="remote-background", default=False)
set_preference(request.user, "header-collapsed", True, module_id="remote-background")
delete(request.user, "header-collapsed", module_id="remote-background")   # True when a row was removed
prefs = list_for(request.user, module_id="remote-background")              # {name: value}, sorted by name
```

A refusal raises `ModulePreferenceError` with `code` and `status_code`:

| code | status | when |
| --- | --- | --- |
| `caller_not_allowed` | 403 | the calling module is not the module named in `module_id` (Python functions only) |
| `signed_in_required` | 401 | the person is not signed in |
| `module_not_found` | 404 | the module is not installed and enabled, is legacy, or is `core` or `tec-tac` |
| `module_not_allowed` | 403 | the person may not use the module (since 1.17.38) |
| `invalid_name` | 400 | the name does not match the pattern |
| `invalid_value` | 400 | the value is not plain JSON, is over 4 KiB or nests over 5 levels |
| `preference_limit` | 400 | a 51st name for the module |
| `audit_failed` | 503 | the audit row could not be written; the change was rolled back (since 1.17.38) |

A module uses it only when `requires.framework` is `>=1.17.38` and the capability `core.module_preferences` is present (`has_capability`).

**The calling module is verified (AD-26, Core 1.17.37).** Each of the four functions asks Core who is calling, the same way Core checks
`core.accounts` (AD-31). A call may read or write only the preferences of the module it names in `module_id`. Any other caller is refused
with `caller_not_allowed` (403) before the name, the value or any row is looked at, so nothing is read or written. Core is never a caller:
a call from a Core, library or generated frame, from a disabled or legacy module, or from code outside every module is refused too.
Enabled state is read on every call. A module that calls the functions for another module's id is refused, even when that id is installed.

**The `user` argument stays the caller's responsibility.** A module could pass any user for its own module id. Since 1.17.38 it cannot
write for a person who may not use that module, and it can never reach another module's rows, because the module id is checked against
the caller.

**Known limit (AD-26 condition 4).** The check reads the call stack. A module whose code is deliberately hostile, running in the same
process, could forge its way past it; signed-module review is the defence against that. The private functions (`_get`, `_set`,
`_delete`, `_list_for`) are not part of the contract and no module may import them.

## What Core can and cannot prove about the module id

Core 1.17.38 states this plainly, for the browser route and the Python functions.

**Core can prove:**

- who the person is: the signed-in session, and the row is always the person's own;
- that the module is installed and enabled, on every call;
- that the person may use that module (`module_not_allowed` otherwise);
- that a row can only ever belong to that person and that module id pair.

**Core cannot prove:**

- that a browser request came from that module's page. The browser writes the module id into the web address, so the id is a claim.
  Any signed-in person who may use module A can therefore write module A's own preference rows for themselves through the browser, and
  nothing more: no other person's row, and no row of a module they may not use. The audit row records this as `source` `browser` and
  `module_verified` `false`, as a claim and not as a fact.
- that a Python call is honest about the `user` argument. The Python path verifies the calling module (AD-26), not the person.

No browser trust claim is made. There is no header and no token, and no claim that the browser is verified. The UI shell's own binding of the id to the
calling module stays a statement of the UI (`ui.authenticated.modulePreferences`).

## The browser contract row

The UI row `ui.authenticated.modulePreferences` (UI 0.12.106) lists `get`, `getAll`, `set` and `remove`. The shell binds the module id to
the calling module, so a module cannot name another id through the helper. It needs Core 1.17.35 or later. Since Core 1.17.38 the helper
can also get `module_not_allowed` (403) and `audit_failed` (503). The shell's helper is a separate contract from the Python functions above.

Since UI 0.12.109 the helper gives each call in one 400 ms window the result of its own type. The last operation in the window decides it:
- Last operation `set()`: every `set()` resolves the value Core stored, and every `remove()` resolves `false`.
- Last operation `remove()`: every `remove()` resolves `true` or `false` as Core answered, and every `set()` resolves `undefined`.

Every merged call gets the same rejection when the write fails. Nothing else about the row changed: the 400 ms window, the 2 seconds limit and `flush()` stay.

## HTTP (browser)

| Method and path | Body | Answer |
| --- | --- | --- |
| `GET /api/tfd/module-preferences/<module_id>/` | none | `{module_id, preferences: {name: value}}` |
| `PUT /api/tfd/module-preferences/<module_id>/<name>/` | exactly `{"value": ...}` | `{module_id, name, value}` |
| `DELETE /api/tfd/module-preferences/<module_id>/<name>/` | none | `{module_id, name, deleted}` |

Refusals are `{detail, code}`: 400 `invalid_name`, 400 `invalid_value`, 400 `preference_limit`, 401 (not signed in), 403
`module_not_allowed` (since 1.17.38), 404 `module_not_found`, 429 when the write throttle is reached, and 503 `audit_failed` (since
1.17.38, the change was not saved). Every route needs a signed-in Tec-Tac session (`SessionAuthenticated`).

**Browser caveat.** The module id in the path is a claim, as described above. The views call the private functions with the path id.
The UI shell binds the id to the module that asks. The result: one person can change only their own choice of a module they may use, and
no other person's row is reachable.

## Versions

- Capability `core.module_preferences` 1.2.0 (Core 1.17.38). Before it: 1.1.0 (Core 1.17.37, the verified caller), 1.0.0 (Core 1.17.35).
  It is registered at start-up by Core (guarded: a failure is logged and never stops start-up).
- 1.2.0 is additive: the same functions, arguments and results. New for a module: (a) a write or delete writes an audit row, (b) the
  refusals `module_not_allowed` (403) and `audit_failed` (503), and (c) a write that changes nothing writes nothing. Nothing in `modules/`
  used the functions before 1.2.0.
- A module that uses the functions must require `tec-tac-framework >=1.17.38`. The browser route and its contract row need Core 1.17.35 or
  later; its audit and refusals need Core 1.17.38.
- Decision AD-36 (the verified caller recorded as an accepted decision) is not recorded here. Johan has not signed it off. The rules in this
  document cite AD-26, AD-31 condition 2 and AD-19 condition 5 instead.
