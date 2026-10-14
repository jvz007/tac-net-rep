# Module user preferences (core.module_preferences 1.1.0)

Core 1.17.35 adds one per-person choice a module can keep through Core. Core 1.17.37 makes the Python functions verify the calling module
(capability 1.1.0, see "Python contract" below). The first use is the collapse control of a window (Remote
Background's header and tabs), which Johan asked to be remembered per person. Browser storage is refused for UI modules, so the
choice cannot live in the browser.

## What it is

A preference belongs to one person, one module id and one name. It holds one JSON value: a scalar, a list or an object.

- Table `TecTacModulePreference`: user (cascade on account delete), `module_id`, `name`, `value` (JSON) and `updated_at`. One row per
  person, module and name (unique). Migration `0031_module_preferences` adds the table and nothing else.
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
- A module that is removed later keeps its rows. They do no harm, and they go with the person when the account is deleted. A module
  that is installed again finds its choice back.

## Python contract (`tec_tac.module_preferences`)

```python
from tec_tac.module_preferences import get, set as set_preference, delete, list_for

value = get(request.user, "header-collapsed", module_id="remote-background", default=False)
set_preference(request.user, "header-collapsed", True, module_id="remote-background")
delete(request.user, "header-collapsed", module_id="remote-background")   # True when a row was removed
prefs = list_for(request.user, module_id="remote-background")              # {name: value}, sorted by name
```

A refusal raises `ModulePreferenceError` with `code` (`caller_not_allowed`, `invalid_name`, `invalid_value`, `module_not_found`,
`preference_limit`, `signed_in_required`) and `status_code` (403 for `caller_not_allowed`). A module uses it only when `requires.framework`
is `>=1.17.37` and the capability `core.module_preferences` is present (`has_capability`).

**The calling module is verified (AD-26, Core 1.17.37).** Each of the four functions asks Core who is calling, the same way Core checks
`core.accounts` (AD-31). A call may read or write only the preferences of the module it names in `module_id`. Any other caller is refused
with `caller_not_allowed` (403) before the name, the value or any row is looked at, so nothing is read or written. Core is never a caller:
a call from a Core, library or generated frame, from a disabled or legacy module, or from code outside every module is refused too.
Enabled state is read on every call. A module that calls the functions for another module's id is refused, even when that id is installed.

**The `user` argument stays the caller's responsibility.** A module could pass any user for its own module id. It can never reach
another module's rows, because the module id is checked against the caller.

**Known limit (AD-26 condition 4).** The check reads the call stack. A module whose code is deliberately hostile, running in the same
process, could forge its way past it; signed-module review is the defence against that. The private functions (`_get`, `_set`,
`_delete`, `_list_for`) are not part of the contract and no module may import them.

## The browser contract row

The UI row `ui.authenticated.modulePreferences` (UI 0.12.106) lists `get`, `getAll`, `set` and `remove`. The shell binds the module id to
the calling module, so a module cannot name another id through the helper. It needs Core 1.17.35 or later. The shell's helper is a separate
contract from the Python functions above.

## HTTP (browser)

| Method and path | Body | Answer |
| --- | --- | --- |
| `GET /api/tfd/module-preferences/<module_id>/` | none | `{module_id, preferences: {name: value}}` |
| `PUT /api/tfd/module-preferences/<module_id>/<name>/` | exactly `{"value": ...}` | `{module_id, name, value}` |
| `DELETE /api/tfd/module-preferences/<module_id>/<name>/` | none | `{module_id, name, deleted}` |

Refusals are `{detail, code}`: 400 `invalid_name`, 400 `invalid_value`, 400 `preference_limit`, 401 (not signed in), 404
`module_not_found`, and 429 when the write throttle is reached. Every route needs a signed-in Tec-Tac session (`SessionAuthenticated`).

**Browser caveat, stated plainly.** The browser cannot prove which module is calling, so the `module_id` in the path is a claim. The
route is not verified by the caller check above; the views call the private functions with the path id. The UI shell binds the id to the
module that asks. The result: one person can change only their own choice of a module, and no other person's row is reachable.

## Not audited

These routes write no audit row, the same as `/api/tfd/ui/preferences/`. The values are display choices, not security events.

## Versions

- Capability `core.module_preferences` 1.1.0 (1.0.0 in Core 1.17.35), registered at start-up by Core (guarded: a failure is logged and
  never stops start-up). 1.1.0 is the verified-caller tightening of 1.17.37; nothing in `modules/` used the functions before it.
- Core 1.17.37 or later for the Python functions. A module that uses them must require `tec-tac-framework >=1.17.37`. The browser route
  and its contract row need Core 1.17.35 or later.
