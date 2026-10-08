# Core Runtime Settings

Core stores a small set of settings the browser shell reads at startup. There is one today.

## Module `register()` time limit

How long a module's `register()` may run before the UI marks the module failed and loads the next one.

```text
module_register_timeout_seconds   default 30   range 5 to 300 (whole seconds)
```

**The UI applies the limit. Modules do not.** Core only stores the value and publishes it. A module must not read the setting to change its own behaviour, and its `register()` must not assume more time than the setting allows.

### Where the UI reads it

`GET /api/tfd/ui/context/` has one new top-level key:

```json
{ "module_register_timeout_seconds": 30 }
```

It is an integer. The shell already fetches this context, so it needs no extra call. The key is additive. UI builds that do not know it ignore it, and existing modules are unaffected.

If the database cannot be read, Core returns the default (30). Startup never fails because of this setting.

### Who changes it

`GET /api/tfd/system/runtime-settings/` is open to any signed-in user.

```json
{
  "module_register_timeout_seconds": { "value": 30, "minimum": 5, "maximum": 300, "default": 30 },
  "updated_at": "2026-10-08T12:00:00+00:00",
  "updated_by": "alice"
}
```

`PATCH /api/tfd/system/runtime-settings/` changes it. The caller needs one of three things: an effective superuser, a role with the Core permission `core.runtime_settings.manage` (group "Runtime settings", added in 1.17.2), or a role with `core.privileged_operations` (kept, so 1.17.1 administrators lose nothing). Anyone else gets 403.

Any role manager can grant `core.runtime_settings.manage` in the role editor. Only a superuser can grant `core.privileged_operations`. Holding `core.runtime_settings.manage` does not allow staging or installing updates. That still needs `core.privileged_operations`.

Python: `tec_tac.rbac.can_manage_runtime_settings(user)` gives the same answer. It never raises.

```json
{ "module_register_timeout_seconds": 45 }
```

- The value must be a whole number from 5 to 300. A boolean, float, string or `null` gets 400, as does a value outside the range.
- Unknown fields get 400. Nothing is changed.
- A change writes one strict Core audit row (module `core`, object type `runtime_settings`, action `modify`) with the value before and after. It is written in the same transaction, so if the audit write fails the change is rolled back.
- Setting the value it already has changes nothing and writes no audit row.
- Writes are limited to 10 a minute and 200 a day for each user and IP. Reads are not counted.

Choose the value with care. A very low limit makes slow modules fail to load. A very high one lets a slow module hold up the shell. Until the Core UI has a settings control, an administrator changes the value through this API.

### Python

`tec_tac.runtime_settings.get_module_register_timeout_seconds()` returns the configured value. It never raises. It is informational: the UI applies the limit.

Storage is the `TecTacRuntimeConfig` singleton (migration `0022_runtime_config`).
