# Core Runtime Settings

Core stores a small set of settings. Three today: the module `register()` time limit, which the browser shell reads at startup, (1.17.14) the Tactical operation upload limit, which Core's own executor reads, and (1.17.23) the system name an authenticator app shows.

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
  "tactical_operation_upload_max_mib": { "value": 10, "minimum": 1, "maximum": 25, "default": 10, "bytes": 10485760 },
  "updated_at": "2026-10-08T12:00:00+00:00",
  "updated_by": "alice"
}
```

`PATCH /api/tfd/system/runtime-settings/` changes it. The caller needs one of three things: an effective superuser, a role with the Core permission `core.runtime_settings.manage` (group "Runtime settings", added in 1.17.2), or a role with `core.privileged_operations` (kept, so 1.17.1 administrators lose nothing). Anyone else gets 403.

Any role manager can grant `core.runtime_settings.manage` in the role editor. Only a superuser can grant `core.privileged_operations`. `core.runtime_settings.manage` covers runtime settings only. It no longer covers the update source, which only a superuser can change (1.17.5). It does not allow staging or installing updates either. That still needs `core.privileged_operations`.

Python: `tec_tac.rbac.can_manage_runtime_settings(user)` gives the same answer. It never raises.

```json
{ "module_register_timeout_seconds": 45 }
```

- The value must be a whole number from 5 to 300. A boolean, float, string or `null` gets 400, as does a value outside the range.
- Unknown fields get 400. Nothing is changed. Since 1.17.14 an empty body is a 400 too, and the answer names both settings.
- A change writes one strict Core audit row (module `core`, object type `runtime_settings`, action `modify`) with the value before and after. It is written in the same transaction, so if the audit write fails the change is rolled back. Since 1.17.14 each changed setting writes its own row, and `object_id` is the setting's name.
- Setting the value it already has changes nothing and writes no audit row.
- Writes are limited to 10 a minute and 200 a day for each user and IP. Reads are not counted.

Choose the value with care. A very low limit makes slow modules fail to load. A very high one lets a slow module hold up the shell. Until the Core UI has a settings control, an administrator changes the value through this API.

### Python

`tec_tac.runtime_settings.get_module_register_timeout_seconds()` returns the configured value. It never raises. It is informational: the UI applies the limit.

## Tactical operation upload limit (1.17.14)

The largest file one Tactical operation may forward through Core (`docs/tactical-operations.md`, "One file: `upload`").

```text
tactical_operation_upload_max_mib   default 10   range 1 to 25 (whole MiB)
```

- `GET` returns `{value, minimum, maximum, default, bytes}`. The setting lives on the runtime configuration row (migration 0026). A row that existed before 1.17.14 reads as 10.
- `PATCH` accepts `module_register_timeout_seconds`, `tactical_operation_upload_max_mib`, or both. A body with only the old key behaves exactly as before.
- The value is validated like the timeout: a whole number only. A boolean, float, string or `null` gets 400, as does a value outside 1 to 25.
- **Only a superuser may change it**, the same rule as the update source. A caller who holds `core.runtime_settings.manage` can still change the timeout, but gets 403 for this key. The check runs before the value is read, so a caller without the right never sees 400. If a body carries both keys and the caller is not a superuser, nothing is changed.
- Each changed setting writes its own strict audit row in the same transaction. Sending a value the setting already has writes nothing.
- The executor reads the setting on every call. A lowered limit takes effect at once, with no restart. An operation's own lower cap still wins.
- A module can never declare a cap above 25 MiB. Registration cannot read the database, so it checks that fixed limit.
- A body limit in the web server or in Tactical still applies in front of Core. This setting does not change either.

Python: `tec_tac.runtime_settings.get_tactical_upload_max_bytes()` returns the effective ceiling in bytes. It never raises and falls back to 10 MiB. It is informational: Core applies it.

Storage is the `TecTacRuntimeConfig` singleton (migration `0022_runtime_config`).

## System name (1.17.23)

The name an authenticator app (Google Authenticator, Microsoft Authenticator and the like) shows beside the account when a person sets up two-factor sign-in. Before 1.17.23 it showed the server address. Now it shows this name.

```text
system_name   default "Tec-Tac"   1 to 60 characters, no colon
```

- It is plain text. Core trims it, normalises it (NFC) and refuses a control character, a zero-width or other invisible character, and a colon. A colon separates the name from the account in an authenticator label, so Core refuses it with a 400 and never stores a changed version.
- `PATCH /api/tfd/system/runtime-settings/` with `{ "system_name": "Acme IT" }` changes it. JSON `null` resets it to `Tec-Tac`. **Only an effective superuser may change it (1.17.24).** Before that, a role with `core.runtime_settings.manage` could too. Such a caller still changes the register time limit, but gets 403 for this key, checked before the value, so a refused caller never sees 400. A body that mixes the name with another setting is refused whole: nothing is saved. A refusal writes one best-effort Core audit row (action `deny`, `object_id` `system_name`, reason `superuser_required`, never the value). The upload-limit refusal writes the same kind of row. Reading the name stays open to every signed-in user.
- Each change writes its own strict audit row (`object_id` `system_name`, the name before and after). The name is not a secret. A value sent unchanged writes no row.
- Read: `GET /api/tfd/system/runtime-settings/` carries `system_name` as `{ value, maximum_length, default }`, and `GET /api/tfd/ui/context/` carries `system_name` as a string. Both are additive. No unauthenticated read exists, so the sign-in set-up screen uses the `issuer` of the enrollment answer, which Core builds.
- Existing authenticator entries keep working. The secret does not change, so only a new set-up (first sign-in, or after "Reset my own two-factor") carries the new label.
- Python: `tec_tac.runtime_settings.get_system_name()` never raises and falls back to `Tec-Tac`.

## Private mail relay for Core's own Priority 1 email (1.17.26, AD-30)

```text
priority_mail_private_relay   default false   true or false
```

Core emails the Tec-Tac administrators when a module job fails (the Priority 1 email). It sends through Tactical's own mail sender. Before it sends, Core checks where the mail server's name points, and by default it accepts public addresses only. Some servers use a relay on the private network. Turn this on to let Core's own Priority 1 email use one.

- On, Core's own call accepts a name that resolves to ordinary private-network addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7. Every address is judged on its own, so a name with one bad address is refused.
- Still refused with it on: cloud metadata addresses, loopback (127.0.0.1 and ::1, a mail server on this server itself), link-local, unspecified and multicast addresses, other reserved ranges, and a name that does not resolve. Loopback stays refused until Johan answers CQ82.
- Nothing else changes. The recipients are the administrators only, the cap is 20 an hour, Core reads no SMTP password and has no SMTP client, and a refusal never falls back to another sender.
- **Core's own call only.** A module that reaches `send_p1_email`, `sweep_failed_jobs` or `host_refusal` gets the public-only rule, with one warning logged, never the private path. So does a call that passes its own host or send function. Core tells by the call stack: a frame inside an installed module's folder means a module is calling. A stack it cannot read counts as a module.
- Only an effective superuser may change it. A holder of `core.runtime_settings.manage` who is not a superuser gets 403 and one best-effort Core `deny` row (`object_id` `priority_mail_private_relay`, no value). The check runs before the value. A body that mixes it with another setting is refused whole. A value that is not true or false (a number, text, a list or null) is a 400.
- Each change writes one strict audit row in the same transaction (`runtime_settings`, `modify`, the boolean before and after). Sending the current value writes no row.
- The Priority 1 audit row (`custom:priority-mail`) carries `private_relay`: true only when the relaxed rule accepted the mail server. It stays count-only.
- Read: `GET /api/tfd/system/runtime-settings/` carries `priority_mail_private_relay` as `{ value, default, warning }`. Existing installs read false.
- Python: `tec_tac.runtime_settings.get_priority_mail_private_relay()` is for Core's own code. It never raises and reads any error or odd stored value as false. It is not in the public Python contract, so no module can read it.
- Tests: `tests/priority-mail-private-relay-1.17.26.py`, `tests/runtime-settings-private-relay-1.17.26.py`, `tests/caller-identity-server-module-1.17.26.py`. The migration (0029) and the real setting row are checked by `tests/priority-mail-runtime-1.17.26.py` on the dev server.
