# Tec-Tac Framework 1.17.5

This release does four things. Only a superuser can change the update source. The installer no longer rolls back a healthy Core when Report Manager reports unhealthy. The reporting fallback now serves registrations that were already forwarded. And the held-findings list is brought up to date.

Closes: the held 1.17.2 Medium (update source rights), the held 1.17.4 Medium (installer rollback) and the held 1.17.4 Low (fallback drops forwarded registrations). The held 1.17.2 Low (stage route default missing from the contract catalog) was already closed in 1.17.3.

## Update source: superusers only (CQ12)

Johan decided on 9 October 2026 that only a superuser changes where Core updates from.

- `PATCH /api/tfd/system/update-source/` now returns 403 for everyone except an effective superuser (Django `is_superuser`, or a role with `is_superuser`). The text is "Only a Tec-Tac superuser may change the update source." (`UPDATE_SOURCE_DENIED`).
- The check runs before the body is read. A person who is not a superuser gets 403, never 400, and nothing is saved or audited.
- `core.runtime_settings.manage` and `core.privileged_operations` no longer change the saved source. Both were enough in 1.17.2 to 1.17.4.
- `RuntimeSettingsView.patch` (the module `register()` time limit) is unchanged. It still accepts `core.runtime_settings.manage` and `core.privileged_operations`.
- `GET` stays open to any signed-in user. Staging and installing keep `core.privileged_operations`. The audit row, throttles and validation are unchanged.
- The contract entry, the note on `/api/tfd/system/updates/online/stage/`, `docs/update-source.md` and `docs/runtime-settings.md` say so.

UI 0.12.82 to 0.12.85 still show the form to those two role types, and they now get a 403 on save. The UI change that hides the controls is filed in `reviews/requests/ui.md` and needs Core 1.17.5.

## Installer: a healthy Core is not rolled back (held Medium)

The installer's reporting check asserted `not s['error']`. `error` is Core's bridge error or the handover error. When Report Manager owns the bridge but reports unhealthy, Core sets a handover error, the check failed, and the system-update helper rolled back a healthy Core.

- `reporting_bridge_status()` gains `bridge_error` (only Core's own bridge error, or null) and `handover_error` (only the handover error, or null). `error` is unchanged and still equals `bridge_error or handover_error`.
- The installer asserts `not s['bridge_error']` and prints `handover_error` as a warning. It keeps the installed-or-handover assertion and every marker assertion, so a real Core bridge fault still fails the install.
- An unhealthy Report Manager is not hidden. The status page and diagnostics still show `error`.

## Fallback serves registrations already forwarded (held Low)

When a module registered a model while Report Manager was available, and Report Manager then proved not to own the bridge at settle, Core installed its bridge but kept those registrations marked forwarded. Neither bridge served them.

- `_take_bridge_back()` now clears the forwarded set (the registrations stay in Core's record) and clears the Report Manager ownership flag, before it installs Core's bridge. Core's bridge serves them, as it does the pending ones.
- A model that carries `hidden_fields` is refused (`hidden-fields-unavailable`), because Core's bridge cannot hide columns. The log line names the formerly forwarded ids too.
- After the fallback, `owner` is `core`, `forwarded_models` is 0, and `unregister_reporting_model` no longer calls Report Manager for those models.
- When Report Manager is healthy at settle, nothing changes: the registrations stay forwarded.

## Module-facing changes

- `PATCH /api/tfd/system/update-source/` is superuser-only. No module calls it (`modules/` has no use of `update-source`, `update_source` or `core.runtime_settings.manage`). A role that holds only `core.runtime_settings.manage` or `core.privileged_operations` now gets 403.
- `tec_tac.reporting.reporting_bridge_status()` gains `bridge_error` and `handover_error`. Additive. `error` is unchanged, so Report Manager 0.3.0 and the seven callers of `register_reporting_model` (`alerts`, `checks`, `cyberhoot`, `huntress`, `patchmanagement`, `scoutdns`, `scriptexecution`) see no change.
- The fallback now serves registrations that were already forwarded. No signature changes. Behaviour only improves for those callers.

## Tests

- New `tests/update-source-1.17.5.py`: superuser can change the source and the audit row is written; `core.runtime_settings.manage` only, `core.privileged_operations` only, both together and no right all get 403; invalid bodies from a non-superuser get 403 and save nothing; `GET` stays open; `RuntimeSettingsView.patch` keeps its rule; contract and docs wording.
- New `tests/reporting-installer-fix-1.17.5.py`: the installer line passes for the unhealthy Report Manager state and the normal, handover and fallback states, and still fails for a Core bridge error or a lost marker; status keys and `error` equals `bridge_error or handover_error`; the contract text; the fallback with forwarded registrations (capability unavailable, and a health callback that raises), the refused `hidden_fields` model, the unchanged no-fallback path, and no provider call on unregister.
- Amended `tests/reporting-handover-1.17.4.py` (new key set, the unhealthy state in the installer loop), `tests/update-source-1.17.2.py` and `tests/runtime-settings-1.17.1.py` (rbac stubs now include `is_effective_superuser`; the 403 text assertion names a superuser).

Not run here: Django is not installed on this PC. The tests above use stubs. `tests/reporting-registration-runtime.py` and the other tests that need `manage.py shell` could not run.
