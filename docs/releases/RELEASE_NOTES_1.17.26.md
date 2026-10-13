# Tec-Tac Framework 1.17.26

This release lets an administrator allow a private mail relay for Core's own Priority 1 email. It audits every API key you create, edit or delete. It gives modules two new options when they declare a Tactical operation: "any of these permissions" and "a larger body". It also cites the accepted decision for moving a site.

Capability: `core.tactical_operations` goes from 1.8.0 to 1.9.0. It is still major 1. Both additions are optional. A declaration that uses neither behaves exactly as before.

Date: 14 October 2026.

## Module-facing changes

Read these before you upgrade a module that declares Tactical operations.

- **`register_tactical_operation(..., permissions_any=None, body_max_bytes=None)` (capability `core.tactical_operations` 1.9.0).** Two new keywords at the end of the signature. Additive and opt-in. Feature-detect with `core.tactical_operations >= 1.9.0`. A module that uses either needs `requires.framework >= 1.17.26`. All 15 modules that declare operations are unaffected until they pass one of them (agent-management, agents, alerts, automation, checks, globalsettings, licensing, patching, remote-background, reportmanager, scriptexecution, scriptmanager, software, take-control, tasks).
  - `permissions_any`: Tactical role flags of which the caller needs at least one. It combines with `permissions`: the caller needs every flag of `permissions` and at least one of `permissions_any`. `permissions` may be empty only when `permissions_any` is given. A flag may not be in both lists. The 403 `tactical_permission_denied` names the flags ("It needs one of can_view_reports, can_manage_reports."), the deny row carries `needs_one_of`, and `list_operations` and `get_operation` show `permissions_any`.
  - `body_max_bytes`: a whole number of bytes from the 256 KiB default up to 8 MiB, a ceiling Core keeps (`MAX_BODY_CEILING_BYTES`). `body_too_large` (413) names the cap that applied. `list_operations` and `get_operation` show the effective cap as `body_max_bytes`. A value below the default, above the ceiling, a bool or a non-integer is refused at registration.
  - Listings: every operation now also lists `permissions_any` (an empty list for an older declaration) and `body_max_bytes` (262144 unless set). Additive keys.
  - Report Manager adopts both in its own release (requested in `reviews/requests/core-modules.md`).
- **No change for Priority 1 email, API keys, or the caller identity.** No module imports `priority_mail`, `send_p1_email` or the new reader. `get_priority_mail_private_relay` is not in the public Python contract, so no module can read the setting.
- **`core.caller_identity` verifies an enabled server module (AD-30).** This is not a change. It was always true, because the identity keys on the enabled extension's folder and not on the category. It is now written down in `docs/caller-identity.md` and pinned by a test, because User Invite (`category: server`) relies on it.

## Closes

In `reviews/requests/core.md`:

- "Binding: private mail relay for Core's own Priority 1 email (AD-30, 14 October 2026)".
- "Core's own Priority 1 sender (CQ81...)" and "Moot for globalsettings from 0.4.3", both under "from Johan's answer on Global Settings mail". The old "Runtime setting to allow a private network mail server" entry closes with them: Global Settings no longer checks the mail host.
- The API keys bullet of "API keys and SSO admin" (the SSO bullet stays open, see CQ84).
- "Tactical operations: permissions any-of" and "Tactical operations: a larger body cap for template import" (from reportmanager 0.5.0).
- The held Medium of the 1.17.25 review: the site-move destination check had no accepted decision. AD-29 (Johan, 13 October 2026, CQ79) now records it.

## What changed

### Private mail relay for Core's own Priority 1 email (AD-30)

Core emails the Tec-Tac administrators when a module job fails. Before it sends, Core checks where the mail server's name points, and until now it accepted public addresses only. A server that sends through a relay on the private network got the in-app notice but no email. Now an administrator can allow the relay.

- **New runtime setting `priority_mail_private_relay`.** A real true or false, off by default. It is stored in a new column on `TecTacRuntimeConfig` (migration 0029, one boolean, existing installs read off).
- **Only an effective superuser may change it** (CQ83, assumption below). Everyone else gets 403 and one best-effort Core `deny` row (`object_id` `priority_mail_private_relay`, no value). The check runs before the value is looked at. A body that mixes it with another setting is refused whole, so nothing is saved. A number, text or null is a 400, so `1` or `"true"` never switches it on.
- **One strict audit row per change**, in the same transaction (`runtime_settings`, `modify`, the boolean before and after). A failed audit write rolls the change back. Sending the current value writes no row. This is the same pattern as `system_name`.
- **GET** carries `priority_mail_private_relay` as `{ value, default: false, warning }`. The warning is plain English: it lets Core's own Priority 1 email go to a mail server on a private network, and nothing else.
- **What the relaxed rule accepts.** With the setting on, and only for Core's own call, a mail server whose name resolves to ordinary private-network addresses passes: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7. Every address is judged on its own, so a name with one public and one bad address is refused.
- **What stays refused, even with the setting on:** cloud metadata addresses, loopback (127.0.0.1 and ::1), link-local, unspecified and multicast addresses, other reserved ranges, and a name that does not resolve. Loopback is refused on purpose until Johan answers CQ82.
- **Core's own call only.** The relaxed rule applies when `send_p1_email` runs with its own default host and send functions, and no frame on the call stack lies inside an installed module's folder (`caller_identity.module_frame_on_stack`). A module that reaches `send_p1_email`, `sweep_failed_jobs` or `host_refusal` gets the public-only rule, with one warning logged. A call that passes its own host or send function gets it too. A stack Core cannot read counts as a module (fail closed). A refusal never falls back to another sender.
- **The Priority 1 audit row** (`custom:priority-mail`) now carries `private_relay`, true only when the relaxed rule accepted the host. It stays count-only: no address, no host, no subject, no body.
- **Unchanged safeguards (AD-28 and AD-30):** the administrators' addresses only, 20 an hour, no SMTP password read, no Core SMTP client, no silent fallback.
- **The reader** `runtime_settings.get_priority_mail_private_relay()` never raises. Any error, or any stored value that is not exactly true, reads as off.
- **Docs:** `docs/runtime-settings.md`, `docs/caller-identity.md`, the contract rows in `contracts.py`. The UI field is already filed in `reviews/requests/ui.md`, which now has the exact key name and answer shape.

### API keys, the Core half (parity, AD-25)

Tactical lets an administrator create, edit and delete API keys. Core already guarded those routes (no key for or on a protected superuser account, a redacted list). It did not audit them.

- Confirmed against Tactical v1.5.2 (`accounts/views.py`, `GetAddAPIKeys`, `GetUpdateDeleteAPIKey`, `APIKeyPerms`): `can_list_api_keys` for the list, `can_manage_api_keys` for create, edit and delete.
- **One strict Core audit row per successful create, edit and delete** (`object_type` `api_key`, action `add`, `modify`, `delete`), in the guard's transaction. The row names the key's id, name and owner. An edit row lists the changed fields and carries name, owner and expiry before and after. **The key value is never in a row.**
- A create row finds the new key by name and owner. If it cannot be found, the row still goes out, with no id and `matched` 0. It is never skipped.
- A refused call keeps the guard's deny row and writes no success row. A call Tactical itself refuses writes no success row.
- Nothing Tactical returns or accepts changes. The list still shows key values to anyone with List API keys, as Tactical does, except `[REDACTED]` for a protected owner's key, as before.
- The routes, flags and rules are listed in the contract rules and in the new `docs/api-keys.md`.

SSO admin is not in this release. It needs a decision from Johan (CQ84).

### Tactical operations: `permissions_any` and `body_max_bytes`

- `permissions_any` matches Tactical's report generation, which a role may run with either "view reports" or "manage reports". `permissions` alone could only say "both".
- `body_max_bytes` lets one operation, such as Report Manager's template import, accept a larger JSON body than 256 KiB, up to 8 MiB.
- Details are in the module-facing section above and in `docs/tactical-operations.md`.
- A web-server body limit (nginx) or a limit in Tactical itself still applies and was not verified.

### Moving a site: AD-29 cited

No behaviour change. `docs/resource-directory.md` now names AD-29 under "Move a site", so the next review finds the decision. The existing `tests/resource-move-site-1.17.25.py` already covers a limited role moving into a client it holds no grant on, and it passed here unchanged.

## Questions for Johan (assumptions I went on with)

These are in `reviews/questions/core.md`.

- **CQ82:** should loopback (a mail server on this server itself) be allowed with the setting on? Assumed no: private ranges only. A one-line change in `priority_mail.refused_reason`.
- **CQ83:** may a holder of `core.runtime_settings.manage` who is not a superuser change the setting? Assumed no: superusers only.
- **CQ84:** SSO admin and the lock-out guard. Not built.
- **CQ85:** Tasks "actions before and after" audit: clear, masked or a changed marker. Not built.

## Left out of this release

- A streamed file answer for a declared operation (Report Manager's PDF run, the PDF history open, the asset download). Next Core release.
- SSO providers and settings admin (CQ84).
- The ticketed terminal WebSocket.
- Actions before and after as Tactical (CQ85).
- Nested scope sources, two audit actions on one route, a per-call audit action, and the other executor additions. Next executor release.

## Checks

Ran on this PC (Python 3.12, no Django, no Knox, no Tactical database):

- New: `tests/priority-mail-private-relay-1.17.26.py`, `tests/runtime-settings-private-relay-1.17.26.py`, `tests/caller-identity-server-module-1.17.26.py`, `tests/api-key-audit-1.17.26.py`, `tests/tactical-operations-permissions-any-1.17.26.py`, `tests/tactical-operations-body-cap-1.17.26.py`. All pass.
- Updated for the new capability version, the newest migration and the new Priority 1 audit field: `tests/priority-mail-1.17.25.py`, `tests/update-source-1.17.2.py`, `tests/session-theme-1.17.24.py`, `tests/runtime-settings-upload-1.17.14.py`, `tests/contract-export-1.17.16.py`, `tests/audit-correlation-1.17.16.py`, and the tactical-operations tests that pin the capability version. Their other checks are unchanged. `tests/tactical-operations-modules-compat-1.17.18.py` passes unchanged.
- The whole `tests/` folder, before and after: no test that passed before fails now. Tests that need Django, Knox or Tactical already fail on this PC before and after, and are the dev-server group.
- `python -m py_compile` on every changed Python file. `ruff check` on the changed files: the repo has no ruff config, and the new findings are the same kinds the files already carry (broad `except Exception` in fail-closed readers, `RUF012` in a migration).

Not run here, and why:

- `tests/priority-mail-runtime-1.17.26.py` (migration 0029 and the real setting row) and `tests/api-key-audit-runtime-1.17.26.py` (Tactical's real API key views with the guard). Both need Django, Tactical and its database. Run them on the dev server through `manage.py shell`.
- The 1.17.26 contract export. That step is Johan's or the pipeline's.
- `tests/contract-export-1.17.18.py` has a known earlier failure when `workspace/ui` sits beside the repo (UI `main.js` does not pass `tacticalScope`). It is the UI area's.

## Dev-server step

After the release is built and signed, update the dev server from the dev branch, run `manage.py migrate` (tec_tac 0029), then run the two runtime scripts above.

## Files

- `framwork/tec_tac/priority_mail.py`: the relaxed rule, `host_check`, `host_refusal`, the setting reader call.
- `framwork/tec_tac/module_failure_notices.py`: `send_p1_email` uses `host_check`, and the audit row carries `private_relay`.
- `framwork/tec_tac/caller_identity.py`: `module_frame_on_stack()`.
- `framwork/tec_tac/runtime_settings.py`, `models.py`, `migrations/0029_priority_mail_private_relay.py`: the setting.
- `framwork/tec_tac/tactical_account_guard.py`: the API key audit rows.
- `framwork/tec_tac/tactical_operations.py`: `permissions_any`, `body_max_bytes`, capability 1.9.0.
- `framwork/tec_tac/contracts.py`: the runtime-settings rows, the API keys rule, the tactical-operations rule.
- `docs/runtime-settings.md`, `docs/caller-identity.md`, `docs/api-keys.md` (new), `docs/tactical-operations.md`, `docs/resource-directory.md`.
- `docs/releases/RELEASE_NOTES_1.17.25.md`: the 1.17.25 notes, moved from the root.
