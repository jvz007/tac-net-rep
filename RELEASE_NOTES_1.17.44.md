# Tec-Tac Framework 1.17.44

This patch release adds one optional declaration key for Tactical operations, `audit.object_id`, so a change with no object in its path still
names its object in the audit row. It also puts three new UI runtime rows, the SearchSelect server mode and the repository response fields into
the public contract export, and closes two findings held from the 1.17.43 review. Everything is additive. No migration, no database change, no
route change, and no change to a key a module already reads.

## Module-facing changes

- **`core.tactical_operations` 1.13.0 (needs framework 1.17.44 or later; feature-detect with `>= 1.13.0`).** One optional key. A declaration that
  does not use it behaves exactly as before, with the same rows.
  - `audit.object_id` is a fixed text declared by the module: letters, digits and `.` `_` `:` `-`, 1 to 64 characters, starting with a letter or
    digit, and not secret-looking. It is for an operation with no path parameter that names the object: a settings save, a test email, a cache
    clear, the server script test.
  - It is the last fallback. The id still comes from `audit.object_param` first, then the first scope object. The literal is used only when
    neither gives an id, so it never overrides a real object.
  - Registration refuses it on a GET operation and together with `audit.object_param`, `audit.object_field` or `audit.object_body_field`, so one
    operation has one source of the object id. The "unknown audit key" message now lists `object_id`.
  - It names the object on **every** row of that operation: success, `tactical_denied` and scope deny, the failed row, the outcome-unknown row and
    the `core_refused` row. It is declared text from the module's signed code, not caller or body input, so the AD-19 rule that a `core_refused`
    row never carries a body value still holds. This scope is Johan's call (`reviews/questions/core.md`, CQ132). Success-row-only is the
    alternative.
  - `list_operations` and `get_operation` show `audit.object_id` (null when not declared) and, since this release, `audit.secret_fields` (an empty
    list when there are none). The audit block only gained keys. `agent-management`, `take-control` and `remote-background` read `get_operation`
    for presence only, so nothing they read changes.
  - `audit.secret_fields` may no longer name the same field as `audit.object_field`, because Tactical's answer often echoes the field and the
    object id would carry its value. No module in `modules/` declares both: `globalsettings` and `remote-background` declare `secret_fields`
    and neither names an `object_field` (checked by grep).
- **Name of the key.** `scriptmanager` 0.4.4 asked for `audit.object_id_const`. Core builds one key only, `audit.object_id`, the name
  `globalsettings` 0.3.0 used. The adoption requests in `reviews/requests/core-modules.md` say so.
- **Capability pins.** Tests that pinned `core.tactical_operations` 1.12.0 now pin 1.13.0. No behaviour assertion changed.

## Contract export

The public contract export is generated from `contracts.py`. These changes are documentation only: no endpoint, capability or version moves.

- **Three new browser rows from UI 0.12.112**, placed after `ui.authenticated.components`:
  - `ui.authenticated.dialogs`: `register` and `open`, the descriptor fields, one dialog at a time, the layers (dialog 1100, toasts 1200, unsaved
    prompt 1300, Yes or No confirm 1400) and the refusals.
  - `ui.authenticated.signInLanding`: `register({id, permission, check})`, what a check may return and the shell's rules. The two open UI
    questions (Q66 reload, Q67 route targets) are stated only as built in UI 0.12.112, not as a Core promise.
  - `ui.authenticated.rowMenu`: `open` and `shouldHandle`, the item fields, the 40-item limit and layer 1150.
- **SearchSelect server mode** on `ui.authenticated.components`: the props `serverSearch`, `loading`, `hasMore` and `selectedLabel`, the events
  `search` and `more`, the 1000-row limit and its line, and the rules for `loading`. The 1.17.42 text is unchanged.
- **Response fields of `GET /api/tfd/modules/repositories/`.** The cause: the JSON catalog already carried `sync_schedule` in `http[].contract`,
  but the Markdown and text exports printed the HTTP boundary as a bare route table, so the exported file showed no response fields. Both
  exports now add an "HTTP response details" section after the table for routes that opt in with `export_details`. Only this one route opts in,
  so the export stays short. A route with no contract adds nothing. The description now also holds `schema`, the six keys of `sync_schedule`
  as `sync_schedule_status()` returns them (`next_run_at`, `last_run_at` and `last_run_status` are null when never run; the whole object is
  null when the schedule does not exist), the repository row fields and the redaction for a caller who cannot manage modules.

## Held findings fixed (from the 1.17.43 review)

- **Medium: `audit.secret_fields` was not shown by `describe()`.** It is now in the audit block.
- **Low: a secret field could equal `audit.object_field`.** Registration now refuses it with a plain sentence.

## What changed

- **`tactical_operations.py`.** `TacticalOperation.audit_object_id`; `_parse_object_id`; `_object_id` takes a `declared` flag and returns the
  literal as its last fallback; `_refusal_object_id` calls it with `declared=False` and applies the literal only after the path-sourced scope
  loop, so a path id still wins on a `core_refused` row. `CAPABILITY_VERSION` is 1.13.0, with `declaration_keys_added_in_1_13_0` and
  `behaviour_added_in_1_13_0` in the contract metadata. No `object_source` metadata key was added for the literal.
- **`contracts.py`.** Three rows, the components text, the repositories description and `export_details`, the two renderers, and a 1.17.44 line in
  the `register_tactical_operation` text. The renderers keep working when a catalog row has no `contract` key.
- **Docs.** `docs/tactical-operations.md` has the header and a new "Added in 1.17.44" section.

## Closes

- `reviews/requests/core.md`: both "From UI 0.12.112" entries, half (a) of globalsettings 0.3.0 (the literal object id), and scriptmanager 0.4.4.
- The Medium and the Low held from the 1.17.43 review.

## Not built, on purpose

- Slicing a whole-list GET answer (automation 0.9.0, tasks 0.9.0): CQ130 is unanswered.
- A failed row for a declared GET (reportmanager 0.6.1, 0.5.2): CQ131 is unanswered.
- The update helper's handling of installer status 78 (held Low): it needs the helper's own release and test.
- The welcome contracts, the system-action contract and the bigger designs in `reviews/requests/core.md`: each waits on Johan or on a design of its own.

## Not run on the development PC

- Django is not installed here. The Django-dependent tests (`tactical-operations-runtime-*`) and a real contract export cannot run. The new tests
  read `contracts.py` with `ast` and run `tactical_operations.py` against the stubs of `tests/tactical-operations-1.17.7.py`.
- The dev server needs Core 1.17.44 signed and installed, and a fresh export written to `docs/contracts`, before the export can be checked end to
  end. Nothing on the Repositories page, the Scheduler or sign-in changes.

## Checks run

- New: `tests/browser-contract-rows-1.17.44.py`, `tests/tactical-operation-object-id-1.17.44.py`.
- Changed: `tests/browser-contract-catalog-1.15.170.py` (three ids) and the capability pins in the `tests/tactical-operation*`, `tests/contract-export-1.17.16.py` and
  `tests/audit-correlation-1.17.16.py` tests.
- `bash tests/release-integrity.sh`, `python -m py_compile` on the changed files and `ruff check` with the repository's configuration.
