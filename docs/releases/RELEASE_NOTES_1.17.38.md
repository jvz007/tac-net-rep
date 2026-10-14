# Tec-Tac Framework 1.17.38

This patch release closes three items of the Core 1.17.38 plan, from Johan's answers in `reviews/questions/core.md`:

1. **CQ113: every module preference change is audited.** Johan answered "yes implement it". Each real add, modify or delete of a module
   preference writes one strict Core audit row.
2. **CQ109 and CQ116: the person must be allowed to use the module.** Johan asked for a more secure browser route. The route and the Python
   functions now refuse a person who may not use the module. The limits that remain are stated plainly below.
3. **CQ104 and CQ115: a failed module job is announced for seven days, once per person.** Johan answered seven days, announced once per person,
   with no daily reminders. The window was six hours.

No migration. No database change. The contract changes are additive.

## Changes

- **Audit rows for module preferences (`framwork/tec_tac/module_preferences.py`, CQ113).** A save or delete writes one strict audit row,
  in the same transaction. The action is `add`, `modify` or `delete`. The object type is `module_preference`, and the object id is
  `<module_id>/<name>`. The row names the signed-in person (the actor and `user_id`), the module and the name. It holds `size_bytes` for
  add and modify only. It never holds the value, before or after. The rule follows AD-19 condition 5, and the row is written the way saved
  views write theirs (the model is AD-26 and AD-31 condition 2).
- **No row for nothing.** A read writes no row. A write that changes nothing writes no row and no database update. `true` and `1` are
  different values, `1` and `1.0` are different values, and the key order of an object does not matter. A delete of a missing name writes
  nothing. A refused call writes no preference row and no deny row, as Johan asked.
- **A strict failure (CQ117).** If the audit row cannot be written, the change is rolled back and the answer is `audit_failed` (HTTP 503,
  or `ModulePreferenceError` with code `audit_failed` and status 503). Johan knows the cost: a display toggle fails while the audit store is
  down.
- **The person may use the module (`module_preferences.py`, the browser views, CQ109 and CQ116).** The order of checks is now the same for
  every route: signed in (401), the module is installed and enabled (404), the person may use it (403 `module_not_allowed`), then the name,
  the value and the limit. The rule is the rule of saved views. A superuser or a role superuser may use any module. A module with no
  permission groups is open to every signed-in person. Any other person needs one of the module's permissions. A person without that access
  gets nothing read, written or audited.
- **Source and verification on each row.** A row from the Python functions records `source` `module_python` and `module_verified` `true`,
  because Core verified the calling module (AD-26). A row from the browser route records `source` `browser` and `module_verified` `false`.
- **Failed module job notices (`module_failure_notices.py`, `notices.py`, CQ104 and CQ115).** `NOTICE_WINDOW_HOURS` is 168 (seven days). A
  failure is announced once per person, through the notice ledger that already holds each job id and person. There is no daily reminder
  and no new mechanism. The ledger keeps rows for 14 days (`LEDGER_RETENTION_DAYS`, up from 7), so a row for a job still inside the window
  is never pruned. The hourly email cap (20 an hour), the 200 jobs per tick and the recipient rules are unchanged.
- **Documentation.** `docs/module-preferences.md` (new Audit section, the access rule, the can and cannot prove section, versions),
  `docs/module-audit.md` (the new object type), `docs/module-replacement.md` (the seven day window and the ledger retention).
- **The root release note of 1.17.37** moved to `docs/releases/RELEASE_NOTES_1.17.37.md`, as earlier releases were moved.

## Module-facing changes

Heading for module authors. `core.module_preferences` moves from 1.1.0 to **1.2.0**, and a module that uses it must require
`tec-tac-framework >=1.17.38`. Nothing in `modules/` used the functions or the browser route when this was written (grepped), so no module
breaks.

- **(a) A write or delete now writes an audit row.** One strict Core row for each real change: action `add`, `modify` or `delete`, object type
  `module_preference`, object id `<module_id>/<name>`. Reads and unchanged writes write nothing.
- **(b) A new refusal, 503 `audit_failed`.** If the row cannot be written the change is rolled back, so nothing is saved without its audit row.
  The browser route answers `{detail, code}`. The Python functions raise `ModulePreferenceError` with `code` `audit_failed`.
- **(c) An unchanged write is skipped.** The same value as the one stored writes nothing and gives the same answer.
- **(d) A new refusal, 403 `module_not_allowed`.** The person may not use the module (the rule above). It comes before any read or write,
  on every function and route. A module that calls the Python functions for a person who may not use its own module is refused too.
- **(e) The module id on the browser route is still a claim.** See the next section.
- **Unchanged:** the functions, their arguments and results, the limits (4 KiB, 5 levels, 50 names, 120 writes a minute), the response
  shapes, and the Python caller check (AD-26, from 1.17.37).

Audit row fields, for anyone reading the log: `username` is the person; `debug_info` holds `object_id`, `module_id` (`core`) and `metadata`,
which is `module`, `name`, `source`, `module_verified`, `user_id` and, for add and modify, `size_bytes`.

## What Core can and cannot prove about the module id

The browser route puts the module id in the web address, so the module id on that route is a claim. Core states what it can and cannot prove.

**Core can prove:**

- who the person is: their signed-in session, and a row always belongs to that person;
- that the module is installed and enabled, on every call;
- that the person may use that module (403 `module_not_allowed` otherwise);
- that a row can only ever belong to that person and that module id pair.

**Core cannot prove:**

- that a browser request came from that module's page. Any signed-in person who may use module A can write module A's own preference rows
  for themselves through the browser, and nothing more. They cannot write another person's rows, nor the rows of a module they may not use.
  The audit row records this as `source` `browser` and `module_verified` `false`. That is a claim, not a fact.
- that the `user` argument of a Python call is honest. The Python path verifies the calling module (AD-26), not the person.

No browser trust claim is made in this release: no header, no token, and no statement that the browser is verified. The UI shell's own
binding of the id to the calling module stays a statement about the UI.

## Not in this release

- **AD-36 is not recorded.** Johan has not signed it off. The docs and these notes cite AD-26, AD-31 condition 2 and AD-19 condition 5 instead.
- **Audit row retention.** The rows are kept as long as Tactical's audit retention keeps audit rows. Core does not set a period, and this
  release makes no privacy or legal claim about them (CQ114 is open for Johan).
- **Deny rows for refused callers.** Not built, as Johan said.
- **Auditing reads.** Not built, by design.
- **UI work.** The helper should debounce rapid saves, so that one person clicking a toggle many times does not write many rows, and it should
  show a plain message for 403 `module_not_allowed` and 503 `audit_failed`. This is in `reviews/requests/ui.md`. Core does not wait for it.
- **Backlog, Low, left for a later release:** copying old email markers into the ledger can use up the hourly email cap (module_failure_notices.py),
  and the UI helper has no function check (`workspace/ui/src/module-preferences.js`, which is UI work).

## What changes for administrators

- **The first sweep after this update may announce a failed module job that was never announced before.** The window was six hours; it is now
  seven days. Each such failure is announced once per person, and the Priority 1 email is capped at 20 an hour, so the emails go out over the
  following ticks. Failures already announced stay silent, because the ledger holds them.
- A notice is never repeated for a person, and there is no daily reminder.

## Questions and requests

- `reviews/questions/core.md`, "Core 1.17.38": CQ113 is answered (Johan: yes, implement it). CQ114 (retention and privacy wording, a legal
  topic), CQ115 (the first sweep after the update), CQ116 (one shared check, for the browser route and the Python functions) and CQ117 (the
  strict failure rule) are written there, with the assumption each one went on with.
- `reviews/requests/ui.md`, heading "modulePreferences helper (src/module-preferences.js)": the UI request above.
- `reviews/requests/core.md`: no entry is closed by 1.17.38.

## Tests

New, Django-free: `tests/module-preferences-audit-1.17.38.py` (the rows on the browser and Python paths, the value never in a row, reads, unchanged
writes and refusals write nothing, the strict rollback, the views, the person check and its order, the capability, the contract rows, the
docs and these notes), and `tests/module-failure-notices-window-1.17.38.py` (the seven day window and its edges, once per person over eight days
of hourly ticks, Clear read and a reinstall, a new recipient, the 14 day retention, and no window line that still says six hours).

New, dev server only: `tests/module-preferences-audit-runtime-1.17.38.py` (real AuditLog rows, the rollback with a broken audit store, and a
person without the module's permission).

Updated for the new pins and the new window: `tests/module-preferences-1.17.35.py`, `tests/module-preferences-caller-1.17.37.py` (the audit
stub and 1.2.0 and `>=1.17.38`), `tests/browser-contract-rows-1.17.37.py` (the new refusals), `tests/module-failure-notices-1.17.34.py` and
`tests/module-failure-notices-1.17.14.py` (the six hour cases moved to seven days).

Checks on this PC are in the report for this release. Django is not installed here, so the runtime script cannot run here.
