# Tec-Tac Framework 1.18.34

Date: 21 November 2026. The audit trail of file transfers is now complete. Core writes a row when a transfer fails at Tactical or the agent, and when it refuses a bad chunk. It also checks who is asking before it reads a chunk, and it stops writing a session id on a row it wrote before it knew the session was real. `main` stays held.

## Module-facing change

`core.tactical_operations` stays at 1.18.0. No declaration key is added. This release changes how the 1.18.33 additions behave and adds one optional keyword. A declaration made the 1.18.33 way registers and runs as before. Needs framework >=1.18.34 only for a module that passes the new keyword.

Remote Background 0.11.4 is the only module in `modules/` that declares `binary_body` and `audit.transfer` (the plan for this release said none did; I checked and it does). Its chunk route (`FileUploadChunkView.put` in `views.py`) calls `read_binary_body` without `params`, then passes `binary_body` to `run_tactical_operation`. Nothing it calls changes signature or code. Two things change for it. First, from 1.18.34 a chunk from a caller who lacks the Tactical flag, the module permission or unrestricted scope is refused before any byte is read, with a deny row. RB maps those codes through `service._refusal` (401, and 403 `tactical_permission_denied`). Second, Core writes the rows in items 1, 2 and 4 below. RB's own six chunk codes stay in `CHUNK_CORE_CODES`, and its refusals now write a Core row limited per user and operation, not per session (RB passes no `params`). RB treats Core's chunk refusals as input problems and writes no row of its own for them, so Core's new row is not a duplicate.

- **`read_binary_body(request, module_id, operation_id, *, params=None)`.** The keyword-only `params` is new and optional. A module that does not pass it still gets every check that matters before the read (item 3). A module that passes the same `params` object it will pass to `run_tactical_operation` also gets the role-scope check before the read, and its rows carry the session id.
- **Chunk refusals now write a row.** `invalid_content_range`, `binary_body_required`, `binary_body_not_allowed`, `body_too_large` (of a chunk), `length_required` and `content_length_mismatch` write one `custom:operation-failed` row with failure `core_refused`. At most one per session and code. The six AD-19 codes (`refusal_row_codes`) and every ordinary operation behave as before. A `body_too_large` from a JSON body still writes no row. New metadata key `chunk_refusal_row_codes`; the key `refusal_codes_without_row_added_in_1_18_0` is gone (it listed these six as "no row").
- **A failed transfer gets its end row.** A `complete`, `cancel` or `fail` that Tactical answers 4xx or 5xx now carries `transfer_stage: end` and `transfer_outcome: failed` on the failure row Core already writes. Still one row per call.
- **Early rows have no session id.** A row written before Core has cleaned the path parameters has `transfer_session` null and no `transfer:<session id>` correlation id. Rows after that carry both, as before.
- **Row text and behaviour a module may rely on:** a refused call writes at most one row; no row holds chunk bytes, `Content-Range` text, Tactical text or caller text.

## Closes

- ORDER "Core 1.18.34, AD-69 audit completeness" in `reviews/requests/core.md` (Johan, 21 November 2026: "yes we need to keep track of this"), all four asks. They are the two Mediums and two Lows held by the Core 1.18.33 review. The release manager removes that entry, naming 1.18.34.

## What changed and why

All code is in `framwork/tec_tac/tactical_operations.py`. The text is mirrored in `docs/tactical-operations.md` and `framwork/tec_tac/contracts.py` (both CRLF, kept).

1. **Chunk refusals write one limited row per session and code** (review Medium). New `CHUNK_REFUSAL_ROW_CODES`. `CORE_REFUSAL_ROW_CODES` is unchanged. `run_tactical_operation` sets a local flag around step 6a (the chunk check), so a `body_too_large` from `_clean_body` (a JSON body) still writes no row. In the except handler, a non-GET refusal from that step writes a `core_refused` row through the existing `_write_core_refusal`, with the full transfer metadata and the `transfer:<session id>` link (the session is known by then). A new helper `_write_chunk_refusal` limits it to once per session and code: `_refusal_row_once` does `cache.add("tectac:transfer-refusal:<session>:<code>", 1, 7200)` (`TRANSFER_REFUSAL_TTL_SECONDS`), the same shape as the end-row guard. A cache that is missing or raises fails open and the row is written. A row that does not record frees the key. A repeat writes no row and leaves `exc.audit` as `None`. Without a session id the key uses the user's pk and the operation id. `read_binary_body` writes the same row for its own five refusals, after its checks pass.
2. **A failed transfer gets its end row** (review Medium). New `_failed_end_fields`. For `complete`, `cancel` and `fail` answered 400 to 599, with a canonical session id, and under the same `_end_row_once` guard as the success end row, the existing failure row (`custom:operation-failed` for 4xx, `custom:outcome-unknown` for 5xx) takes `transfer_stage: end`, `transfer_outcome: failed`, `transfer_reason` and `transfer_bytes` (only a whole-number `committed_offset` of a JSON answer). No Tactical text. A repeat of the failing call writes its failure row without end fields. A row that does not record frees the key so a retry can write it.
3. **`read_binary_body` checks before it reads** (review Low). Steps 3, 4 and 4a of `run_tactical_operation` and the role-scope loop moved verbatim into private helpers (`_check_caller_rights`, `_check_role_scope`, `_deny_hint`) that both functions call. `run_tactical_operation`'s order, codes and row fields are unchanged. `read_binary_body` now first requires a real, authenticated request (401, same codes as `run`), runs the Tactical flag, module permission and `caller_scope` checks and, with `params`, the role-scope check, with the same deny rows. `read()` and `request.body` are never touched on a refused call, and `Content-Length` is still checked before a byte is read.
4. **Early deny rows carry `transfer_session` null** (review Low). `run_tactical_operation` no longer reads the session id from the raw parameters. The rows of `server_only`, the permission refusals, an invalid correlation id and `invalid_params` carry `transfer_role` and `transfer_direction` only. After `_clean_params` the session comes from the cleaned values and goes on every later row. A caller who is refused can no longer write a row under another person's session id.
- Comments and docstrings that said "writes no row" or "every row carries the session id" now say what is true. The capability metadata adds `chunk_refusal_row_codes` and `chunk_refusal_rows_added_in_1_18_0` and describes the new rows.
- `VERSION` and `tec_tac_package.json` are 1.18.34. `RELEASE_NOTES_1.18.33.md` moved to `docs/releases/`, `tests/version-1.18.33.py` to `tests/legacy/`.

## Assumptions

- **Which statuses give a failed end row.** The order says "a 4xx or 5xx". I excluded 401 and 403 (permission refusals: they stay `deny` rows, and the session did not end), 408 (already relayed with no row) and 429 (Tactical asks the caller to retry; the session is still open). Everything else from 400 to 599 gets the end fields. Recorded in `reviews/questions/core.md`.
- **A later success after a failed end row writes no second end row.** It is the same once-only key, as ordered. So a 5xx can say `failed` for an outcome that was unknown. The row action says `custom:outcome-unknown` next to it. If a success after a failure should still write its completed row, say so.
- **`read_binary_body`'s own refusals write the row too** (`length_required`, `body_too_large`, `content_length_mismatch`, `binary_body_not_allowed`), once per session and code, or per user and operation when no `params` is given. Cache down fails open.
- **`core.tactical_operations` stays 1.18.0.** No declaration key is added, and the changes fix behaviour of features only Remote Background declares. The metadata and docs describe the changed behaviour under 1.18.0. A module that wants the new `params` keyword checks framework >=1.18.34.
- **Helper signature.** The plan named `_refusal_row_once(session, code)`. It is `_refusal_row_once(session, code, fallback=None)`; `fallback` is the user and operation key part for a call with no session id.
- **An extract that finishes on its own still has no end row.** Outside the four asks, still open in `reviews/questions/core.md` (1.18.33 entry).

## Retired or changed checks

All in `tests/tactical-operation-file-transfer-1.18.33.py`, which still passes after these edits:

- `helper_error` (read_binary_body refusals, was "a helper refusal writes no row"): now expects one `core_refused` row with the code.
- The 413 oversize chunk check ("an oversize chunk never reaches Tactical and writes no row"): now expects one row.
- The bad-range loop ("Tactical never called and no row"): the first refusal of the session and code writes one row, every repeat none. One more check: a repeat writes no second row.
- "required and not allowed" and "binary_body_not_allowed ... no row": now one limited row each; the AD-19 code `body_field_not_allowed` still writes its row.
- The permission refusal of a chunk (was: session and `transfer:<id>` link on the row): now `transfer_session` null, role and direction present, the caller's own correlation id kept.
- The module scan: Remote Background 0.11.4 now declares `binary_body` and `audit.transfer`. The scan lets that one module use the new names and the `transfer` audit key, and still refuses every other module. The test failed on the 1.18.33 source for this reason before this release.
- `tests/version-1.18.33.py` moved to `tests/legacy/`; `docs/releases/RELEASE_NOTES_1.18.33.md` is the old note.

## New tests

- `tests/tactical-operation-file-transfer-audit-1.18.34.py`:
  - Item 1: each of the four run-path codes writes exactly one row (failure `core_refused`, the code, role, session, `transfer:<session>`); a repeat writes none and `exc.audit` is `None`; another code or session writes its own; no session id keys by user and operation; a cache that raises or is missing still writes the row; a failed audit write frees the key; the `read_binary_body` codes write one limited row and `read()` is never called for 411 and 413; no bytes, `Content-Range` text or Tactical text in a row; a JSON `body_too_large` writes no row; the six AD-19 codes write a row every time; a GET writes nothing.
  - Item 2: complete, cancel and fail answered 400, 404, 409, 422, 500 and 502 write the end fields; 401, 403, 408 and 429 do not; a repeat writes a failure row without end fields; a failed end row followed by a cancel or a success writes no second end row; the cache and audit-failure paths; chunk, ack and status answered 4xx unchanged; a GET is not an end role; ordinary operations unchanged.
  - Item 3: no Tactical flag, no module permission, a limited role for an unrestricted-only operation and (with `params`) an agent out of scope each get the refusal and the deny row with `stream.reads == []`; 401 for an anonymous request, a request with no session proof and a stand-in object; an allowed caller reads as before.
  - Item 4: permission, module-permission, caller-scope, `server_only`, invalid-correlation-id and `invalid_params` rows have a null session and no `transfer:` link even with a valid uuid in the path; rows after cleaning carry both; a refused caller cannot write under another person's session.
  - Metadata, docs and contract text.
- `tests/version-1.18.34.py`: release bookkeeping, line endings, rebuild-label guard.
- `tests/release-integrity.sh` runs the new test before every pack.

## What could not be run here

Django, Tactical and Redis are not installed on this PC. Only the stub-based tests ran: the new test, `tests/tactical-operation-file-transfer-1.18.33.py` and the whole `tactical-operation*.py` family, except `tactical-operations-runtime-1.17.7.py` and `tactical-operations-runtime-1.17.13.py`, which import `accounts` from a live Django and could not start. A real `manage.py` dispatch, Django's real cache and a signed build did not run. Both rows and the cache key shape were checked against stubs only. The review and signing happen in the pipeline.

## Johan dev02 checklist

You need Core 1.18.34 on dev02. Remote Background 0.11.4 declares the upload operations, so steps 1 to 4 use its file upload from the browser. Open the audit log filtered to Remote Background after each step.

1. Update dev02 to Core 1.18.34 and check the version.
   - PASS: `VERSION` and the package say 1.18.34 and Core starts with no error in the log.
   - FAIL: the update stops or Core does not start. Send the update log.
2. Upload a small file to an online endpoint through Remote Background and let it finish.
   - PASS: two rows for the transfer, `transfer_stage` start and end (outcome `completed`), both with correlation id `transfer:<session id>`, and no row per chunk.
   - FAIL: a row per chunk, a missing end row or a different correlation id on the two rows. Send the rows.
3. Start an upload, then stop the agent service on the endpoint and let the transfer fail (or cancel it after Tactical has expired the session), so Tactical answers `complete` or `cancel` with an error.
   - PASS: one row for that call with `transfer_stage` end and `transfer_outcome` failed, and no Tactical text in it. A second try of the same call writes a failure row without those two fields.
   - FAIL: the failure row has no end fields on the first failing call, or two rows carry them. Send the rows.
4. Send a chunk with a wrong `Content-Range`, three times in a row on the same transfer (a test script or browser dev tools, replaying the chunk request).
   - PASS: 400 `invalid_content_range` each time, and the audit log holds one `custom:operation-failed` row with failure `core_refused` for the transfer, not three.
   - FAIL: three rows, or none. Send the rows.
5. Sign in as a user without the "Use the file browser" permission and send a chunk with a valid session id from another user's transfer.
   - PASS: the refusal row has `transfer_session` empty and no `transfer:` correlation id, and the other user's transfer rows are unchanged.
   - FAIL: the row carries the other user's session id. Send the row.
6. Use Core as you did before this release (list agents, run a script, open Remote Background).
   - PASS: everything works as on 1.18.33.
   - FAIL: any new error. Send the message and the time.

## Exit list

- Chunk refusal rows, failed end rows, `read_binary_body` checks, early rows with a null session, metadata, docs, contract text, tests: done.
- Signing, review, dev02 install and a fresh public contract export: not done here. The export is generated on a running server; it is still open for 1.18.32 and 1.18.33 in `reviews/requests/core.md`.
- Not done: the extract end row for an extract that finishes on its own, the non-blocking sandbox run for a long sign-in ("From ai 0.8.7 round 1"), and the sandbox, scheduler and install findings in `reviews/core/BACKLOG-new-findings.md`. None is in the order.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.


Changed in 1.18.35: the failed end row has its own once-only key (not the success key), a 404 takes none, and the old metadata key `refusal_codes_without_row_added_in_1_18_0` is back as an empty list. See `RELEASE_NOTES_1.18.35.md`.
