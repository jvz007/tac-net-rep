# Tec-Tac Framework 1.18.33

Date: 21 November 2026. Core can now carry file transfers for the file browser. A module can send one binary chunk to Tactical, read one back, and have each transfer audited as one start row and one end row instead of one row per chunk. `main` stays held.

## Module-facing change

`core.tactical_operations` goes from 1.17.0 to 1.18.0. It is additive and still major 1. Needs framework >=1.18.33. Feature-detect with `core.tactical_operations >= 1.18.0`. A declaration made the 1.18.32 way registers and runs as before. No module in `modules/` uses any of the new keys yet, and the compatibility check in the new test proves the 133 declarations there still pass the registration keys.

- **`binary_body=True`** (`register_tactical_operation`). PUT or POST only. Refused together with `upload`, `body_fields`, `file_response` and `body_selector`. `query_params` stay allowed.
  - A module's own route calls `read_binary_body(request, module_id, operation_id)` (new, public, in `tec_tac.tactical_operations`) before it touches `request.data` or `request.body`. It returns `{content, content_range}`.
  - `run_tactical_operation(..., binary_body={content, content_range})` is a new keyword-only argument, placed after `audit_before`. No positional argument moved. It is never reachable over Core's HTTP route: an operation that declares `binary_body` and is called there gets 400 `binary_body_required`.
  - `MAX_BINARY_BODY_BYTES` is 4 MiB plus 64 KiB (`limits.binary_body_bytes` in the metadata). It sits below `MAX_BODY_CEILING_BYTES` (8 MiB). A module cannot change it.
  - `read_binary_body` checks `Content-Length` first. Missing or invalid is 411 `length_required`. Over the cap is 413 `body_too_large`, and the message names the cap. Both happen before any byte is read. It then reads from the request stream with `read()`, at most the declared length plus one byte. It never reads `request.body`, so Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` (2.5 MiB by default on a Tactical 1.5.2 server) cannot refuse a 4 MiB chunk. Fewer or more bytes than `Content-Length` is 400 `content_length_mismatch`.
  - Core checks `Content-Range` itself, after the permission, role, scope and module-permission checks: exactly `bytes <start>-<end>/<total>` in digits, `start <= end < total`, and `end - start + 1` equal to the size of the chunk. Anything else is 400 `invalid_content_range`. A binary operation called without `binary_body` is 400 `binary_body_required`. `binary_body` given to any other operation is 400 `binary_body_not_allowed`.
  - Tactical's view receives the exact bytes with `Content-Type: application/octet-stream`, `Content-Length`, and `HTTP_CONTENT_RANGE` rebuilt from the numbers Core checked. A `Content-Range` that arrived on the inbound request never reaches any operation.
  - These refusals write no Core row, like `body_too_large` and the upload codes today. The call never reached Tactical, and a loop of bad chunks must not flood the audit log. The bytes never reach a log, a row or an error text.
- **`binary_response=True`**. GET or POST only. Refused together with `file_response`. Core relays `Content-Range`, `X-Chunk-Start` and `X-Chunk-End` next to `Content-Type` and `Content-Disposition`. Each of the three is relayed only when it is digits (`bytes n-n/n`; the other two at most 19 digits). A header that fails the check is dropped. The body stays raw bytes in `result.content`, held to the existing 25 MiB cap. A binary GET also works over Core's HTTP route, which already copies the relayed headers. Every other operation relays the same two headers as before.
- **`audit.transfer = {role, direction}`** (AD-69). `role`: `init`, `chunk`, `ack`, `status`, `complete`, `cancel`, `fail`. `direction`: `upload`, `download`, `archive`, `extract`. Registration refuses: an unknown role or direction, a role other than `init` on a route with no `{session_id:uuid}` parameter, `init` on a route that has one, a GET `init`, `complete`, `cancel` or `fail`, `audit.action_by_body` next to it, and `binary_body` on any role but `chunk`.
  - **Start row.** A 2xx `init` writes one row with the operation's own audit action and object type. Metadata: `transfer_stage: start`, `transfer_role`, `transfer_direction`, `transfer_session` (the answer's `session_id` when it is a canonical lowercase uuid, else null), `transfer_size` (a whole number from the answer's or the body's `total_size`, else left out). The declared `audit_fields` (paths, file name) are in the after value. An `init` whose body carries a `session_id` (Tactical's resume of an open session) writes no row.
  - **End row.** A 2xx `complete`, `cancel` or `fail` writes one row. Metadata: `transfer_stage: end`, `transfer_outcome` (`completed`; for `cancel` and `fail` the answer's `status` when it is `cancelled`, `failed` or `expired`, else `cancelled` or `failed` by role), `transfer_bytes` (the answer's `committed_offset` when it is a whole number), `transfer_reason` (`user` or `error`, only when the body's `reason` is exactly that), `transfer_session`. A module that splits Tactical's cancel route by `body_selector` (reason `error` is `fail`, otherwise `cancel`) records a failure as an end row.
  - **Once per session.** Before an end row, Core does `cache.add("tectac:transfer-end:<session id>", 1, 7200)` on Django's cache (Tactical's shared Redis). A repeated `complete` or `cancel` for the same session is relayed and writes no second end row. A cache error fails open and the row is written. The key is deleted when the row write itself fails, so a retry can write it.
  - **Link.** Every row of a call that carries the session id in its path, and the start row once Tactical answers, has the correlation id `transfer:<session id>` (45 characters). A `correlation_id` that a module passes on a transfer operation is replaced by it. This is the one case where Core overrides a caller's correlation id. A module should not pass one.
  - **Chunk, ack and status** write no row on a 2xx or 204. When Core or Tactical refuses one, the usual `deny`, `custom:operation-failed` (non-GET) or `custom:outcome-unknown` row is written. It now carries `transfer_role`, `transfer_direction` and `transfer_session` in its metadata and the transfer correlation id.
- **204 and 408.** For an operation that declares a transfer role, Tactical's 408 (`notify_retryable`: repeat the same request) is relayed unchanged, writes no row and leaves `result.audit` empty, so no `X-Tec-Tac-Audit` header is set. A 204 on a chunk read is relayed with no row. An operation without a transfer role is audited exactly as before: a 408 on a change still writes `custom:operation-failed`, and a 204 on a DELETE still writes its success row. No existing audit coverage shrinks.
- `describe()`, `list_operations`, `get_operation` and the exported metadata show `binary_body`, `binary_response` and `audit.transfer`. The metadata adds `limits.binary_body_bytes`, `transfer_roles`, `transfer_directions`, `declaration_keys_added_in_1_18_0`, `refusal_codes_added_in_1_18_0` and `behaviour_added_in_1_18_0`.
- What Remote Background does next (its own request, see below): declare the ten file operations with their roles, set `chunk_size` to at most 4 MiB in the init bodies, call `read_binary_body` in its upload route, split Tactical's cancel route by `body_selector`, and pass no `correlation_id` on transfer operations.

## Closes

- ORDER "Core 1.18.33, file browser part 2: binary chunk relay and one audit row per transfer" in `reviews/requests/core.md` (Johan, 21 November 2026, AD-69), all four asks. The release manager removes that entry, naming 1.18.33.

## What changed and why

- `framwork/tec_tac/tactical_operations.py`:
  - New constants `MAX_BINARY_BODY_BYTES`, `BINARY_RESPONSE_HEADERS`, `TRANSFER_ROLES`, `TRANSFER_DIRECTIONS`. `CAPABILITY_VERSION` is 1.18.0.
  - `TacticalOperation` gains `binary_body`, `binary_response` and `audit_transfer`. `register_tactical_operation` gains the two keywords (after `path_query_params`) and the `transfer` audit key. New `_parse_transfer`.
  - `run_tactical_operation` gains the keyword-only `binary_body`. New helpers `_clean_binary_body`, `read_binary_body`, and the transfer helpers (`_transfer_session`, `_transfer_meta`, `_end_row_extra`, `_end_row_once`, `_end_row_forget`). `_build_request` sends the chunk and always drops an inbound `HTTP_CONTENT_RANGE`. `_write_core_refusal` takes an optional extra for the transfer metadata.
  - Step 8 (the status branches) has a new first branch for a transfer operation answered 408, and the success branch decides per role whether a row is due. The header relay adds the three binary-answer headers.
  - `tactical_operations_contract_metadata()` carries the new keys.
- `framwork/tec_tac/tactical_operation_views.py`: unchanged. A binary operation reached over the JSON route is refused by the executor, and the relay of `result.headers` already carries the three new headers.
- `docs/tactical-operations.md`: header (1.18.0) and a section "File transfers: a binary chunk, a binary answer and one audit row per transfer (1.18.33)". `framwork/tec_tac/contracts.py`: an "Added in 1.18.33" paragraph on the `run` contract text.
- `tests/release-integrity.sh` runs the new test before every pack.
- Version 1.18.33 in `VERSION` and `tec_tac_package.json`.
- Works on Tactical 1.5.2: nothing here calls a new Tactical route. Remote Background registers no file operation on a 1.5.2 server, because Core refuses the unknown `can_use_file_browser` flag.

## Assumptions

- **Chunk upload is for a module's backend only.** `read_binary_body` plus `run_tactical_operation(binary_body=)`. It is not on Core's generic HTTP route. That route is throttled per minute and per day and carries a JSON envelope with an 8 MiB ceiling, so a 256-chunk upload would hit the throttle. Binary downloads (GET chunk) work on both.
- **204 and 408 are quiet only for an operation that declares a transfer role.** Every other operation keeps its rows.
- **One end row per session**, with Tactical's shared cache as the once-only guard. If the cache is down, a repeated `complete` can write a second end row. A missing end row is worse than a repeated one.
- **An extract that finishes on its own has no end row.** Tactical 1.6.1 has no `complete` call for extract. The agent reports done through its own callback and the browser only polls. This release writes the extract start row and the cancel or fail end row. A later release can write the end row when a status read first shows a terminal state, guarded by the same once-only key. Not built: it is outside the four asks.
- **The new refusal codes write no row.** `invalid_content_range`, `binary_body_required`, `binary_body_not_allowed`, `length_required`, `content_length_mismatch` and `body_too_large` for a chunk. Say if AD-19's "a Core pre-dispatch refusal writes a row" should cover them.
- **Two small differences from the plan.** The correlation id `transfer:<session id>` is 45 characters (the plan said 44); it passes the existing shape check. The helper has one code the plan did not list, `content_length_mismatch`, for a body that is shorter or longer than its `Content-Length`. `read_binary_body` is a direct import like `register_tactical_operation`, not an operation of the capability provider, so the capability's `operations` list is unchanged.
- The Tactical behaviour (UploadFileChunk reads `request.body` and `HTTP_CONTENT_RANGE`; the download chunk answers 204 when not ready, else 200 with the three headers; 408 is `notify_retryable`) was read from the 1.6.1 reference only. It did not run here.

## Retired or changed checks

- `tests/version-1.18.32.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.32.md` moved to `docs/releases/`. Release integrity allows one root note.
- Twenty-two existing tests that pinned capability 1.17.0 now pin 1.18.0. The edits are the version text only.
- `tests/tactical-operations-object-field-1.17.21.py` compared the whole `describe()` audit object and key set. It now expects the new `transfer` and `binary_body` / `binary_response` keys.
- `tests/tactical-operation-file-browser-routes-1.18.30.py`: the module scan assumed no module used `path_query_params` or a uuid route. Remote Background now does, which is what 1.18.30 was for. The scan now allows that one module and skips the file routes it owns now. The test failed on the 1.18.32 source before this change.

## New tests

- `tests/tactical-operation-file-transfer-1.18.33.py`: registration of the three new keys and every refusal; `read_binary_body` (Content-Length first, 411, 413 before any read with a stub stream that counts reads, short and long bodies, never `request.body` or `request.data`, a wrapped request); a 4 MiB chunk reaching Tactical's view byte for byte with its headers; 4 MiB plus 64 KiB passing and one byte more refused; more than twenty-five bad ranges; the required and not-allowed codes; scope before range; a stray inbound `Content-Range`; the JSON route refusing a chunk; the three relayed headers and their shape check, the 25 MiB cap, and the HTTP route; 408 and 204 for transfer roles and unchanged for ordinary operations; the rows of a whole upload (two rows, one correlation id, chunks silent), a download, cancel, fail, archive and extract; end-row dedupe with a working, a raising and a missing cache, and the key released when the row write fails; refusal rows with the session link; init resume and an answer without a session id; no file content, Tactical text or secret in any row; the ten Remote Background operations registering under `agents/{}/files/`; a 1.18.32-style declaration unchanged; `describe()`, metadata, docs and contract text; and a scan of `modules/` for keys the registration no longer takes.
- `tests/version-1.18.33.py`: release bookkeeping, line endings, and the 1.18.33 rebuild-label pattern.

## What could not be run here

Django, Tactical and Redis are not installed on this PC. The new test stubs Django, the cache and Tactical's views. These did not run: a real `manage.py` dispatch of Tactical's `UploadFileChunk` and `GetFileDownloadChunk` views, a real 4 MiB request through nginx and uWSGI, and Django's real cache. Of the Core tests I ran, `startup-imports-1.18.1.py`, `audit-declared-browser-events-1.16.0.py` and `system-update-audit-1.17.67.py` fail the same way on the 1.18.32 source (they pin old pattern text or need `fcntl`, which Windows lacks). Tests that import `accounts` or `tec_tac` from a live Django (`*-runtime-*`, `api-key-audit-runtime`, `module-preferences-audit-runtime`, `server-backup-*`) did not run.

## Johan dev02 checklist

You need Core 1.18.33 on dev02. Remote Background does not use the new keys yet, so steps 1 to 3 run a small test operation from a Django shell (`manage.py shell`) as a signed-in test user. Step 6 needs no code.

1. Update dev02 to Core 1.18.33 and check the version.
   - PASS: `VERSION` and the package say 1.18.33, and Core starts with no error in the log.
   - FAIL: the update stops or Core does not start. Send the update log.
2. Declare a test upload with `init`, `chunk` and `complete` roles on an agent route that Remote Background owns, send an init, three chunks and a complete, then open the audit log.
   - PASS: exactly two rows for the transfer, `transfer_stage` start and end, both with correlation id `transfer:<session id>`, and no row for the chunks.
   - FAIL: a row per chunk, a different correlation id on the two rows, or a missing end row. Send the rows.
3. Send a chunk that Tactical answers 408 (stop the agent mid-transfer so Tactical answers "retry"), and read a download chunk before the agent has pushed data (Tactical answers 204).
   - PASS: the 408 and the 204 come back as they are, and the audit log gets no new row for either.
   - FAIL: a `custom:operation-failed` row for the 408, or an error instead of the 204. Send the answer and the log line.
4. Send the same `complete` twice, then a `cancel` for the same session.
   - PASS: the audit log holds one end row for that session.
   - FAIL: two end rows. Send both.
5. Send a chunk with a wrong `Content-Range` (end past the total), and a body larger than 4 MiB plus 64 KiB.
   - PASS: 400 `invalid_content_range` for the first and 413 `body_too_large` for the second, Tactical's log shows no call, and the audit log gets no row.
   - FAIL: either request reaches Tactical, or a row appears. Send the response and the log.
6. On a Tactical 1.5.2 server, use Core as you did before this release (list agents, run a script, open Remote Background).
   - PASS: everything works as on 1.18.32.
   - FAIL: any new error. Send the message and the time.

## Exit list

- `binary_body`, `read_binary_body`, `binary_response`, `audit.transfer`, the 204 and 408 rule, metadata, docs, contract text, tests: done.
- Real Django dispatch, real 4 MiB request through nginx, signing and review: not done here (pipeline, dev02).
- Not done: Remote Background parts (b) to (d) (its own request in `reviews/requests/remote-background.md`), the extract end row for an extract that finishes on its own (see Assumptions), a chunk upload on Core's generic HTTP route, the WAF allowance for `/api/v3/file-transfers/` and a 17 MiB body limit (server module work), and the other open requests in `reviews/requests/core.md`. The refreshed `docs/contracts/tec-tac-public-contracts*.md` is generated on the server after install.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
