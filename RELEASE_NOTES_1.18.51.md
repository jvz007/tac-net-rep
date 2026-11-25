# Tec-Tac Framework 1.18.51

Date: 25 November 2026. Access events are now Core-internal. Core 1.18.50 offered them to every module, which the review found wider than any signed decision. This release withdraws that, checks who calls each access-event function, and closes the Low finding on small DATA frames. It is a Core-only change. `main` stays held.

## Module-facing change

This release removes things 1.18.50 added. No module in `modules/` used them (a search of `modules/` for `access_events`, `access_changed`, `changed_at` and `mark_changed` finds nothing), so nothing breaks. The removal is stated here because it changes a published contract.

- `core.access_events` 1.0.0 is no longer registered. `has_capability('core.access_events')` answers no. Its two contract rows (`access_changed` and `changed_at`, area `access-events`) are gone from the contract export, and so is the public Signal `tec_tac.access_events.access_changed`. No module may connect to, read or raise access events.
- `networkprobe` needs nothing. Core's own tunnel relay reads its own marker, and `set_tunnel_site` still moves a probe's site exactly as in 1.18.50 (`core.probe_transport` 1.2.0 is unchanged).
- Tunnel DATA frames with less than 512 bytes of payload now count against the 2000 a second control budget (`FRAMES_PER_SECOND_MAX`), not the 10000 DATA budget. A probe or Console that sends many small DATA frames must stay under 2000 a second in total with its ACKs and other control frames. A bulk copy (frames of 512 bytes or more) and interactive typing are unaffected. The limits metadata gains `small_data_payload_bytes` (512) next to `data_frames_per_second`. For `probe-developer` and `networkprobe`: the tunnel sender must batch tiny writes (a typing burst is fine, a loop of 1-byte writes is not). The over-rate end row is the same as before: `protocol_error`, detail `rate_control`.

Johan decided on 25 November 2026 (in chat, recorded in `reviews/questions/core.md`) that modules may listen only in a declared form. That form is built the first time a module needs it. Until then access events stay Core-only.

## Closes

- Held 1.18.50 review finding 1 (Medium): `core.access_events` gave every module a cross-user read without a signed decision.
- Held 1.18.50 review finding 2 (Medium): the Signal was exposed, and `notify_access_changed` and `mark_changed` had no caller check.
- Held 1.18.50 review finding 3 (Low): DATA frames were bounded at 10000 a second with no minimum payload.
- The request "core: tell modules when a person's scope or permissions change" stays closed in `reviews/requests/_history/core.md`. Core 1.18.50 built it Core-internal and Core 1.18.51 keeps it Core-only pending Johan.

## What changed and why

1. **Access events are Core-internal (finding 1).** `apps.py` no longer registers a capability and keeps only its guarded block that connects the receivers. `AccessEventsProvider`, the registration function, the metadata function and the operation list are deleted from `access_events.py`. The two contract rows are deleted from `contracts.py`, and the guidance sentence now says plainly that access events are Core-internal, that no module may connect, read or raise them, and that a form for modules is not built yet (Johan's 25 November 2026 decision: declared, built when a module first needs it). The tunnel scope sentence no longer names the capability. The receivers on Tactical's models, the markers and the 5-second Console check work as before.
2. **The Signal is private and callers are checked (finding 2).** The Signal is now `_access_changed`. There is no public Signal name. Core has no consumer of it today, and the receivers still send to it, so a Core consumer can be added later. Each function checks its caller from the call stack, by the real path of the first frame outside `access_events.py`:
   - `notify_access_changed` accepts only Django's own signal dispatcher, which is how Core's model receivers run.
   - `mark_changed` accepts only `probe_tunnel.update_site`.
   - `changed_at` accepts only `probe_tunnel.access_changed_at`, the function Core's Console already uses.

   Any other first caller is refused. That covers module code, a `threading` target and a `functools.partial` that Core's Scheduler runs, because the allow-list is positive: only the named Core callers pass. A refusal returns 0 (a writer) or `None` (the reader), writes nothing, sends nothing, and logs one warning a minute at most. The reader logs at debug only, because it runs every tick. When a warning is due, Core also names whether a verified module made the call (the identity helper of `tec_tac.caller_identity`), without naming the module or any person. If the check cannot be completed (a path read fails, the stack is unavailable), it refuses. The 5-minute re-check stays the backstop. The hot path does no disk scan: a Core caller is recognised by file path, and the module lookup runs only when a refusal is logged. A private test seam (`_allow_caller_for_tests`) lets tests name an allowed caller. Nothing in Core calls it.
3. **What is enforced, and what is not.** Ordinary calls from module code are refused by caller. Hostile code is a different matter. Code that reaches private underscore names, forges a file name, calls Django's own model signals itself or writes the shared cache key directly is not stopped here. Signed-module review is the defence for that, the same limit as `docs/caller-identity.md`. Every document says so, and none claims an absolute block without that limit.
4. **Small DATA frames count as control (finding 3).** New `DATA_SMALL_PAYLOAD_BYTES = 512` in `probe_tunnel.py`. In `_rate_exceeded`, a DATA frame with a payload under 512 bytes (`len(frame) - HEADER_LEN`) counts against `FRAMES_PER_SECOND_MAX` (2000, detail `rate_control`). Only DATA frames of 512 bytes or more count against `DATA_FRAMES_PER_SECOND_MAX` (10000, detail `rate_data`). So a flood of 1-byte frames ends the session at 2000 a second and no longer hides in the 10000. The check is still in memory, makes no cache call and runs before `check_frame`. The limits comment, the contract metadata (`small_data_payload_bytes`, and the 1002 text) and `docs/probe-transport.md` say so.
5. **Documents.** `docs/access-events.md` is rewritten (Core-internal, not a capability; the reasons, markers and backstop are kept; the module rules are removed; "what is enforced" and "what is not enforced" are added). The "Core access events" section of `docs/capabilities.md` is a short statement that it is Core-internal and not registered. `docs/probe-transport.md` and the tunnel metadata name the marker as Core's own.

## Assumptions

No new question for Johan: his answer of 25 November 2026 already covers the module-facing form. The assumptions are recorded in `reviews/questions/core.md` as information.

- **Module-facing form (already decided by Johan, 25 November 2026):** he chose the declared form (option C: the manifest names it, the review checks the reason, the admin sees it at install) and said it is built the first time a module needs it, with Core 1.18.51 shipping Core-only. This release follows that: Core-only. When it is built it will be a registered capability limited to declared callers, with a connect wrapper and no Signal object. `networkprobe` does not need it.
- Core's allow-list is positive (Django's dispatcher, `update_site`, `access_changed_at`), plus the module-identity helper for the log wording. Refusing a legitimate event on a read fault is acceptable because the 5-minute re-check is the backstop.
- 512 bytes is the threshold the review suggested. No byte-rate bound is added, because the 128 KiB stream window already bounds bytes.
- A refused caller gets 0 or `None` and a rate-limited log line, never an exception, so a stray call cannot break Tactical's own save.
- AD-54 (the caller-identity decision) is unchanged. No new trusted purpose and no new global read is added; this release narrows one.

## New tests

- `tests/access-events-1.18.51.py` (new): the capability, provider, public Signal and contract rows are gone; `apps.py` has no registration call; calls from a plain frame, a stub module frame, a `threading` target and a `functools.partial` are refused (0 or `None`, no marker, no signal); Django's dispatcher stand-in, `update_site` and `access_changed_at` are accepted; the real receivers still stamp markers and send the private signal through the dispatcher path; 100 refused calls write nothing and log one warning a minute; a fault in the check refuses; documents and metadata say Core-internal and offer nothing to modules; CRLF kept in `apps.py`, `contracts.py` and `capabilities.md`, LF in `access_events.py`.
- `tests/probe-tunnel-limits-1.18.51.py` (new): 2000 one-byte DATA frames pass and the 2001st ends `rate_control` on both sides; 511-byte payloads count as small and 512-byte as big; 10000 big frames pass and the 10001st ends `rate_data`; mixed DATA and ACK cases; a new second resets both windows; no cache call; the rate check still runs before `check_frame`.
- `tests/version-1.18.51.py` (new): release bookkeeping and line endings. `version-1.18.50.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.50.md` to `docs/releases/`.
- Changed: `tests/access-events-1.18.50.py` and `tests/tunnel-scope-recheck-1.18.50.py` (they run as an allowed Core caller through the test seam and read the private Signal), `tests/probe-tunnel-limits-1.18.50.py` (its DATA cases use 512-byte payloads) and `tests/probe_transport_harness.py` (the private Signal name and a stack-aware caller stub for `access_events`).

## What could not be run here

- Django is not installed on this PC, so `manage.py check` and anything that imports Django did not run. The real Django signal dispatcher (`django/dispatch/dispatcher.py`) was not available: the tests compile a stand-in under a dispatcher file name, which is exactly what the check reads. Whether the real dispatcher frame is the first frame outside `access_events.py` when Tactical saves a model is confirmed on dev02 (checklist step 1). Tactical's real `Role` and `User` models, `channels_redis`, Redis and uvicorn were not available either.
- `ruff` runs with the repo's config where it is installed; see the report for the result.
- No migration and no model change.

## Johan dev02 checklist

Update dev02 to Core 1.18.51 from the dev branch. No migration. Restart the web workers and the ASGI service. Steps 1 and 2 need networkprobe 0.2.24 for the scope part; step 3 runs on any tunnel.

1. Open a tunnel session as an engineer. In Tactical, remove that client from the engineer's role while the session is open.
   - PASS: the session ends within about 10 seconds (this proves Core's receivers still pass the caller check through Django's real dispatcher).
   - FAIL: it is still open after one minute. Send the Core log. A line "access_events.notify_access_changed refused a caller" is the sign of this finding.
2. Check the Core log after step 1.
   - PASS: no "refused a caller" line from `access_events`.
   - FAIL: a "refused a caller" line from a call that should be Core's. Send that line.
3. Copy 10 MiB through the tunnel in both directions, then type in a session.
   - PASS: the bytes match and nothing ends `protocol_error`.
   - FAIL: a session ends `protocol_error`. Send the end row (its detail says `rate_control` or `rate_data`).

## Exit list

- Version 1.18.51, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change. `docs/contracts` is not edited (the export runs on dev02 after signing).
- Release manager: after signing, export the public contract for 1.18.51 on dev02. It no longer lists `core.access_events` or its two rows. The three held 1.18.50 review findings are not in `reviews/core/BACKLOG-new-findings.md`, so nothing is removed there.
- Left out on purpose: the declared module-facing access event (built when a module first needs it); the Engineer Console certificates; the tunnel check-in frame (on hold); making `site_id` required (after networkprobe 0.2.24 ships); the installer change for `--ws-max-size` and `X-Forwarded-Proto`; every other open Core request.
- `reviews/requests/networkprobe.md` needs no new entry. Its note about `scope_lost` and `set_tunnel_site` stays true.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it. Tunnels stay dev02-only until networkprobe 0.2.24 ships.
