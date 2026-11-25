# Tec-Tac Framework 1.18.49

Date: 25 November 2026. This release hardens the Network Probe tunnel relay after the 1.18.48 review. A frame can no longer vanish when the other side is slow: the session ends with a clear reason instead. Core also bounds the frame rate on each tunnel socket, ends an orphaned session from the probe socket, and drops the target address from the ticket audit row. It is a Core-only change. `main` stays held.

## Module-facing change

No function, signature, close code, ticket field or reason list changes. `core.probe_transport` stays at 1.1.0 with the same nine operations, the same two routes, the same wire frames and the same `tunnel.closed` event. `networkprobe` (the only user in `modules/`; it imports no private Core path), the probe and the Engineer Console need no change.

What you can see:

- A peer that cannot keep up now ends the session `relay_overloaded`. Before, Core could lose frames without a word.
- More than 2000 messages in one second on one tunnel socket ends the session `protocol_error` (close 1002, ended by `core`). A real stream stays far below that.
- The probe socket now ends an orphaned session at the idle limit plus 30 seconds, or at the hard cap plus 60 seconds, when the Console's worker has died. It writes the end row and `tunnel.closed` itself with the last flushed counters.
- The `custom:probe-tunnel-ticket` row no longer has a `target` key, and no tunnel audit row can carry one. `target_label` is still accepted in the spec and kept in the session record. Nothing in `modules/` reads the key from Core's row; `networkprobe` audits the address itself.
- Frames now wait a little longer in one case: the probe side holds output (up to 1 MiB) until the Console's channel is known. The wire frames are byte for byte as before; Core still reads only byte 0 and the length.

## Closes

- M2 (Medium), tunnel relay silently drops frames when the peer's channel is full.
- L2 (Low), the 15-second pair wait ending a drain that is still running. This is also the held Low of 1.18.48 in `reviews/core/BACKLOG-new-findings.md`.
- L3 (Low), the probe's data socket had no idle or hard-cap timers of its own.
- L4 (Low), no bound on the frame rate of a tunnel socket. The message-size part is a hosting-stack setting; see Assumptions.
- L5 (Low), the 4403 plain-text guard depends on `X-Forwarded-Proto`. Documented only.
- L8 (Low), the ticket audit row could carry the target address although the docs say it never does.

## What changed and why

1. **Frames go to the peer's own channel (M2).** `channels_redis` 4.3.0 `group_send` never raises `ChannelFull`: when a member holds 100 messages it skips the message and logs at info level. Capacity cannot be raised for the `tectac-pnt-` prefix, because specific channel names are random and Tactical's settings are not Core's. So `_forward` now uses `channel_layer.send` to the peer's channel name, which does raise `ChannelFull`. `ChannelFull`, a send over 5 seconds or any layer error ends the session `relay_overloaded` and the frame is never dropped. The group carries only `tunnel.paired` and `tunnel.end`.
2. **Peer discovery is symmetric (M2).** After `accept` and `group_add`, each side writes its ready marker with its own channel name (`probe_ready` as before, new `console_ready`), sends `tunnel.paired {side, channel}` to the group, then looks at the other side's marker. This is the join-then-look argument of 1.18.48, now for both sides, so either the marker or the message is seen. `probe_tunnel.py` gains `SIDE_CONSOLE_READY`, `mark_console_ready`, `mark_probe_ready(session_id, channel)`, `clean_channel` and `ready_channel`; a name must match `^[A-Za-z0-9._!-]{1,200}$`. `poll_session` also returns `console_channel`. Both watchers keep polling the peer's marker while unpaired as the backstop. "Paired" now means the peer's channel is known.
3. **One pairing and buffering routine in the base class (M2).** The 1.18.48 buffer, `_paired`, `_pairing` and `_complete_pairing` moved to `_TunnelConsumer`, so the probe side also holds frames (same 1 MiB `BUFFER_CAP_BYTES`) until the Console's channel is known. Over the cap the probe side ends `console_not_connected`. The Console side keeps `probe_offline`.
4. **A sequence number per direction (M2).** The layer message is `{type: tunnel.frame, side, seq, data}`. The receiver checks `seq` against the next expected number; any gap, repeat or reorder ends the session `relay_overloaded`. This covers what `ChannelFull` cannot: a message the layer expired after 60 seconds in a stalled consumer's queue, or a Redis flush. The number is internal to the layer message. A lost final frame is noticed at the next frame or at the idle limit.
5. **The pair wait spares a live drain (L2).** The 15-second check is now `not _paired and not _pairing and elapsed >= PAIR_WAIT_SECONDS`. The drain is bounded (1 MiB, 5 seconds a send), so it cannot hang. The probe side uses the same rule: a Console that is attached but whose channel stays unknown ends the session `console_not_connected` 15 seconds after the first tick that saw it.
6. **Backstop timers on the probe socket (L3).** The probe consumer tracks the last DATA of either direction once paired and ends `idle_timeout` after the Console's idle limit plus `BACKSTOP_IDLE_GRACE_SECONDS` (30). It ends `hard_cap` when the record's creation time plus the cap plus `SLOT_GRACE_SECONDS` (60) has passed. Both are later than the Console's own timers. A backstop end has the probe consumer write the end row (`end_audit` reads the last flushed counters) and deliver `tunnel.closed`. Both are `cache.add` guarded, so a live Console never produces a second row.
7. **A frame-rate bound (L4).** `FRAMES_PER_SECOND_MAX` (2000) messages in a one-second window on the injected monotonic clock, counted in memory (no cache or database call) and checked before the frame check, on both consumers. The next message ends the session `protocol_error`.
8. **No target in tunnel audit rows (L8).** `target` is removed from the ticket row in `issue_ticket` and from `TUNNEL_AUDIT_KEYS` in `probe_transport.py`. The docs sentence "Never a ticket, key, header, payload or target address" now holds.
9. **Docs (L5).** `docs/probe-transport.md` describes the relay, the pairing, the sequence check, the 60-second Redis residual, the two new constants and the hosting-stack facts: the 4403 guard reads `X-Forwarded-Proto`, which Tactical's nginx `/ws/` block does not set (nothing is exposed today); payload bytes pass through Redis only while relayed and are never stored.

## Assumptions

None needs Johan; nothing widens trust. They are in `reviews/questions/core.md` as information.

- A lost frame ends the session `relay_overloaded`. No new reason name, so no contract change.
- Probe-side frames before the Console's channel is known are held up to 1 MiB, then `console_not_connected`.
- The backstop grace is 30 seconds. The Console's tick and flush are 5 seconds, so the Console's own clock fires first in normal running.
- Message size (L4): Tactical 1.6.1 runs uvicorn 0.53.0 with websockets 13.1 (`requirements.txt`; `install.sh` starts it without `--ws-max-size`, in a unit still named `daphne.service`). The default limit is 16 MiB per message, not unlimited as the review assumed. A 1.5.2 server runs Daphne and was not verified here. Core can only check a message after the server has buffered it, so the real bound is a hosting-stack setting. Core keeps `check_frame` first and adds the frame-rate bound. An installer change is not part of this release; the question is recorded.
- A frame sent to a peer that has already disconnected waits in Redis until the layer expires it (60 seconds). This is documented.

## New tests

- `tests/probe-tunnel-hardening-1.18.49.py`: a full peer channel in both directions (the 101st frame ends `relay_overloaded`, the 100 held frames arrive in order, nothing is sent after the end); a lost DATA, ACK and CLOSE, a repeat, a reorder and unusable numbers all end `relay_overloaded`; no frame goes through `group_send` (runtime and source scan); peer discovery in both connect orders, a lost `tunnel.paired` recovered by each watcher, malformed channel names refused; probe-side holding, drain order and the cap; a 10 MiB echo byte for byte; a drain held across the 15-second mark; the probe's idle and hard-cap backstops, DATA and non-DATA, a live Console firing first with one row and one event; the 2000 frames a second limit with no cache call; no target in any audit row; the docs.
- `tests/version-1.18.49.py`: release bookkeeping and line endings. `version-1.18.48.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.48.md` to `docs/releases/`.
- Changed: the 1.18.47 relay test (the `ChannelFull` case uses `send`; four `data[0]` reads), the 1.18.47 ticket and end tests (no `target`), the 1.18.48 pairing test (channel names, markers) and the harness `FakeLayer` (`send` delivers like `group_send`, can hold a channel up to 100 messages and raise `ChannelFull`, and can drop a message).

## What could not be run here

- Django is not installed on this PC, so `manage.py check` and anything that imports Django did not run. `channels_redis` is not installed either. The tests run on the in-memory harness and stubs, so nothing ran against a real Redis layer, a real expiry or uvicorn.
- The real `ChannelFull` of `channels_redis` is modelled by the harness at 100 held messages.
- No migration and no model change.

## Johan dev02 checklist

Update dev02 to Core 1.18.49 from the dev branch first. No migration; restart the ASGI service. The steps need `networkprobe` 0.2.21 or later, a probe with the P2 build and the Engineer Console.

1. Open a session from the Console and type a command at once.
   - PASS: the first command and its output arrive complete, every time, over several tries.
   - FAIL: a missing first line or a stuck session. Send the Core log and the Console message.
2. Copy 10 MiB through the tunnel in both directions.
   - PASS: the bytes match on both sides.
   - FAIL: corrupted or missing bytes, or a session that ends `relay_overloaded`. Send the Console message and the Core log.
3. Open a session, then stop the probe service on the device and wait for one minute.
   - PASS: the session ends and the audit shows one end row.
   - FAIL: the session stays open, or there are two end rows. Send the audit rows.
4. Open the ticket row in the audit log for a new session.
   - PASS: the row has the engineer, the session id and the permission, and no target.
   - FAIL: a target address in any tunnel row. Send the row.

## Exit list

- Version 1.18.49, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change. No change to `docs/contracts` (the export runs on dev02 after signing).
- Release manager: after signing, remove the 1.18.48 Low "Watcher can end the session probe_offline during a drain that is still running" from `reviews/core/BACKLOG-new-findings.md`, naming Core 1.18.49, and export the public contract for 1.18.49 on dev02.
- Left out on purpose: M1, L1 and L6 (networkprobe, filed as ORDER networkprobe 0.2.23); M3, L9 and L10 (Engineer Console) and L6 and L7 (probe), filed in `reviews/requests/_unsorted.md`; an installer change for `--ws-max-size` and `X-Forwarded-Proto`; a Console-liveness heartbeat in the probe watcher; every other open Core request.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it.
