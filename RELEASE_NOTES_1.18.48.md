# Tec-Tac Framework 1.18.48

Date: 25 November 2026. This release fixes the two held Medium findings of the 1.18.47 review on the Network Probe tunnel. First, the Console's first frames can no longer be lost while the probe is still joining the session. Second, output from the device behind the probe no longer keeps the engineer's sign-in alive. It is a Core-only fix. `main` stays held.

## Module-facing change

No contract, capability, endpoint, close code, ticket or audit change. `core.probe_transport` stays at 1.1.0 with the same nine operations, the same two routes, the same wire frames, the same close codes and reasons, the same audit rows and the same `tunnel.closed` event. `networkprobe` (the only user in `modules/`), the probe and the Engineer Console need no change.

Two behaviours you can see:

- The Console may now wait a few milliseconds longer for the probe to join the session. Core holds its first frames meanwhile and sends them in order, so none are dropped. This is the only timing difference.
- The engineer's sign-in idle timer (rule 1.8, AD-35) now follows the engineer's own input only. A target that streams output no longer keeps the sign-in alive. The tunnel's own idle timer (`idle_s`) still counts DATA in both directions, as before. There is no audit row, no contract field and no close reason for this (no audit change); a session ended by the sign-in idle limit ends `ended_by_core`, as any other sign-in refusal does.

## Closes

- Held Medium 1 of the 1.18.47 review (`probe_tunnel_consumer.py`, pairing race on the relay): the Console counted itself paired as soon as the probe's attach marker existed. That marker is written before the probe socket joins the group, so a frame sent in the gap reached nobody and was lost.
- Held Medium 2 of the 1.18.47 review (`probe_tunnel_consumer.py`, sign-in activity): any DATA frame, including probe-to-Console output, was passed to the sign-in as activity. Rule 1.8 allows only the engineer's own action.

## What changed and why

1. **A second marker, `probe_ready`.** `probe_tunnel.py` has `mark_probe_ready(session_id)` and the side name `SIDE_PROBE_READY`. The probe's consumer writes the marker after `accept()` and `group_add` succeed and before it sends `tunnel.paired`, on the cache pool. The existing `probe` attach marker is unchanged: it is still the 4409 duplicate guard, the input of the `probe_offline` re-check and the status row. `poll_session` now also returns `ready`.
2. **The Console pairs on `probe_ready`.** It still accepts and joins the group first, then looks. It counts itself paired only if the marker exists. If not, the probe's later `tunnel.paired` reaches it, because the Console is already in the group.
3. **One pairing routine.** `_complete_pairing` is used by `tunnel_paired`, by the look at connect and by the watcher. It drains the buffer in order, one frame at a time. It sets `_paired` only when the buffer is empty, with no wait between the check and the set. A frame that arrives during the drain is appended and sent after the earlier ones. A flag stops two drains running at once.
4. **A backstop in the watcher.** While unpaired, each 5-second tick looks at `probe_ready` and completes pairing if it is set. A lost `tunnel.paired`, or a failed cache look at connect, can no longer leave the Console buffering until the 15-second `probe_offline`.
5. **Limits unchanged.** Frames held while unpaired still count against `BUFFER_CAP_BYTES` (1 MiB, then `probe_offline`) and the 15-second wait. The 128 KiB stream window and the 1 MiB in-flight limit are the two endpoints' rules. Core adds no limit and still reads only byte 0 and the length.
6. **Activity.** The Console consumer keeps `_last_data` and `_last_data_wall` as the tunnel's own idle clock and for the stats flush. New `_last_up_wall` and `_up_since_check` are set only by Console-to-probe DATA. The 5-minute re-check passes `activity_at` only from those, and the flag clears after a passing re-check, as before. Probe-to-Console DATA, ACK and CLOSE, and the Console's own ACK, OPEN and CLOSE, never touch the sign-in.
7. **Docs.** `docs/probe-transport.md` rewords "DATA frames count as activity" to the engineer's own DATA, and gains a pairing paragraph.

## Assumptions

None needs Johan; nothing widens trust. They are in `reviews/questions/core.md` as information.

- The Console learns the probe is in the group through a second cache marker, not a handshake frame. A handshake would change the wire protocol the probe and Console build to, and Core must not parse frames.
- Target output does not count as engineer activity (rule 1.8, AD-35). The tunnel's own `idle_timeout` still counts both directions.
- The frame buffer stops where it did: 1 MiB, then `probe_offline`, and 15 seconds.

## New tests

- `tests/probe-tunnel-pairing-1.18.48.py`: the race (attach marker held, probe not in the group, frames in order and none lost), the same under a 10 MiB echo, a frame arriving during the drain, the buffer cap and the 15-second wait, a lost `tunnel.paired` and a failed look at connect recovered by the watcher, both connect orders, a source scan that the Console never reads the `probe` attach marker, and the activity rules (probe-only output passes no activity, the engineer's DATA passes its own time once, ACK-only traffic passes none, a streaming target ends at the sign-in idle limit).
- `tests/version-1.18.48.py`: release bookkeeping and line endings. `version-1.18.47.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.47.md` to `docs/releases/`.
- The 1.18.47 probe tests run unchanged.

## What could not be run here

- Django is not installed on this PC, so `manage.py check` and anything that imports Django did not run. The tests run on the in-memory harness and stubs. The real sign-in check (`session_refusal`) is modelled in the new test, not run.
- A real Redis, `channels_redis`, uvicorn and a real websocket. The end-to-end tunnel test runs on dev02 after this release is signed.
- No migration and no model change.

## Johan dev02 checklist

Update dev02 to Core 1.18.48 from the dev branch first. No migration; restart the ASGI service. The steps need `networkprobe` 0.2.21, a probe with the P2 build and the Engineer Console.

1. Open a session from the Console and type a command at once, as fast as the Console lets you.
   - PASS: the first command and its output arrive complete, every time, over several tries.
   - FAIL: a missing first line or a stuck session. Send the Core log and the Console message.
2. Copy 10 MiB through the tunnel in both directions.
   - PASS: the bytes match on both sides.
   - FAIL: corrupted or missing bytes. Send the Console message and the Core log.
3. Start a command that prints output all the time, and do not touch the keyboard until your sign-in idle limit passes.
   - PASS: the session ends when your Tec-Tac sign-in goes idle, and the end row shows `ended_by_core`.
   - FAIL: the session stays open past that point. Send the audit rows and your idle setting.

## Exit list

- Version 1.18.48, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change.
- Release manager: after signing, remove the two 1.18.47 Medium lines (the pairing race and the probe-to-Console activity) from `reviews/core/BACKLOG-new-findings.md`. No entry in `reviews/requests/core.md` is open for this theme.
- Left out on purpose: every other open Core request and held finding; scoped trusted service context for networkprobe; the secret store; no change to the Console or `networkprobe`.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it.
