# Tec-Tac Framework 1.18.47

Date: 25 November 2026. Core gets the tunnel of the probe channel (C2): an engineer's desktop tool, the Engineer Console, can reach a device behind a Network Probe through Core, with Core relaying the traffic and never reading it. It adds four operations to `core.probe_transport` (1.0.0 becomes 1.1.0), two websocket routes, the session limits and the end and status calls. It also closes the two held Lows of 1.18.46 on the probe route. Nothing is on until `networkprobe` calls `issue_tunnel_ticket`. `main` stays held.

## Module-facing change

`core.probe_transport` 1.1.0 (framework >=1.18.47) is a pure addition on 1.0.0. The five 1.0.0 operations, their results, the control route `/ws/tfd/network-probe/` and its close codes are unchanged. `networkprobe` is the only user and the only module Core lets register as owner or call any operation. In `modules/`, only `networkprobe` 0.2.20 (M1) uses the contract, and it uses 1.0.0 operations only, with the same signatures, so it keeps working. `networkprobe` 0.2.21 (M2) builds the tunnel on the new operations, and the probe (P2) and the Console (E1) build against `docs/probe-transport.md`.

New operations, all sync, all verified from the call stack (`module_id` must equal the verified caller; anything else gets `outcome: denied`):

- `issue_tunnel_ticket(request, module_id, spec)` returns `{outcome: ok, ticket, launch_url, expires_in: 60, session_id}` or `{outcome: denied, invalid, rate_limited, limit_reached, probe_offline, session_exists or unavailable, code, message}`. `request` is the engineer's signed-in Tec-Tac request. `spec` is `{session_id (uuid4), probe_id, permission (networkprobe.*), target_label, idle_s, cap_s}`.
- `end_tunnel(module_id, session_id, ended_by)` with `ended_by` of `engineer`, `admin` or `core`.
- `end_tunnels_for_probe(module_id, probe_id, reason)`. The owner calls it when a probe is disabled or revoked. `disconnect()` still ends no tunnel by itself.
- `tunnel_status(module_id, session_ids=None, probe_id=None)`, from the cache, up to 200 ids.

New events to the owner's event task: one `tunnel.closed` per session, `(probe_id, frame)` with `payload {session_id, reason, ended_by, bytes_up, bytes_down, source: "core"}`. The probe's own `tunnel.closed` still arrives through the normal path. Core sends `tunnel.close` to the probe on the control channel on every end. Core never sends `tunnel.open`: the owner does, through `request()`, after `issue_tunnel_ticket`. The owner checks the person's scope and the port rules; Core re-checks the account and the permission only.

Four new rows in `CORE_CONTRACTS` (area `probe-transport`). Two new routes: `/ws/tfd/probe-tunnel/` (Console) and `/ws/tfd/network-probe/tunnel/` (probe). Wire details, limits, close codes and reasons: `docs/probe-transport.md`, section "The tunnel (contract 1.1.0)".

## Closes

- `reviews/requests/core.md`, "core: probe transport C2" (Johan signed the plan, 19 November 2026): C2a to C2d.
- The two held Lows of 1.18.46 on the probe route: `probe_transport_consumer.py` `json.loads` of nested `[` (RecursionError) and `probe_transport.py` pool sizing (C2e).

## What changed and why

1. **`probe_tunnel.py` (new).** The ticket store, the session index and its limits, the per-session cache records, the account re-check, the end of a session, the launch link and the two route classes. A sibling of `probe_transport.py`; it imports nothing from `endpoint_transport` (AD-54). Its own cache prefixes (`tec-tac:pt:ticket:` and `tec-tac:pt:tun...`), group prefix (`tectac-pnt-`) and audit actions (`custom:probe-tunnel-*`).
2. **Ticket.** `secrets.token_urlsafe(32)` (43 characters), stored only as its SHA-256, 60 seconds, once. `launch_url` is `tectac-console://open?host=<host>&ticket=<ticket>`, as the Console's `link.rs` reads it. Order of checks: signed-in request and Knox digest, spec, permission, probe presence, 10 tickets a minute per engineer, then the slots under one short cache lock: 50 sessions in all, 5 per probe, 3 per engineer. A slot is held from the ticket until the session ends. Each entry has an expiry, so a leaked slot heals. No shared cache (a dummy cache) means `unavailable` and no ticket. One ticket per session id, no resume. Every refusal writes one deny row and never the ticket.
3. **Two data routes (`probe_tunnel_consumer.py`, new).** Binary only, no Origin rule, plaintext 4403, accept first and close with the code and the reason name as the close text. Console side: `Authorization: Ticket <43>` (a `Probe` or `Token` header is 4401 `wrong_scheme`), redeem once, account re-check at connect (user active and not blocked, Knox token live, `record_terminal_activity` with the last DATA time as activity, permission, module enabled). Probe side: `Authorization: Probe <id>.<key>` through the same `authenticate_probe` and failure counters as the control route, plus `X-Tunnel-Session` naming a pending session of that probe (4404 unknown, 4409 already attached). Each route is installed in its own guarded block in `apps.py`.
4. **Relay.** Both sockets join `tectac-pnt-<session_id>` and forward frames with `group_send`, tagged with their side. Core reads byte 0 (1 to 4) and the length (5 up to 5 + 32 KiB) and nothing else; anything else, and any text frame, ends the session with close 1002. The Console's frames wait in a buffer of at most 1 MiB until the probe side attaches (15 seconds, then `probe_offline`). `ChannelFull` or a send over 5 seconds ends the session `relay_overloaded`. Only DATA frames reset the idle timer and count bytes (`bytes_up` is Console to probe). No frame, byte or stream id is logged, audited or stored.
5. **Watcher.** The Console's consumer ticks every 5 seconds: `idle_timeout` after `idle_s` with no DATA, `hard_cap` after `cap_s`, counters written to the cache every 5 seconds and at the close, and every 5 minutes (up to 30 seconds of jitter) the account, permission, module and probe presence or data socket are checked again. A lost right ends the session `ended_by_core`. The probe side waits 60 seconds for the Console (`console_not_connected`) and checks its own identity again every 5 minutes.
6. **End.** The first end wins through `cache.add`, so the reason and `ended_by` are written once. Both sockets close at once with the reason as the close text, the probe gets `tunnel.close` on its control channel, the slot is freed. One `custom:probe-tunnel-end` row and one `tunnel.closed` event per session: the Console's consumer writes and sends them at its close with its final counters, or whoever ended the session does it with zero counters when the Console never attached. The control route refusing a probe at its re-check ends that probe's tunnels itself.
7. **Probe route Lows (C2e).** A text frame of 15000 `[` raised `RecursionError` out of `receive()`; it is now one bad frame (`ValueError` and `RecursionError`). The pools are sized like the endpoint route: `auth (6, 256)`, `recheck (2, 4096)`, `cache (6, 2000)`, `audit (3, 800)`, `handover (2, 64)` unchanged. A ceiling of 64 connects in flight before the identity check answers 1013 and counts nothing, on the control route and both tunnel routes.
8. **Audit helper.** `record_probe_event` takes an optional `extra` with a fixed list of field names (`engineer`, `session_id`, `side`, `ended_by`, `detail`, `duration`, `bytes_up`, `bytes_down`, `target`, `permission`). Ints and short clean text only. `audit.py` is unchanged.
9. **Docs.** `docs/probe-transport.md` has the tunnel section and the fleet-size note. `docs/capabilities.md` names 1.1.0.

## Assumptions

None of these needs Johan. They are in `reviews/questions/core.md` as information.

- `issue_tunnel_ticket` also refuses `probe_offline` when the probe has no presence, so no slot or ticket is spent. The owner can still call it only after `presence()` says connected.
- The owner, not Core, sends `tunnel.open`, as with `probe.welcome`. Core sends `tunnel.close` itself, because it must close the probe's target at once.
- Core also delivers its own `tunnel.closed` (`source: "core"`, the Console's byte counters) so the owner's audit row exists even when the probe never reports.
- Pairing: the Console side accepts first and holds at most 1 MiB until the probe side attaches. Close codes: 4401 identity or ticket, 4403 plaintext, 4404 unknown or not pending, 4409 side already attached, 1002 protocol error, 1013 busy or overloaded, 4503 unavailable, 1001 server going away.
- The Console's 5-minute check reuses `record_terminal_activity` with the last DATA time as activity, so the engineer's idle and absolute sign-in limits apply to a live tunnel as they do to a terminal (AD-35).
- Fleet size: up to 500 connected probes. A server shutdown reaches a consumer as close code 1001 or 1012 (what the ASGI server sends); both end the session `server_restart`.

### Plan corrections found in the code

- The plan says the reason list is fixed at 14 names and also asks for close 1002 `protocol_error`. Core adds `protocol_error` as a 15th name for a frame that breaks the rules; the Console shows its general message with the close code for a name it does not know.
- The plan says a probe side with an unknown session closes 4404 and a second side closes 4409. A session that exists but whose probe side is already attached gets 4409; unknown, ended and another probe's sessions get 4404.
- The plan puts the end row in the ender's hands. Bytes are only exact at the Console consumer's close, so an attached Console's consumer writes the row and the event with its final counters (`cache.add` keeps each to one). Cost: a server process that dies without closing its sockets leaves no end row for that session. The slot still heals at its expiry.
- `channels_redis` may drop a message for a full channel without raising. The plan's `ChannelFull` rule is built as written; whether the real layer raises is a dev02 check.

## Retired or changed checks

- `tests/version-1.18.46.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.46.md` moved to `docs/releases/`.
- `tests/probe-transport-contract-1.18.46.py` is now `probe-transport-contract-1.18.47.py` (version 1.1.0, nine operations, the 1.0.0 behaviour checked unchanged) and `probe-transport-docs-1.18.46.py` is now `probe-transport-docs-1.18.47.py` (the "C2 is a later release" check became the tunnel section checks).
- `tests/probe_transport_harness.py` is extended additively (close reasons, bytes frames, `ChannelFull`, a failing layer, the sign-in and permission stubs, tunnel helpers). The 1.18.46 identity, consumer and isolation tests are unchanged and pass.
- `tests/release-integrity.sh` runs the new tests and `version-1.18.47.py`.

## New tests

- `tests/probe-tunnel-ticket-1.18.47.py`: the ticket, its store, the limits and every refusal.
- `tests/probe-tunnel-relay-1.18.47.py`: the two routes and the relay: a 10 MiB echo both ways, the refusals, protocol errors, idle and bytes, each end reason, the buffer, the account re-checks, faults and the route install.
- `tests/probe-tunnel-end-1.18.47.py`: end, end for a probe, status, `tunnel.closed`, the audit rows and no secret anywhere.
- `tests/probe-tunnel-isolation-1.18.47.py`: the tunnel shares nothing with the agent route.
- `tests/probe-transport-hardening-1.18.47.py`: the two Lows.
- `tests/version-1.18.47.py`: release bookkeeping and line endings.

## What could not be run here

- `manage.py check`, Django itself, a real Redis, `channels_redis`, uvicorn and a real websocket. The tests run on stubs and an in-memory channel layer. The sign-in check (`session_refusal`, `record_terminal_activity`), the real permission lookup and the user model are stubbed, so they are exercised on dev02 only.
- The real two-client 10 MiB echo through nginx and Redis (a dev02 step below).
- The contract export for 1.18.47. No contract file exists in `docs/contracts/` yet; the export runs on dev02.
- This release adds no migration and no model.

## Johan dev02 checklist

Update dev02 to Core 1.18.47. Steps 1, 2, 3 (the 4503 half) and 7 work without `networkprobe` 0.2.21. Steps 3 (the 4401 half) and 4 to 6 need the Engineer Console and `networkprobe` 0.2.21 (M2) and a probe with the P2 build.

1. Run `manage.py check`, then restart Core and Celery.
   - PASS: "System check identified no issues (0 silenced)." and no `probe` route or capability error in the Core log.
   - FAIL: any error, or a log line saying a tunnel route failed to install. Send the output and the lines.
2. Open `/api/tfd/capabilities/`.
   - PASS: `core.probe_transport` 1.1.0 is listed with nine operations, including `issue_tunnel_ticket`, `end_tunnel`, `end_tunnels_for_probe` and `tunnel_status`.
   - FAIL: version 1.0.0, five operations, or `core.endpoint_transport` changed. Send the list.
3. Connect to `wss://<dev02>/ws/tfd/network-probe/tunnel/` with `websocat` and a `Token` header, then to `wss://<dev02>/ws/tfd/probe-tunnel/` with a `Probe` header.
   - PASS: while `networkprobe` has not registered an owner, both close 4503. Once it has, both close 4401 with the text `wrong_scheme`.
   - FAIL: any other code, or a hang. Send the output.
4. Open a session from the Console to a device behind a probe, and copy 10 MiB through it in both directions.
   - PASS: the bytes match on both sides, and the end row and `tunnel.closed` show `bytes_up` and `bytes_down` near 10 MiB.
   - FAIL: corrupted or missing bytes, or a close before the copy ends. Send the Console message and the Core log.
5. Use the launch link a second time, after the first session has connected.
   - PASS: the Console is refused with 4401 and the message that the ticket was already used.
   - FAIL: a second session opens. Send the Core log.
6. Press End in Tec-Tac for a live session, then disable the probe with a second live session.
   - PASS: both sockets close at once, the probe drops its target connection, and one `custom:probe-tunnel-end` row exists per session with the reason `ended_by_engineer` or `ended_by_core`.
   - FAIL: a socket stays open, a session has two end rows, or none. Send the audit rows.
7. Check that an Endpoint Agent still connects to `/ws/tfd/endpoint-agent/`.
   - PASS: the agent shows as connected, as before.
   - FAIL: the agent is refused, or Tactical is slow to start. Send the Core log.

## Exit list

- Version 1.18.47, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change.
- Release manager: in `reviews/requests/core.md`, move "core: probe transport C2" to `_history/core.md`, naming 1.18.47. Remove the two 1.18.46 probe Lows (`probe_transport_consumer.py:282`, `probe_transport.py:307`) from `reviews/core/BACKLOG-new-findings.md`. Tell `networkprobe` (M2) and `probe-developer` (P2) that the tunnel section of `docs/probe-transport.md` is their spec. Export the contract file for 1.18.47 on dev02.
- Left out on purpose: every other open Core request and held finding; no Core UI change.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it.
