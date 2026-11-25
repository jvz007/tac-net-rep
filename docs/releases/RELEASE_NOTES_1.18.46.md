# Tec-Tac Framework 1.18.46

Date: 25 November 2026. Core gets a live channel for the Network Probe: one websocket, `/ws/tfd/network-probe/`, and one new contract, `core.probe_transport` 1.0.0. This is C1 of the probe channel plan. The channel carries small control messages. Bulk data and the outbox stay on HTTPS. Nothing is on until the module `networkprobe` registers as the owner: until then the route answers close code 4503 to everyone. `main` stays held.

## Module-facing change

New contract `core.probe_transport` 1.0.0 (framework >=1.18.46). It is a pure addition. No module in `modules/` uses it yet, and nothing existing changed: `core.endpoint_transport`, its route and its files are exactly as in 1.18.45.

- Operations: `register_owner(module_id, authenticator_path, event_task_path)`, `request(module_id, probe_id, frame, timeout=10)`, `send(module_id, probe_id, frame)`, `presence(module_id, probe_ids)` and `disconnect(module_id, probe_id, reason)`.
- `networkprobe` is the only allowed owner. Core verifies the caller from the call stack. Any other module, Core itself and an unverifiable caller get `outcome: denied`.
- `networkprobe` 0.2.20 (M1) registers an authenticator `authenticate(probe_id, key)` and an event task from `AppConfig.ready()`. The signatures, return values, close codes and reconnect rules are in `docs/probe-transport.md`, so M1 and the probe (P1) can be coded against them.
- Five new rows in `CORE_CONTRACTS` (area `probe-transport`), so the contract export lists them. A fresh export for 1.18.46 is not part of this release.

## Closes

- `reviews/requests/core.md`, "core: probe transport C1 and C2": the C1 half (`core.probe_transport` 1.0.0 and the route). **The C2 half stays open.**

C2 is not in this release: the tunnel relay, the Console ticket, the two data routes, the session limits, `end_tunnel` and contract 1.1.0. It is Core 1.18.47 and builds on C1 once C1 is signed.

## What changed and why

1. **`probe_transport.py` (new).** A sibling of `endpoint_transport.py` that imports nothing from it (AD-54). It has its own prefixes (`tectac-pn-` for groups, `tec-tac:pt:presence:`, `tec-tac:pt:fail:` and `tec-tac:pt:failprobe:` for the cache), its own worker pools (`tectac-pn-*` threads), its own credential parser, owner registry and audit actions. It holds the header parser, the failure limits, the owner registry, the identity check, the frame checks, the presence keys, the route class and the contract.
2. **Credential.** The probe sends one header, `Authorization: Probe <probe_id>.<key>`. The key is the same secret the probe already uses over HTTPS. Nothing goes in the URL. A `Token` header (an agent token) is refused with 4401 and the reason `wrong_scheme`, and it never reaches the owner's authenticator.
3. **Identity.** Core does not know probes. It calls the authenticator the owner registered. The authenticator returns `{probe_id, client_id, site_id}` for an accepted probe, or `probe_unknown`, `probe_disabled` or `probe_key_invalid` for a refusal. Any other answer, a fault, a timeout (10 seconds) or a full pool closes 1013 and is counted nowhere. Core checks again every 5 minutes (with up to 30 seconds of jitter). A refusal closes 4401. A fault keeps the socket until 300 seconds past the deadline, then closes 1013.
4. **Failed attempts.** The numbers are the ones AD-54 signed for the agent route: 10 failed attempts a minute per address (an IPv6 address by its /64) and 10 failed checks a minute per probe id. The per-probe counter is read only after a failed check, so a real probe is never locked out by someone who knows its id. Nothing is widened.
5. **`probe_transport_consumer.py` (new).** Written as its own file, not imported from the agent consumer. Connect order: address ceiling, then no registered owner (4503), then plaintext (4403), then headers, then the identity check, then any per-probe decision. After success: group join, presence (a random owner id, so a newer connection is never mistaken for an older one), a takeover message so an older socket for the same probe closes 4409, and an audit row. The watcher pings every 30 seconds, renews the group, refreshes presence, closes 4408 after two unanswered pings and re-checks the identity. The receive loop never touches the database, the cache or the broker: every blocking call runs on one of the route's own small pools.
6. **Frames.** `{v: 1, type, id, func, payload}` with `type` one of `request`, `reply`, `event`, `ping`, `pong`. At most 16 KiB (1009), 20 frames a second (4429), 20 bad frames then 4400. An event goes to the owner's task as `(probe_id, frame)`. There is no `ack`: events are best effort. A reply is routed only to the request that was delivered to that socket. Core never reads `func`.
7. **Provider operations.** `request` waits for a reply (timeout clamped to 1 to 30 seconds, returns within timeout plus 1, `offline` decided at once from presence). `send` is fire and forget for an event or a reply frame. `presence` reads the cache for up to 2000 ids. `disconnect` closes a probe's socket with 4401 for one of `disabled`, `revoked`, `key_rotated` or `module_disabled`, so the probe stops the channel and keeps its 5-minute HTTPS check.
8. **Wiring.** `apps.py` registers the capability and installs the route in two separate guarded blocks, apart from the agent route. A fault is logged and start-up goes on. A fault in the consumer later closes the socket 4503 and never stops Tactical (rule 1.15).
9. **Audit.** `audit.py` gets `SERVER_PROVENANCE_PROBE_TRANSPORT` and a private `_record_probe_transport`, beside the endpoint one. Rows are non-strict: `custom:probe-connect`, `custom:probe-disconnect` and `custom:probe-refused` (refusals only), module `core`, object type `probe`. The client and site the owner reported are in the metadata. No existing function changed. Never a key, a header or a payload.
10. **Docs.** `docs/probe-transport.md` (new) and a short section in `docs/capabilities.md`.

## Assumptions

None of these needs Johan. They are recorded in `reviews/questions/core.md` as information.

- The frame keeps the endpoint envelope including `v: 1`. The plan names the envelope without `v`. Keeping it lets one frame shape serve both sides. There is no `ack` type on this route.
- The authenticator is a plain synchronous function `authenticate(probe_id, key)` in the owner's own folder. It returns the dict or one of the three refusal codes (the codes `networkprobe` already uses). Core holds the key in memory only, for the 5-minute re-check, as the agent route does with its token.
- `probe.welcome` is the owner's reply, not Core's. `networkprobe` answers `probe.hello` through `send()` with a reply frame that carries the hello's `id`. So `send()` takes event and reply frames.
- No per-event audit rows. Presence lives 90 seconds with a 30-second ping. When no owner is registered, the answer is 4503 for everyone, so a probe sees the same code as a Tactical-side fault.

### Plan corrections found in the code

- `register_owner` checks that the authenticator is a plain function (not a Celery task or a callable object) and that its code file, like the task's, lies inside the owner's own folder. The plan said "inside the owner's own folder" for both. It did not say how, so the check reads the code file, as the agent route does for its task.

## Retired or changed checks

- `tests/version-1.18.45.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.45.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs the five new probe tests and `version-1.18.46.py` in place of the retired one.

## New tests

- `tests/probe-transport-identity-1.18.46.py`: header parsing, the authenticator contract, the failure counters, `register_owner`, denied callers, `request`, `send`, `presence` and `disconnect`, and the key never shown.
- `tests/probe-transport-consumer-1.18.46.py`: the socket, with an in-memory channel layer and a stubbed authenticator (`tests/probe_transport_harness.py`).
- `tests/probe-transport-contract-1.18.46.py`: the five contract rows, the capability, the wiring and the audit helper.
- `tests/probe-transport-isolation-1.18.46.py`: the two routes share no import, prefix, group, pool, audit action, credential or owner.
- `tests/probe-transport-docs-1.18.46.py`: the docs name every operation, close code, limit and audit action, with the numbers in the code.
- `tests/version-1.18.46.py`: release bookkeeping, line endings and the rebuild-label guard.

## What could not be run here

- `manage.py check`, `makemigrations --check` and a real Redis, channels or uvicorn websocket. The tests stub them. This release adds no migration and no model.
- `build_contract_catalog()` needs Django settings and the live capability registry. The new tests read `CORE_CONTRACTS` and `audit.py` with `ast` and check each row against the real functions. The signed export is made on dev02.
- The contract file for 1.18.46 in `docs/contracts/` (the export tool runs on dev02).

## Johan dev02 checklist

Update dev02 to Core 1.18.46. Steps 1 to 4 work without `networkprobe` 0.2.20. Steps 5 and 6 need it (M1).

1. Run `manage.py check`, then restart Core and Celery.
   - PASS: "System check identified no issues (0 silenced)." and no `core.probe_transport` error in the Core log.
   - FAIL: any error, or a log line saying the probe capability or route failed. Send the output and the log lines.
2. Open `/api/tfd/capabilities/`.
   - PASS: `core.probe_transport` 1.0.0 is listed with `register_owner`, `request`, `send`, `presence` and `disconnect`.
   - FAIL: it is missing, or `core.endpoint_transport` changed. Send the list.
3. Connect to `wss://<dev02>/ws/tfd/network-probe/` with `websocat` and any `Authorization: Probe` header, while `networkprobe` has not registered an owner.
   - PASS: the socket closes with code 4503 and no audit row is written.
   - FAIL: any other code, or a hang. Send the websocat output.
4. Check that an Endpoint Agent still connects to `/ws/tfd/endpoint-agent/`.
   - PASS: the agent shows as connected, as before.
   - FAIL: the agent is refused, or Tactical is slow to start. Send the Core log.
5. After `networkprobe` 0.2.20 is installed, connect to the probe route with a `Token` header (an agent token).
   - PASS: the socket closes with 4401, and one `custom:probe-refused` row says `wrong_scheme`.
   - FAIL: any other code, or no row. Send the output and the row.
6. With the same module, connect with a `Probe <id>.<wrong key>` header, then with a real probe's id and key.
   - PASS: the wrong key closes 4401 with one refusal row and the real probe stays connected and shows as online in `presence`.
   - FAIL: the real probe is refused, or the key shows in any log line or audit row. Send the output and the rows.

## Exit list

- Version 1.18.46, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change.
- Release manager: in `reviews/requests/core.md`, split "core: probe transport C1 and C2" and remove the C1 half, naming 1.18.46. Keep the C2 half open. Note in `reviews/requests/networkprobe.md` that M1 can start against `docs/probe-transport.md`. Export the contract file for 1.18.46 on dev02.
- Left out on purpose: C2 (Core 1.18.47) and every other open Core request. Per-event audit rows and an `ack` frame on the probe route are not built.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it.
