# Tec-Tac Framework 1.17.92

Date: 29 October 2026. Endpoint transport 1.1. The 29 October 2026 load test (2 000 agents from one address) did not pass: valid tokens were closed with 4401 and 4429. This release changes how the socket decides, so a valid token connects and a fault on our side tells the agent to try again. The capability `core.endpoint_transport` stays at 1.0.0. One history note: the 1.17.91 notes say 1.17.90 was never signed. A signed 1.17.90 manifest exists in the previous tree, so treat that line as wrong. The 1.17.90 labels in code comments name the work.

## What changed and why

1. **A valid token is never refused because someone else failed.** The identity check now runs before any per-agent decision. The old single counter (10 failures a minute per exact address, checked first) is replaced by three limits:
   * 10 failed attempts a minute per address, the limit AD-54 signs (plan section 9A item 1). An IPv6 address counts by its /64. An IPv4 address counts exactly. Over it: close 4429, no audit row.
   * 10 failed checks a minute naming one agent id. It counts only a failed check for an id that is a valid agent id, and it is read only after a failed check, so someone who presents a real agent's id cannot lock that agent out. The 11th gets 4429 with no audit row. A valid token for that id still connects.
   * No global budget of refusal audit rows by default (`REFUSAL_ROWS_PER_MINUTE = 0`), so every refusal is audited as AD-54 signs. The budget mechanism stays in the code, off, for a signed amendment.

   Only failures count. A good connect never counts. The plaintext refusal still counts as a failure. A cache fault reads as not limited and is logged. `rate_limited(ip)` and `note_failure(ip)` keep their names and signatures. New helpers: `note_agent_failure`, `agent_limited`, `note_failed_check`, `refusal_row_allowed`.
2. **A fault on our side never closes 4401 and never counts.** `authenticate_endpoint_agent` returns a transient result (`ok` False, `reason` `unavailable`, `transient` True) for any database or lookup exception. A full auth pool answers `busy` and a check that takes over 10 seconds answers `unavailable`. The consumer closes all three with the new code 1013 (retry later), counts nothing against the address or the agent and writes at most one non-strict `custom:endpoint-refused` row with that reason every 10 seconds. 4401 is closed only for `malformed_agent_id`, `malformed_token`, `unknown_token`, `token_mismatch`, `no_agent`, `agent_mismatch` and `inactive`. The 10 minute re-check follows the same rule: a transient result keeps the socket open and retries 30 seconds later. Only a real identity answer closes 4401. The reason `lookup_failed` stays in the refusal texts for old rows; new rows say `unavailable`.
3. **Burst handling without the default executor.** The consumer no longer uses `run_in_executor(None, ...)` or `database_sync_to_async` (one thread-sensitive thread). Core owns four small pools, created on first use, each with an in-flight counter so a full pool answers at once: auth (6 threads, backlog 256, each job runs `close_old_connections()` before and after and closes its connection), cache (8, 2000), audit (2, 1000, a row over the cap is dropped with a throttled log line) and hand-over (4, 64, so a broker outage can no longer take a thread from the executor Tactical's own sockets use). The Celery hand-over passes `retry=False`. The connect audit row is written in the background, so the first ping is not delayed by the database. The first ping goes out 60 to 70 seconds after connect and the re-check 600 to 660 seconds after, so agents that connected in one ramp do not reach the database together.
4. **Presence is re-acquired and never overwritten.** `refresh_presence(agent_id, owner, since)` touches the key while the connection owns it (the value is never rewritten, so a late refresh from the older connection cannot overwrite the newer one). When the key is gone it creates it again with `cache.add` (atomic) using the connection's own `since` and owner. A different live owner is left alone. A superseded connection never re-acquires. Ping and pong both refresh.
5. **Documented.** `docs/endpoint-transport.md` has the new limits, the 1013 section, the pools, and a Load test section with the stage 3 numbers and the pass target (2 000 agents at the real 60 s ping, ramp 20 ms, from one address; all connect; no 4401 or 4429 for a valid token; ping p95 under 2 s after the ramp; no 502s, or 502s only during the ramp with the agents' back-off recovering all). The contract metadata has the same.

## Module-facing change

Behaviour on the socket only. No contract operation, signature or return shape changed, so `core.endpoint_transport` stays at 1.0.0 and the range nats-comms asks for keeps working. Nothing else in `modules/` uses it.

* New close code **1013** (retry later) for a server-side fault while checking a token. The agent should treat it like a network error and reconnect with jitter. The agent request for this is in `reviews/requests/endpoint-agent.md`.
* Limits: 10 failures a minute per address (IPv6 by /64, unchanged from 1.17.90), a new 10 failed checks a minute per agent id. 4429 now means those, or more than 20 frames a second.
* 4401 now means only a real answer about identity.
* A new `custom:endpoint-refused` reason, `unavailable` or `busy`, on a 1013 row (not a refusal in the audit sense).

After Core 1.17.92 is installed on dev02, the public contract needs exporting again into `docs/contracts` (Claude cannot generate it).

## Not built here

* Per-agent connect and event budgets (held Medium 3 of 1.17.90-1). A per-agent connect budget could refuse a valid token, which this release must not do. Next patch.
* Short publish and connect timeouts on the Celery hand-over. The broker's own settings own those. Core bounds the wait (5 seconds) and the pool.
* The two held Mediums in the contract request path, the uncached plugin scan, and the load-seed file Low. They are not in the connect burst.
* Agent-side back-off on 1013 and the loadsim report: not Core work. It is filed in `reviews/requests/endpoint-agent.md`.
* nginx tuning for the 32 HTTP 502s. They are nginx's answer to a slow upstream. They were not reproduced here. If they remain outside the ramp after the re-test, the install owner decides.

## Tests

New: `tests/endpoint-transport-limiter-1.17.92.py`, `tests/endpoint-transport-retry-later-1.17.92.py`, `tests/endpoint-transport-burst-1.17.92.py` (real threads on the stub harness) and `tests/endpoint-transport-docs-1.17.92.py`. Changed to the new limits and the 1013 outcome: `tests/endpoint-transport-consumer-1.17.90.py`, `tests/endpoint-transport-identity-1.17.90.py`, `tests/endpoint-transport-contract-1.17.90.py` and the harness (`touch`, a `django.db` stub, `settle`).

## Not run here

Django, channels and Redis are not on this PC. The tests run on stubs and the real `endpoint_transport.py` and consumer. `tests/endpoint-transport-runtime-1.17.90.py` is a dev-server script and was not run. The 2 000 agent load re-test is Johan's, on dev02 with `agent/tests/loadsim`. The 502s were not reproduced here. The cause of the 42 refusals of 4401 in stage 3 cannot be read from this PC: the dev02 audit rows hold the reason. The fix does not depend on it, because every cause that is not an identity answer now closes 1013.


## Fixed after review

Round 1 blocked 1.17.92 (High): the release raised the signed per-address limit of 10 failed attempts a minute to 600 and added a 600 row audit budget, with no signed amendment. CLAUDE.md says a change that loosens security beyond a signed decision is built fail-closed and the wider version goes to `reviews/questions/core.md`.

* `FAILURES_PER_ADDRESS_PER_MINUTE` is back to 10 and `REFUSAL_ROWS_PER_MINUTE` is 0 (off). There is no setting to raise either. The identity-first ordering for the per-agent-id limit stays (it only adds a 4429 after a failed check and never refuses a valid token on its own).
* The 600 per address, 600 row budget and a per-agent-id limit proposal are in `reviews/questions/core.md` for Johan. They stay off until an AD-54 amendment is signed.
* Because the signed limit is read before the check, a valid token from an address that already had 10 failures in the minute waits for the next minute. This is the 1.17.90 behaviour. The load test pass target "no 4429 for a valid token" holds only while no more than 9 failures come from that address in a minute.
* Tests: `endpoint-transport-limiter-1.17.92.py` asserts the 11th failed attempt from one IPv4 address in a minute closes 4429 under default settings; the budget mechanism is tested with the value set by the test. The consumer, identity and docs tests carry the signed numbers. `docs/endpoint-transport.md` and the contract metadata say 10.
* Not done: an AD-54 amendment entry in `docs/review-accepted-decisions.md`. Only Johan signs a decision.
