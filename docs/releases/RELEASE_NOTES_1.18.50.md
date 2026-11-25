# Tec-Tac Framework 1.18.50

Date: 25 November 2026. A tunnel session now ends when the engineer who opened it loses access to the probe's site. Core does this itself, within about 10 seconds of a role, scope or account change, and at the latest at the existing 5-minute re-check. This release also closes the two held findings of the 1.18.49 review: the probe's hard-cap backstop that could fire before the Console's own cap (Medium), and the frame-rate cap that counted DATA and ACK alike (Low). It is a Core-only change. `main` stays held.

## Module-facing change

Everything is additive. `core.probe_transport` moves from 1.1.0 to 1.2.0 and a new capability `core.access_events` 1.0.0 appears. Both need `framework >=1.18.50`. `networkprobe` is the only user of `core.probe_transport` in `modules/`. It imports the module functions directly and calls nothing new today, so networkprobe 0.2.22 and 0.2.23 keep working unchanged. No other module uses either contract.

What `networkprobe` can now do, from 0.2.24 on (the ORDER is in `reviews/requests/networkprobe.md`):

- `issue_tunnel_ticket(request, "networkprobe", spec)`: `spec` may carry `site_id`, a positive integer (not a boolean), the probe's site. Core then refuses a person who cannot see that site (`{outcome: denied, code: out_of_scope}`, one deny row, no ticket, no slot), refuses their Console connect (4401, close text `scope_lost`) and ends their live session (`ended_by_core`, end-row detail `scope_lost`) when they lose it. A fault while checking is `unavailable` at the ticket and `check_failed` for a live session (fail closed). Without `site_id` Core checks no scope, exactly as in 1.18.49.
- `set_tunnel_site(module_id, probe_id, site_id)` is a new operation (the tenth). It returns `{outcome: ok|invalid|denied|unavailable, updated: [session ids]}`. Verified owner only, `module_id` must equal the caller. Call it after a probe moves to another site. Core writes the new site into every live session of that probe that the caller opened, and each opener's Console re-checks within about 5 seconds.
- `tunnel_status` rows gain `site_id` (null when the owner sent none). The other keys are unchanged.
- A tunnel session that ends over the frame rate now has end-row detail `rate_control` or `rate_data`. The reason list is unchanged (`protocol_error`, close 1002).
- `core.access_events` 1.0.0: the Django signal `tec_tac.access_events.access_changed` (receivers get `user_ids`, a frozenset of ints, and `reason`) and `changed_at(user_id)`. `networkprobe` needs neither for tunnels: Core's own relay uses them. A module cannot raise the signal.

No close code, wire frame, route, ticket field (other than the optional `site_id`) or reason name changes.

## Closes

- Request "core: tunnel session access check (networkprobe 0.2.23, 25 November 2026)" and review finding M1 of `reviews/security/tunnel-e2e-review-25-11-2026.md`.
- Request "core: tell modules when a person's scope or permissions change (coordinator, 25 November 2026)". Both moved to `reviews/requests/_history/core.md`.
- Held 1.18.49 Medium: the probe hard-cap backstop can fire before the Console's own cap (`probe_tunnel_consumer.py`).
- Held 1.18.49 Low: the 2000 messages a second cap counts DATA and ACK alike (`probe_tunnel.py`).

## What changed and why

1. **Core checks the engineer's access to the probe's site (M1).** `scope_refusal(user_id, site_id)` in `probe_tunnel.py` reads the person fresh and calls `tec_tac.resources.get_site(site_id, context=user_context(user))`. That is the same rule the module uses at open (Tactical's client and site scope and the site-list right), so Core and the owner agree. Not found or not permitted is `scope_lost`. Any other error is `check_failed`, logged, and treated as a refusal. It runs at three points: `issue_ticket` (after the permission check, before the probe's presence; `denied` with `out_of_scope`, or `unavailable`), `console_open` (after the record is checked, before the Console side is taken; 4401) and `console_recheck` (after the account check; it reads the LIVE session record, so a site the owner updated counts). The Console consumer already ends any other reason `ended_by_core` with that detail, so no new close reason and no wire change are needed. A re-check costs about three queries per session, at most 50 sessions, every 5 minutes.
2. **The owner can tell Core a probe moved (M1).** `set_tunnel_site` rewrites `site_id` in the record of each live session of that probe that the caller opened (an ended session is skipped), keeps the record's lifetime, and stamps the opener's access marker so the Console re-checks in its next tick. A person with access to the new site keeps the session. The id can never be cleared: a non-positive or non-integer `site_id` is `invalid`.
3. **The access-change hook (request "tell modules when a person's scope or permissions change").** New `tec_tac/access_events.py`. Receivers on Tactical's models find the affected people: a role saved or deleted; a role's client or site list changed (the many-to-many, forward and reverse, including a reverse clear, which reads the roles before the clear); a Tec-Tac extension permission of a role saved or deleted; a user's role, active flag, superuser flag or dashboard block changed (a save that names other fields only, such as `last_login`, does not fire); a user deleted. `notify_access_changed` writes one cache marker per person (`tec-tac:access:chg:<id>`, the time, kept 6 hours, above the 4-hour tunnel cap), then sends the `access_changed` signal with `send_robust`, so a faulty receiver never stops the others or Tactical's save. Inside a transaction it runs on commit. It caps the list at 5000 ids and never raises. The m2m receiver also deletes Tactical's `role_<name>` cache key: Tactical caches a role for 600 seconds and clears it when the role is saved, but its editor sets the client and site lists after that save. The receivers connect in their own guarded block of `apps.ready`, with the capability registration in another.
4. **The tunnel relay uses it.** A signal fires in the web or Celery process that saved the change. The sockets live in the ASGI process. So the signal is not enough, and the cache marker is what crosses. Each Console socket stamps the time before its open decision and, once per 5-second tick, reads its person's marker. A newer marker brings the 5-minute re-check forward to that tick. The re-check decides (account, permission, module, site, probe), so a change that touches nothing the person holds ends nothing. A re-check that cannot run reuses the 30-second retry and the stale-grace end. The result: a real loss ends the session within about 5 to 10 seconds, not instantly. The 5-minute check stays as the backstop and also covers changes that fire no signal (`queryset.update`, raw SQL) and a deleted site or client. The docs say so.
5. **The probe's hard-cap backstop counts from the Console's start (Medium).** The old rule used the ticket's creation time plus the cap plus 60 seconds. A Console that connected at created+59 had its own cap at up to created+cap+64, after the probe's backstop at created+cap+60. `poll_session` now also returns `console_at` (the console side marker's time). The backstop is `console_at` (or, when the Console has not attached or the poll failed, the end of the 60-second ticket window) plus the cap plus `SLOT_GRACE_SECONDS`. The Console's own cap is at most its start plus the cap plus one 5-second tick, so the backstop is later by about 50 seconds in every case. The test asserts `SLOT_GRACE_SECONDS >= WATCH_TICK_SECONDS + FLUSH_SECONDS + 15`. The idle backstop is unchanged.
6. **DATA and control frames are counted apart (Low).** `FRAMES_PER_SECOND_MAX` (2000) now bounds OPEN, ACK and CLOSE. New `DATA_FRAMES_PER_SECOND_MAX` (10000) bounds DATA: a 100 Mbit/s stream even in 1.5 KB frames, and about 300 MB/s in 32 KiB frames. A bulk copy is no longer ended by its own ACKs, and DATA is still bounded (review L4). Both are counted in memory in the same one-second window before the frame check. A text frame, an empty message or an unknown type counts as control and is refused by the frame check right after. Over either bound the session still ends `protocol_error` (close 1002, `ended_by_core`). The end row's `detail` says `rate_control` or `rate_data`.
7. **Docs and contract text.** `docs/probe-transport.md` (scope section, both frame bounds, the backstop rule), new `docs/access-events.md`, `docs/capabilities.md`, `CORE_CONTRACTS` rows for `set_tunnel_site`, `access_changed` and `changed_at`, the `site_id` text of `issue_tunnel_ticket` and `tunnel_status`, and two `RULES` lines. The `core_does_not` text no longer says Core checks no person's scope.

## Assumptions

None needs Johan; nothing widens trust. They are in `reviews/questions/core.md` as information.

- Core ends the sessions itself. No `session_access(session_id)` read is published: a read of other people's access would put person-access questions in the owner (standard section 1a) and adds surface for nothing once Core ends them. It can be added later without breaking anything.
- `site_id` is optional in 1.2.0, so networkprobe 0.2.22 and 0.2.23 keep working. A session opened without it gets no Core scope check (the account, permission and module checks still run). Plan: require it in the next Core patch after networkprobe 0.2.24 is signed.
- `notify_access_changed` and `mark_changed` are not offered through the capability. A module that could raise the signal could make Core re-check people at will. The fail-closed form keeps raising Core's own.
- The access marker is read every 5 seconds per live session, one cache call. That is the cost of "within about 10 seconds". A push into the ASGI process would be faster but needs a channel-layer group per person; the marker is simpler and fails soft (an unreadable marker ends nothing and the 5-minute check stays).
- A fault while asking for the site ends a live session `check_failed`, as a fault in the account check already does. The re-check job itself failing to run (pool full, timeout) is transient and retries after 30 seconds.
- DATA gets 10000 a second. Lowering it would end more legitimate sessions. Johan can ask for another figure.
- The backstop starts at the Console's attach time. The Console's own timers always fire first in normal running.

## New tests

- `tests/access-events-1.18.50.py`: the markers and the signal (ids cleaned and capped, the reason list, TTL, `send_robust`, after-commit delivery, cache faults); every receiver (role save and delete, m2m forward and reverse for clients and sites, extension permission save and delete, user save with and without `update_fields`, user delete); created rows fire nothing; Tactical's role cache key is deleted; a failing receiver never reaches Tactical's save; `connect_receivers` is idempotent; `apps.ready` has its own guarded blocks and keeps CRLF; the capability registers with two operations and offers no way to raise the signal.
- `tests/tunnel-scope-recheck-1.18.50.py`: `site_id` validation; the ticket refused `out_of_scope` (one deny row, nothing started), `unavailable` on a fault; the connect refused 4401 `scope_lost`; a live session ends at the first re-check after the scope is removed, both sockets closed, one end row, one `tunnel.closed`; a fault ends it `check_failed`; a session in scope is untouched; permission and account end as before and the site is not asked; no `site_id` behaves exactly as 1.18.49; the status row; `set_tunnel_site` (owner only, only that probe, only the caller's sessions, ended sessions skipped, record lifetime, fault); a move ends or keeps the session at the next tick; a newer marker brings the re-check forward, an older one or another person's does not, a pass is not repeated, a transient failure retries after 30 seconds, an unreadable marker ends nothing.
- `tests/probe-tunnel-limits-1.18.50.py`: the backstop with a Console that connects at created+59 (the old time passes without an end, the Console's cap ends it with exact bytes, one end row and one `tunnel.closed`), a dead Console worker still ended by the probe, the 1.18.49 case, a failed poll, a Console that never connected; 2000 ACKs and 10000 DATA frames pass on both sides, the next ends `protocol_error` with the right detail, the two are not one bucket, the window resets, no cache call during the check, and text, short, oversize and unknown frames still end `protocol_error`.
- `tests/version-1.18.50.py`: release bookkeeping and line endings. `version-1.18.49.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.49.md` to `docs/releases/`.
- Changed: the harness (stubs for `tec_tac.resources`, `django.dispatch` and `django.db.transaction`, and the real `access_events`), the 1.18.47 contract test (ten operations and rows, 1.2.0), the 1.18.47 docs test, the 1.18.47 end test (`site_id` in the row), the 1.18.47 relay test (five `data[0]` reads) and the 1.18.49 hardening test (`_rate_exceeded(` before the frame check, the DATA bound named in the docs).

## What could not be run here

- Django is not installed on this PC, so `manage.py check` and anything that imports Django did not run. Tactical's `Role` and `User` models, real Django signals, real `get_site` queries, `channels_redis`, Redis and uvicorn were not available. The receivers and the scope check ran against stand-ins; the tests say so. The first real run is on dev02.
- The signal receivers load at start-up, so dev02 needs the web workers and the ASGI service restarted after the update.
- No migration and no model change.

## Johan dev02 checklist

Update dev02 to Core 1.18.50 from the dev branch. No migration. Restart the web workers and the ASGI service (the signal receivers load at start-up). Steps 2 to 4 need networkprobe 0.2.24, which sends `site_id`. Steps 1 and 5 run on 0.2.23 as it is.

1. With networkprobe 0.2.23 (no `site_id`), open a tunnel session and use it.
   - PASS: it opens and works exactly as before.
   - FAIL: any refusal or an end that mentions `scope_lost`. Send the audit rows and the Core log.
2. With networkprobe 0.2.24, open a session as an engineer. In Tactical, remove that client from the engineer's role while the session is open.
   - PASS: the session ends within about 10 seconds, and the end row has detail `scope_lost`.
   - FAIL: the session is still open after one minute, or ends with another detail. Send the end row and the Core log.
3. With networkprobe 0.2.24, open a session, then move the probe to a site the engineer cannot see.
   - PASS: the session ends within about 10 seconds.
   - FAIL: it stays open. Send the end row and the Core log.
4. Open a session, then move the probe to a site the engineer can see.
   - PASS: the session stays open and keeps working.
   - FAIL: it ends. Send the end row.
5. Copy 10 MiB through the tunnel in both directions, then run a long bulk copy.
   - PASS: the bytes match and no session ends `protocol_error`.
   - FAIL: a session ends `protocol_error`. Send the end row (its detail says `rate_control` or `rate_data`).

## Exit list

- Version 1.18.50, no rebuild label. No migration, no root-helper, `install.sh` or sudoers change. No change to `docs/contracts` (the export runs on dev02 after signing).
- Release manager: after signing, remove the two "From core core-1.18.49 review" lines (Medium and Low) from `reviews/core/BACKLOG-new-findings.md`, naming Core 1.18.50, and export the public contract for 1.18.50 on dev02 (`core.probe_transport` 1.2.0 and the new `core.access_events` 1.0.0).
- Left out on purpose: a published `session_access(session_id)` read; making `site_id` required (next patch, after networkprobe 0.2.24 is signed); the Engineer Console certificate authority; the tunnel check-in frame (on hold); the installer change for `--ws-max-size` and `X-Forwarded-Proto`; a signal for changes that bypass Django signals; every other open Core request, including the scoped `trusted_service_context` request of 19 November 2026.
- Filed: `reviews/requests/networkprobe.md` has the ORDER for networkprobe 0.2.24 (send `site_id`, call `set_tunnel_site` when a probe moves, map `scope_lost`).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it. Tunnels stay dev02-only until networkprobe 0.2.24 ships.
