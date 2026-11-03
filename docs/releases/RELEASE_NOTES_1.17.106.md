# Tec-Tac Framework 1.17.106

Date: 3 November 2026. A fix-only release. System Update no longer offers an old saved branch head as the current update. A branch stage now checks the live head first, so it can't quietly stage an older version.

Closes: the System Update downgrade found on dev02 on 3 November 2026 (HAR `update dev missing.har`). There was no entry in `reviews/requests/core.md`.

## What happened on dev02

* `GET /api/tfd/system/updates/branches/` showed the live `dev` head, 28e1396 (1.17.105).
* `GET /api/tfd/system/updates/online/?refresh=none` returned a head saved the day before, 45cbf36 (1.17.99), with `refresh.reason: cache_fresh`. The same answer said `cache.stale: true` for the stable release.
* `POST /online/stage/` with 45cbf36 was accepted, because it matched the saved copy. It staged 1.17.99 as `operation: downgrade`.

The saved head was 26 hours old. Core should have asked GitHub once. Instead it got no lock and returned the saved head with no error and no flag. The answer came back in under 300 ms and no GitHub telemetry had been saved since 2 November. That points at the update-check lock failing at once. The likeliest cause is a lock file created by root (umask 022, so mode 0640), which the Tactical account can't open for writing. We have not confirmed this on the server.

## What changed and why

1. **A stale head is never presented as current.** The branch answer has two new fields. `head_checked_at` says when GitHub last confirmed the head. `head_stale` is true when that was 5 minutes ago or more. When Core couldn't refresh the head (no lock, rate limit, GitHub unreachable), `refresh.reason` is now `not_refreshed` or `rate_limited`, never `cache_fresh`. `cache_fresh` now means the main answer is inside its limit. A new `refresh.stale` list names every saved part past its limit: `branch_head`, `stable_release` (branch source) or `latest_release` (release source). That explains the dev02 answer: the stable release was old, by design, because a branch check never fetches it.
2. **The lock failure says so.** When the lock can't be taken, `branch_error` now says the saved head is shown. The lock also opens read-only when it can't open read-write: `flock` needs no write access, so a root-created lock file no longer blocks every check.
3. **Choice: bounded refresh, no new requests.** `refresh=none` already sends one conditional request when the saved head is older than 5 minutes. That stays the only call, and when it can't run, the answer is now marked stale. No request was added to page loads.
4. **A branch stage confirms the live head.** With `commit`, Core sends one forced conditional `GET /branches/<ref>` first. A 304 costs no rate limit. The 20-second guard, the shared lock and the rate-limit block still apply. If the commit isn't the current head, the stage gets 409 `stale_candidate` with the head named: "dev has moved to 28e1396; the check showed 45cbf36. Refresh the check and try again." If Core can't confirm the head inside the 5-minute limit (rate limit, GitHub unreachable, no lock), the stage is refused the same way. Nothing is downloaded. A release-source stage is unchanged.
5. **A downgrade is flagged.** The staged preview now has `downgrade` (true when the package is older than what's installed), `confirmation_required: "downgrade"` and a `downgrade_warning` that names both versions. The install route still refuses a downgrade without `allow_downgrade=true` (superuser only). So a deliberate downgrade, for example to a stable release, still works with that confirmation.

## Module-facing changes

* None. These are Core's own System Update routes. No module calls them (a grep of `modules/` found no caller). No capability, permission or module contract changed.
* The route contract text in `contracts.py` for `GET /api/tfd/system/updates/online/` and `POST /api/tfd/system/updates/online/stage/` is extended additively. Every older field is unchanged. The new values are `branch.head_checked_at`, `branch.head_stale`, `refresh.stale`, reason `not_refreshed`, `preview.downgrade`, `preview.confirmation_required` and `preview.downgrade_warning`. The 409 text now names the head.

## UI request

`reviews/requests/ui.md`, "From Core 1.17.106": don't offer a head marked `head_stale`; refresh once on page load when it is; show `refresh.stale`; and confirm a downgrade with its own Yes/No dialog. Until the UI ships this, the server-side check in item 4 stops the old commit from being staged.

## Assumptions (recorded in `reviews/questions/core.md`)

* We chose to mark a stale head rather than add an extra GitHub call. The existing single conditional request stays the only one.
* A pinned branch stage needs a head confirmed inside 5 minutes. Otherwise it is refused.
* We flag a downgrade but don't refuse it at stage. The install route's `allow_downgrade` stays the gate.

## Tests

* New: `tests/system-update-stale-head-1.17.106.py`. It covers: a stale cache with `refresh=none` and no lock (`not_refreshed`, `head_stale`, `branch_error`, no request); the same with GitHub reachable (one request, the new head); the rate limit (no request, `rate_limited`, `head_stale`); a stale release source; staging an old commit refused with "dev has moved to ccccccc" (one request, nothing downloaded); the current commit staged (no request inside 20 seconds, one 304 after); a rate-limited stage refused when the head is older than 5 minutes and accepted at 60 seconds, with no request either way; the downgrade flag and warning; and the install refusing a downgrade without `allow_downgrade` and queueing the deliberate stable downgrade with it. It also checks the contract text.
* Changed: `tests/github-rate-limit-1.17.98.py` compares the three original `refresh` keys, because `refresh.stale` is a new additive key.

## Checks on the test server (Johan)

1. Before updating, run `sudo ls -l /var/lib/tec-tac/system-updates/cache/`. **Expected:** a note of the owner and mode of each `github-refresh-*.lock` file. Send the list back. A `root` owner with mode `-rw-r-----` confirms the cause.
2. Update Core to 1.17.106 from `dev`. Open System Update. **Expected:** the Framework `dev` row shows the live head (28e1396 or later), or the response for `GET /online/?component=framework` shows `branch.head_stale: true` with `refresh.reason` `not_refreshed`. **FAIL:** an old head with `refresh.reason: cache_fresh` and `head_stale: false`. Send the HAR.
3. Press Refresh, then stage the Framework `dev` update. **Expected:** the preview shows `operation: update` (or `reinstall`) and `downgrade: false`. **FAIL:** `downgrade: true` for the current dev head. Send the HAR.
4. Wait for the next push to `dev` (or a release that moves it). Without refreshing, stage again. **Expected:** 409 with "dev has moved to <sha>; the check showed <sha>. Refresh the check and try again." Nothing is staged. **FAIL:** a 201 for the old commit. Send the HAR.
5. Set the source to Release and stage the stable release (an older version). **Expected:** the preview shows `operation: downgrade`, `downgrade: true` and the warning. Install works only after the downgrade confirmation. **FAIL:** the install starts without that confirmation, or is refused with it. Send the HAR.
