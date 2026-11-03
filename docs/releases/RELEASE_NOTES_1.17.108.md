# Tec-Tac Framework 1.17.108

Date: 3 November 2026. A small release for the licensed catalogue, before the beta on 6 November 2026. You now see why a licensed module cannot be installed, and an unreadable licence policy gets its own message. What may be installed only gets stricter.

Closes, in `reviews/requests/core.md`:

* "Licensing 0.10.2": the state for "this Licensing version cannot read the licence's module policy" (`licensing.catalogue` 1.1.0, `licensing.entitlements` 1.5.0).
* "Licensing 0.10.1 (Licensing Server v0.1.44)": distinct availability states (handoff `docs/TEC-TAC-CORE-LICENSING-API-HANDOFF-v0.1.44.md`, section 4, item 4), and no offer for a module whose `category` is None.

## What changed and why

1. **New state `licence_policy_unreadable`.** Licensing 0.10.2 answers `licence_grace_expired` when it cannot read the licence's module policy, because Core knew no better state. Core now knows `licence_policy_unreadable`, with the sentence "This Licensing version cannot read the licence's module policy. Update Licensing, then use Refresh now." It fails closed exactly like `licence_grace_expired` (AD-58): the list is emptied, no new install is offered, and installed modules keep working. The daily sync counts it as attention, not a failure. Only the label and the reason change. Licensing can start sending it in its next release.
2. **One state per licensed release.** Each release row of the licensed source now carries `availability_state`:
   * `available`: entitled, classified, and the server says available (or says nothing). Only these can be installed.
   * `entitled_unavailable`: in the licence, but the server says the release is not available now.
   * `blocked_by_channel`: not offered on the channel set for the source.
   * `missing_or_dependency`: missing on the server, or a module it needs is not available.
   * `not_in_licence`: not in the licence (as in 1.17.103).
   * `unclassified`: no category (see 3).
   Every state other than `available` is marked "not offered" with Core's own sentence, so it never gets an Install button.
3. **No offer for a module with no category (AD-21).** A category that is not `core`, `server` or `premium` (None, missing or an unknown word) is stored as null and the release is `unclassified`. Core's install-time AD-21 check still applies as before.
4. **The catalogue lists what is not offered.** `GET` of the online catalogue returns a new key `unavailable[]`: each licensed release that is listed but not offered, with its id, name, version, channel, category, repository, state and reason. At most 500 rows. It is display only. `modules[]` and `count` keep their meaning.
5. **A cache from 1.17.107 gets the states when it is read**, so you do not have to wait for the next sync. A retired or refused repository mark is never replaced.
6. **Staging a release that is not offered names its reason** (for example the channel, or no category) instead of always saying "not in the licence".

The browser does not show `unavailable[]` yet. A request for a **Not available** list on the Online catalogue is in `reviews/requests/ui.md`. Until the UI ships it, those releases are simply not listed, as before.

## Module-facing changes

* None that a module calls. The changed route (the online catalogue) is used by the browser only. The new key and row field are additive.
* `licensing.catalogue`: Core now accepts the extra state `licence_policy_unreadable` from the provider. A Licensing version that does not send it is unaffected. A grep of `modules/` found one provider (Licensing) and no other user of these states.
* `module_updates.list_updates` reads the online catalogue. A licensed release that is no longer `available` is no longer offered as an update there either. This is stricter, not wider.

## Assumptions (recorded in `reviews/questions/core.md`)

* The server's `availability` word is free text. No word or `available` means available. A word containing "channel" is `blocked_by_channel`. A word containing "missing" or "dependen" is `missing_or_dependency`. Any other word is `entitled_unavailable`, so an unknown word is never read as available.
* No `availability` word at all is still read as available, as in 1.17.103. Each download is checked again by the server's grant.
* `not_in_licence` comes before `unclassified` when both apply, so the licence reason shows first.
* The state is named `licence_policy_unreadable` (the name in the request), not `policy_unreadable` (the Licensing registration state).

## Tests

* New: `tests/licensing-availability-1.17.108.py`. It covers the new state (lists, sentence, fail-closed like `licence_grace_expired`, read from the provider), every row state including None and unknown categories and unknown availability words, idempotence and no overwrite of a retired mark, a 1.17.107 cache read with the new states, `unavailable[]`, the staging sentence, docs, contract, version and line endings.
* Re-run and passing: `tests/licensing-repository-1.17.103.py`, `tests/licensing-download-1.17.103.py`, `tests/licensing-sync-skip-1.17.105.py`, `tests/release-integrity.sh`.
* Not run here: anything that needs Django, which is not installed on this PC.

## Checks on the test server (dev02)

1. Settings, Modules, Repositories: press Sync on "Tec-Tac licensed modules (Licensing)". Expected: the sync ends with ok and the online catalogue lists your entitled modules as before. FAIL: an entitled, classified module that was listed in 1.17.107 is missing. Send back the module id and the `availability` word from the Licensing page.
2. Open `/api/tfd/modules/catalog/online/` in the browser while signed in. Expected: a key `unavailable` (an array, may be empty). Each row has `availability_state` and `reason`. FAIL: the key is missing, or a row in `unavailable` also appears in `modules`. Send back the JSON.
3. If a module on the Licensing Server has no category, it must appear in `unavailable` with `unclassified` and must not appear in `modules`. FAIL: it can be staged.
4. Installed modules keep working after the upgrade. FAIL: any installed module is disabled.
