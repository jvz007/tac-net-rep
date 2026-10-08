# Tec-Tac Framework 1.17.3

This release fixes what a branch source shows on the System Updates page. A server that follows `dev` no longer gets a stable-release tag beside the branch. It also tells you whether the installed code matches the branch when no install recorded a commit. And it documents the stage route in the HTTP contract.

Nothing here breaks a module. No module uses these routes. See "Module-facing changes".

## Branch source stops leading with the GitHub release

Johan's dev-server test of 0.12.82 showed the release tag from `main` beside the `dev` branch. Core fetched the latest release even for a branch source.

- `online_status(component, force, source)` with a branch source no longer calls GitHub's `releases/latest`, `commits/<tag>` or the signature preview. It does not read or write the release cache.
- Every key stays present. `latest_release` is now `null`, `release_error` is `null`, and `checked_at` is `null`. `source`, `branch` and `branch_error` are as in 1.17.2.
- A release source, or no source, returns exactly the answer it did before.
- The branch cache row still lives in the release cache file under `branches`, beside `components`.
- `GET /system/updates/` and `cached_online_status` are unchanged. They never called GitHub.

## Installed-versus-branch fallback (CQ11)

Servers that installed 1.17.2 from a zip have no install job with a GitHub commit, so the branch state read `unknown`.

- When no install recorded a commit, Core reads `VERSION` at the branch head commit and compares it with the installed `VERSION` (through the same version comparison the rest of the updater uses, so `-N` rebuild suffixes compare consistently).
- Equal gives `same`. Not equal gives `differs`. The branch object gains `basis` (`commit`, `version` or `null`), `head_version` and `installed_version`.
- A recorded commit still wins (`basis` is `commit`).
- The state stays `unknown` when the head VERSION cannot be read, the installed VERSION is missing, or either is not a plausible version. A failed VERSION read never sets `branch_error` and never raises.
- The head VERSION is cached in the existing `branches` cache row, keyed by the head commit, for the 5-minute branch TTL. `force` bypasses it. A check makes at most one extra GitHub call.

**Limit, stated plainly.** A version match is weaker than a commit match. A branch can gain commits without a VERSION bump, so `basis: "version"` can read `same` while the commits differ. The contract entry and `docs/update-source.md` say so.

CQ11 is closed. Johan asked for the VERSION comparison, so Core now does both: the commit record from 1.17.2 and this fallback. It is removed from `reviews/questions/core.md`.

## Stage route contract entry

The held Low from the 1.17.2 review. `HTTP_CONTRACT_DETAILS` now has an entry for `POST /api/tfd/system/updates/online/stage/`: the `core.privileged_operations` requirement, the request keys (`component`, `source_type`, `ref`), the remembered-source default introduced in 1.17.2, the 201 response and the 400, 403 and 500 errors. Documentation only. The route's behaviour is unchanged. CQ12 (who may change the remembered source) is still open and unchanged.

## Module-facing changes

- `GET /api/tfd/system/updates/online/`: for a branch source `latest_release` is `null` and `release_error` is `null` (the keys stay present). A release source is unchanged. The only consumer is the Core UI shell. It already switches on the saved source and tolerates a missing release, so no UI change is needed from Core.
- The `branch` object has three additive keys: `basis`, `head_version`, `installed_version`.
- New HTTP contract entry for `POST /api/tfd/system/updates/online/stage/`.
- No module uses any of these routes or `system_update` (checked in `modules/`). No module needs a change.

## Tests

- New `tests/update-source-1.17.3.py`: no release call for a branch source, key set, cache coexistence, the VERSION fallback in every case above, the cache rules, and the stage contract entry checked against the view's request keys.
- `tests/update-source-1.17.2.py`: the two assertions that expected release data for a branch source now expect `null`, with a comment naming 1.17.3. It stubs the VERSION read so its `unknown` cases still hold. It also asserts the stage contract entry.

Django is not installed on the development PC, and GitHub cannot be called from it. The tests load `system_update.py` against stubs. The live behaviour is verified on the dev server after the update: the framework row should show `same` or `differs` and no release tag for `dev`.
