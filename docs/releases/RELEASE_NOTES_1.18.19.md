# Tec-Tac Framework 1.18.19

Date: 19 November 2026. Core can now plan the install of several licensed modules before anything is installed. The plan is read-only: it starts no job, fetches no package and writes no audit row.

## What changed and why

### 1. A read-only install plan: `POST /api/tfd/modules/catalog/online/plan/`

Welcome's module picker shows a suggested order, but Core is the one that knows the real rules. This route gives Welcome Core's own answer: what would install, in which order, what gets added because something needs it, and what is blocked and why. It closes the plan half of request R1a.

- Body: `{"modules": ["id", ...]}`, 1 to 50 ids (`[a-z0-9][a-z0-9_-]{0,63}`). Duplicates are dropped and the order is kept. Anything else is `400 bad_request`. There is no version choice: the version is the one in the licence plan's release.
- Needs `core.privileged_operations`, checked first, fails closed.
- The allowed list is read once through `licensing_catalogue_source.read_allowed_modules()`, the only caller Licensing accepts. If its state is not `ok`, the answer is `{ok: false, state, message}` with no plan (200, 502 `invalid_response` or 503 `licensing_unavailable`, the same map as `GET allowed/`).
- A module is offered only if its allowed row is `selected`, has a release, is available and is entitled. Otherwise it is blocked with a code and a plain sentence: `not_in_allowed_list`, `not_selected`, `no_release`, `not_available`.
- The allowed row's release has no `requires`, `optional_dependencies` or category. Core takes them from the saved Licensing catalogue entry with the same module id and release id. No matching entry, or a `download_unavailable` entry, blocks the module (`not_in_catalogue_cache`: "Sync the repository, then plan again"). There is no fallback.
- Also blocked up front: protected ids (`protected`), the same version already installed (`already_installed`), a newer version installed (`older_than_installed`), and a module that is installed but disabled (`disabled_install`, the same sentence as the single install).
- A hard dependency that is not installed at a satisfying version is added from the allowed list when its row is selected, has a release, has a catalogue entry and the release fits the constraint (`added_dependencies[]`, `added_for[]`). This repeats for its own dependencies, capped at 100 modules and safe against cycles. A dependency that cannot be added is left out, and the shared resolver reports it as `missing_dependency` or `dependency_version`.
- Reuse: the plan calls `module_manager_v2.resolve_install_plan`, the function both `queue_v2_install` and `queue_batch_install` end in. It holds the runtime, missing, disabled and out-of-range dependency rules, the optional dependencies, the category rule (AD-21), the replacement rules, `breaks_dependant`, cycles, the install order and `will_disable`. The new file writes none of these again.
- Rounds: every resolver problem is tied to a module and that module is blocked with the problem type as the code and the resolver's sentence. Modules that need a blocked module are blocked `dependency_blocked`. The survivors are resolved again, at most 8 rounds, then everything left is blocked `plan_unstable`. A problem that cannot be tied to one module goes to `conflicts[]` and blocks every pending module (`plan_conflict`).
- The answer uses Core's own words only. It carries no SHA-256, publisher id, key id, URL or token.

New file: `framwork/tec_tac/module_install_plan.py` (plan builder with injected collaborators, plus the wiring). The view `ModuleOnlineInstallPlanView` sits in `module_allowed_views.py`, because `module_repository_views.py` must stay free of `licensing_catalogue_source`. The route is registered in `urls.py` and documented in `contracts.py` and `docs/module-repositories.md`.

Modules and tools moved: `RELEASE_NOTES_1.18.18.md` to `docs/releases/`, `tests/version-1.18.18.py` to `tests/legacy/`.

## Module-facing change

- New route `POST /api/tfd/modules/catalog/online/plan/`. Additive. No module calls it yet; the first reader will be Welcome. No existing route, contract or capability changed, so no module needs a change.
- The answer's fields are in `contracts.py`: `ok`, `state`, `message`, `valid`, `requested`, `order`, `added_dependencies`, `will_disable`, `conflicts`, `blocked`, `optional_dependencies`, `plan_state`, `plan_revision`, `fetched_at`, `checks_deferred`.
- The plan is advice. The real install (R1b, a later release) stages the package, checks the SHA-256, the detached signature, the trusted publisher and key, and runs `resolve_install_plan` again on the signed manifest.

## Johan test checklist

Update dev02 to Core 1.18.19 first. Licensing must be 0.10.7 or later.

a. As a module manager, POST the plan with one licensed id that is installed and one that is not. Expected: the installed one is blocked `already_installed`, the other is in `order`, and `checks_deferred` is listed. FAIL: a job, a download or an audit row appears, or the answer is 5xx.
b. POST a module whose dependency is not ticked. Expected: it shows as blocked with the reason (`missing_dependency` or `dependency_blocked`). FAIL: it is listed in `order`.
c. POST a premium id you have unticked. Expected: blocked `not_selected`. FAIL: it is in `order`.
d. Stop the Licensing module and POST again. Expected: 503, state `licensing_unavailable`, no plan. FAIL: any plan or module list comes back, or an audit row is written.

## What could not be run

Django is not installed on this PC, and the module state code needs `fcntl`. The view, DRF throttles and the real `resolve_install_plan` against a live module state were not run. The plan builder ran with a fake provider and a small fake resolver that copies the resolver's problem shapes (`tests/online-install-plan-1.18.19.py`). That the real resolver does the work is proven at source level: the plan file calls `resolve_install_plan`, and both install paths still call it. Your dev02 checklist covers the live wiring.

## Assumptions

- The plan covers the licensed catalogue only. Index repositories (the default and custom ones) keep the single stage route. Anything not on the allowed list is blocked `not_in_allowed_list`.
- A release with no matching saved catalogue entry is blocked (fail closed). The runtime and optional-dependency data exist only in that entry.
- `will_disable` is empty for licensed releases today: neither the allowed row nor the catalogue row carries `replaces`, `capabilities` or a migration. `checks_deferred` names what waits for the package: `replacement`, `rename`, `signature`, `licence-in-manifest`.
- The read-only plan writes no audit row, like `GET allowed/`. The audited start and end belong to R1b.

## What is not in this release

- R1b to R1d (the install run, its progress and stop). The request "read `licensing.allowed_modules` in the batch install" stays open for its install half.
- Plans for index repositories, and the remaining R2 and R3 items.
- The replacement, rename, signature and licence checks before download: they need the package, or `replaces` on Licensing's rows (asked of Licensing as information).
- The held Low "online catalogue reads each repository cache twice" is not on this path.
