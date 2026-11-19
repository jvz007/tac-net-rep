# Tec-Tac Framework 1.18.18

Date: 19 November 2026. Every refused or failed attempt to tick or untick a premium module now leaves an audit row, and Core now calls the published Core-only operation of Licensing instead of an unpublished method. This is one theme: premium module selection.

## What changed and why

### 1. One audit row for every selection attempt that does not end saved

Until now only four answers (`locked`, `unknown_module`, `bad_request`, `required_by`) wrote a row. A selection that failed because Licensing was down, a licence or plan had expired, or the caller was not allowed left no trace. That closes the held Low 3 of the Core 1.18.10 review.

- `PUT /api/tfd/modules/catalog/allowed/selection/` writes one `deny` row on `module_selection` for every answer whose state is not `saved`. A `saved` answer keeps its `modify` row.
- The metadata holds `result` (the state word), `selected` and `outcome`. `outcome` is `refused` for the four answers above (Core or Licensing said no) and `failed` for every other state (no usable answer). `required_by` also lists the blocking module ids, at most 50.
- A failed attempt is also a `deny` row. Core's `custom:operation-failed` action cannot be written through the audit helper, and a separate writer would add a new audit path. The `outcome` word tells the two apart.
- The message is fixed Core text built from state words: "Refused to change the selection of halopsa: locked." or "Could not change the selection of halopsa: licensing_unavailable. Nothing was changed." Nothing Licensing sent, and no key, grant, token or server address, goes into a row.
- A malformed module id gives `object_id` none and never reaches the log.
- The audit write still never raises. HTTP statuses and response bodies do not change.

### 2. Core requires licensing.allowed_modules 1.1.0

`ALLOWED_CAPABILITY_RANGE` is now `>=1.1.0,<2.0.0`. Licensing 0.10.7 registers 1.1.0 with the published, gated, Core-only `set_selection`. Core already called it with keyword arguments from `licensing_catalogue_source.py`, so no call changes. This closes the held Medium of the 1.18.10 review ("Selection route calls an unpublished, ungated Licensing provider method"). `licensing.catalogue` (`CAPABILITY_RANGE`) is unchanged. The contract export text and `docs/module-repositories.md` say the same.

## Module-facing change

- Core now needs `licensing.allowed_modules` 1.1.0 or later. A Licensing that registers only 1.0.0 (0.10.5 or 0.10.6) reads as `licensing_unavailable` on the list, refresh and selection routes. There is no fallback to the old method and never an unrestricted list. Update Licensing to 0.10.7 (signed 18 November 2026) before or together with this Core.
- No module in `modules/` calls the capability. Welcome 1.2.15 reaches it only through Core's three routes, whose bodies and statuses do not change. Its picker already shows the `licensing_unavailable` state.

## Johan test checklist

a. Update Licensing to 0.10.7 first, then Core to 1.18.18. In Welcome, open the module picker. Expected: the list loads. FAIL: it shows "licensing unavailable". Send the Licensing version and the Core audit log.
b. Untick a licensed premium module and tick it again. Expected: two `modify` rows on `module_selection`. FAIL: a row is missing or has a `deny` action.
c. Untick a module another selected module needs. Expected: the 409 answer and one `deny` row with `outcome` `refused` and the blocking ids. FAIL: no row.
d. Stop the Licensing module, then untick a module. Expected: a 503 answer and one `deny` row with `outcome` `failed` and `result` `licensing_unavailable`. FAIL: no row, or the row shows Licensing's own text.

## What could not be run

Django is not installed on this PC. The view test (`tests/premium-untick-audit-1.18.18.py`) drives the real view with stub `rest_framework`, `drf_spectacular`, `session_security`, `views` and `audit` modules and the real source file with a fake provider. The real audit table and the registry's version matching were not exercised. `ruff check`, py_compile and `tests/release-integrity.sh` were run where possible (see the report).

## Assumptions

- A failed attempt is a `deny` row with `outcome` `failed`, not a new action word. Say if you want a distinct word.
- Raising the range fails closed on a server with Licensing 0.10.5 or 0.10.6, as the rules require.

## What is not in this release

- Sandbox changes wait for the dev02 canary.
- Reading `licensing.allowed_modules` in the batch install (R1) waits for its own release.
- The held Low about one unexpected catalogue id hiding the whole allowed list is a different code path and stays held.
