# Tec-Tac Framework 1.17.39

This patch release closes three items of the Core 1.17.39 plan. All three changes are additive. No migration, no database change, and no
change to a value a module already consumes.

1. **Contract row: the signed-in person's superuser flag (`ui.authenticated.runtime-context`).** Core has sent `user.superuser` in
   `GET /api/tfd/ui/context/` since before 1.17.38. The row now lists it, with one details line. It closes the globalsettings 0.6.0 request.
   Documentation only. The flag is the effective superuser (Tactical's `is_superuser` or the role's `is_superuser`). It is a display hint:
   Core and Tactical still decide every call.
2. **Contract row: module preferences (`ui.authenticated.modulePreferences`).** The row now lists `flush()` and carries the debounce
   (400 ms, at most 2 seconds from the first call), the `hideControl` flag on a 403 refusal, and the "old value stays" wording for a 503.
   The numbers are copied from `tec-tac-ui/docs/module-preferences.md` (UI 0.12.108). It closes the module preferences contract row request.
   Documentation only.
3. **Module repository hardening (licensing server assessment, 14 October 2026; Core 1.17.38 verified against the server 0.1.18).** An
   index entry that fails a check is now skipped and recorded. The rest of the index is kept. Before this release, one bad entry failed the
   whole index.

## What changed

- **Each entry is checked on its own (`framwork/tec_tac/module_repository.py`, `_accepted_releases`).** A skipped entry is recorded as
  `{index, id, version, reason}`. `id` and `version` are the entry's own text, cut to 100 characters with control characters removed.
  `reason` is at most 300 characters. The list holds at most 100 records, and `skipped_count` is the real total.
- **Duplicates.** When two entries share an id and version, both copies are skipped with the reason `duplicate`. Neither can be trusted.
- **An index with no valid entry fails.** When the index has entries and none is valid, the sync fails with status `error`, and the old
  cache is kept. A broken publish cannot empty a good catalog. An empty `modules` array is still `ok` with `module_count` 0.
- **Status stays as it was.** The status values are unchanged (`ok`, `error`, `never`, `disabled`). `ok` means at least one entry was kept.
- **Whole-index failures are unchanged.** A non-schema-1 index, a `modules` value that is not an array, a fetch failure, the size limit and an
  address refused by the SSRF guard still fail the whole index and keep the old cache. A download host that does not resolve is now a
  skipped entry.
- **Module ids with a dot are skipped, not allowed.** `docs/module-identifiers.md` does not allow a dot, and a dot separates capability and
  permission prefixes. The reason now says which characters are allowed. The rule itself is unchanged.
- **Five informational release fields (`_validate_release`).** `channel`, `lifecycle`, `downgrade_policy` and `signing_environment` are
  bounded strings (at most 64 characters, control characters removed, null when absent or empty). `recommended` is a strict boolean. A bad
  value becomes null and never drops the entry. The values are not checked against a list. Core never uses them for selection, ordering,
  compatibility, staging or any refusal. The online catalog copies them from the selected release onto each module item.
- **Sync answers and status rows carry `skipped_count` and `skipped`** (`sync_repository`, `repository_status`, `sync_all`, and the
  online catalog through the repository status rows).
- **Non-manager redaction (`module_repository_views.py`).** A caller who cannot manage modules sees a generic sentence in place of each skipped
  reason, because a reason can quote a URL or a host. `id`, `version`, `index` and `skipped_count` stay.
- **Documentation.** `docs/module-repositories.md` gains sections on module ids, skipped entries, informational release fields and
  entitlement. `docs/module-identifiers.md` has one sentence on the dot rule. The three repository HTTP routes have contract rows in
  `contracts.py` (`HTTP_CONTRACT_DETAILS`), marked added 1.17.39, additive, informational.
- **The root release note of 1.17.38** moved to `docs/releases/RELEASE_NOTES_1.17.38.md`, as earlier releases were moved.

## Not built, on purpose

Johan's brief for the licensing server leaves these out, and nothing in this release does them:

- No downgrade refusal on stage or install. `downgrade_policy` is passed through as information only.
- No revoked-module warning. Nothing reads or shows a revoked flag.
- No default repository seeding (a built-in Tech Flow repository entry).
- No licence or entitlement check on repository sync, listing or download. Core's sync and stage code does not call the licensing capability.
- No enum check on the five informational fields. The value lists are not in the tree.

## Module-facing changes

Heading for module authors. Every change is additive. A module that uses none of these keys is unaffected.

- **(a) The two browser contract rows are documentation.** Core already sends `user.superuser` in the runtime context. `flush()` is a UI 0.12.108
  helper that Core does not serve. No code path changed for either row.
- **(b) `sync` answers and status rows carry `skipped_count` and `skipped`.** Informational. Older UI builds ignore them. The `status` values are
  unchanged.
- **(c) Five release fields on `modules[]` and `modules[].releases[]`.** Informational only. Core never acts on them.
- **(d) One behaviour change: an invalid entry is skipped, not a whole-index failure.** Nothing in `modules/` calls the repository functions or
  these routes (grepped: no `module_repository`, `online_catalog`, `catalog/online`, `modules/repositories` or `sync_repository` use under
  `modules/`). `workspace/ui/src/modules.js` calls the same routes and does not read the new keys, so the UI keeps working.
- **Unchanged:** the functions and their arguments, the staging path, the selection rule (priority, pinned source, highest version), and the
  sync status values.
