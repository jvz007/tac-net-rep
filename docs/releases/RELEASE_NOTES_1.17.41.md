# Tec-Tac Framework 1.17.41

This patch release fixes the Online catalog and adds three opt-in abilities to Tactical operations. Everything is additive. No migration,
no database change, and no change to a key a module already reads.

1. **The Online catalog shows what the repositories offer.** Johan's dev-server test of 15 October 2026 showed only the modules already
   installed. The list now comes from the enabled repositories, and it says plainly why it is empty.
2. **`core.tactical_operations` 1.11.0.** Core can relay a streamed Tactical file (report PDF, asset download). A DELETE or POST can declare
   a query string. A route can carry a Windows service name. Closes the request "Tactical operations: relay a streamed file answer (blocks PDF)"
   (reportmanager 0.5.0, including the report asset download) and items (a) and (b) of "Tactical operations: three additions so remote-background
   ..." (item (c) shipped in 1.17.18).
3. **The wording of Tactical's `client_tree_sort`.** Documentation only.

## What changed

- **Online catalog (`GET /api/tfd/modules/catalog/online/`).** `modules[]` holds only modules that at least one enabled repository's cache
  offers. Each item still carries `installed`, `installed_version`, `update_available`, `compatible`, `available_sources` and `releases`.
  An installed module that no enabled repository offers leaves `modules[]` and goes to the new `installed_only[]`
  (`id`, `name`, `installed_version`, `installed_source`). It is no longer presented as available. `count` is `len(modules)`.
- **`availability`.** A new object says what the list can honestly say. `state` is `no_repository` (no enabled repository), `not_synced`
  (enabled, none synced yet), `sync_failed` (every enabled repository's last sync failed and none has a cache), `empty` (synced, no modules)
  or `ready`. It also carries `enabled_repositories`, `synced_repositories`, `installed_only_count` and a one-sentence `message`, empty when the
  state is `ready`. For example: "No module repository is set up. Add one under Repositories, then sync it."
- **Unchanged on purpose.** A cache kept after a failed sync still counts as synced, so its modules stay offered. A person who cannot manage
  modules gets the same redaction and never sees a repository address. The GET never calls a repository: Sync stays the only action that does.
  The pinned-source rule is the same: a module pinned to a repository that does not offer it is `source_conflict` only when another repository
  offers it, and otherwise sits in `installed_only`. Core still seeds no default repository.
- **File relay: `file_response`.** `register_tactical_operation(..., file_response=True)` (a strict bool, GET or POST only) lets Core read
  Tactical's streamed `FileResponse` chunk by chunk, up to 25 MiB (the cap every answer already has), close it, and carry on as for any answer:
  the same status handling and the same rows (success with the declared action, deny for 401 and 403, failed for another 4xx on a change,
  outcome-unknown for a 5xx). `Content-Type` and `Content-Disposition` are relayed with the bytes. A stream over the cap is cut, closed and
  refused as `tactical_response_refused`. The audit row never carries the file name or the bytes. Without `file_response` a stream is refused
  exactly as before (now also closed). `list_operations` and `get_operation` show `file_response`. `agents/installer/` stays a route Core forbids.
- **`query_params` on any method.** The rule that only a GET operation may declare a query whitelist is lifted, because Tactical's registry
  delete-key and delete-value read `request.query_params` on a DELETE. The protections stay: a whitelist of names, flat values of at most 512
  characters, no control characters, no `..` segment, and a name that looks like a secret is refused at registration. `audit_fields` may name a
  query parameter.
- **Route parameter kind `service`.** `{svcname:service}` takes a Windows service name: first character a letter, digit or underscore, then
  letters, digits, space and `$ # ( ) . , _ -`, at most 256 characters, no slash, no `..`. The value is stripped first, as for every kind, and the
  path is built unquoted, so Tactical's own `<str:svcname>` pattern resolves `MSSQL$SQLEXPRESS` and `Print Spooler`. The kind `str` still refuses
  `$` and a space. The owner table is unchanged: `services/` is Remote Background's alone. `audit.params` may name it.
- **`client_tree_sort` wording.** The runtime-context row, `docs/my-account.md` and `docs/resource-directory.md` now say that `alphafail` is
  Tactical's "Move failing clients to the top" and `alpha` is A to Z, that Core publishes the person's setting and the failing state
  (`failing_checks`, as of Tactical's last periodic refresh), and that Core never sorts. No key, version or behaviour changed.
- **Capability and contract rows.** `core.tactical_operations` goes 1.10.0 to 1.11.0, still major 1, with `declaration_keys_added_in_1_11_0` and
  `behaviour_added_in_1_11_0` in its metadata. The `contracts.py` rows for the declaration, the HTTP route and the online catalog carry the new
  text. `docs/tactical-operations.md` replaces the "What does not work yet" paragraph and adds "Added in 1.17.41". `docs/module-repositories.md`
  has "What the online catalog shows (1.17.41)".
- **Release housekeeping.** The root release note of 1.17.40 moved to `docs/releases/RELEASE_NOTES_1.17.40.md`.

## Module-facing changes

All additive. A declaration that uses none of the three new things behaves exactly as before, with the same text and the same rows.

- **`core.tactical_operations` 1.10.0 to 1.11.0 (needs framework 1.17.41 or later; feature-detect with `>= 1.11.0`).**
  - `file_response` on `register_tactical_operation`. Reportmanager can enable the PDF template run, the PDF history open and the report asset
    download. A file over 25 MiB is refused.
  - `query_params` on a DELETE, POST, PUT or PATCH declaration. Remote Background can declare the registry delete-key and delete-value operations.
  - `{name:service}` in a route. Remote Background can declare `services/{agent_id:agent}/{svcname:service}/` for start, stop, restart and startup type.
  - Grepped `modules/`: 17 modules declare operations. `tactical_response_refused` is still handled by agents, automation, checks and
    scriptexecution and keeps its meaning for an operation that does not declare `file_response`. No module declares `file_response`, a query on a
    non-GET operation or the `service` kind yet, so nothing in `modules/` changes behaviour.
- **Online catalog route (browser only).** `modules[]` now means "offered by a repository". `installed_only[]` and `availability` are new, and
  `count` is the length of `modules`. No module in `modules/` calls `/api/tfd/modules/catalog/online/`. Only Core UI reads it (`src/modules.js`,
  `ModulesView.vue`). The follow-up is in `reviews/requests/ui.md`.

## Closes

- reportmanager 0.5.0: "Tactical operations: relay a streamed file answer (blocks PDF)", including the report asset download.
- remote-background 0.3.0: items (a) `query_params` on DELETE and POST, and (b) the service-name parameter kind. Items (d) and (e) stay open.
- Johan's dev-server test of 15 October 2026: the Online catalog showed only installed modules.

## Not built, on purpose

- A default repository, and an automatic or scheduled repository sync (CQ121, CQ122: assumption only).
- A larger cap for a relayed file (CQ123: assumption only).
- The `agents/installer/` operation: it needs a route-owner decision and a review of the token in the answer.
- Sorting by `client_tree_sort`: Core publishes, the consumer orders (CQ124).

## Not run on the development PC

Django and Tactical are not installed here. The tests read the real source with stubs. These need the dev server: a real Tactical `FileResponse`
through `run_tactical_operation`, and the Online catalog against a real repository cache. After the update, export a fresh public contract: it
must list `core.tactical_operations` 1.11.0 and the new catalog keys.

## Tests

`tests/online-catalog-availability-1.17.41.py`, `tests/tactical-operation-file-response-1.17.41.py`,
`tests/tactical-operation-query-service-1.17.41.py`, `tests/client-tree-sort-wording-1.17.41.py`. The capability version pins in the 1.17.7,
1.17.14, 1.17.16, 1.17.23 and 1.17.28 tests moved to 1.11.0, the 1.17.13 test no longer asserts that a POST cannot declare `query_params`, and the
1.17.21 test lists `file_response` among the described keys.
