# Tec-Tac Framework 1.17.40

This patch release closes two requests. Both changes are additive. No migration, no database change, and no change to a key a module
already reads.

1. **`core.resources` 1.10.0: `failing_checks`, `agent_count` and `maintenance_mode` on client and site records.** Endpoints 0.7.0 needs them
   to show which clients and sites need attention, and to sort the Scope pane. Closes the request "endpoints 0.7.0: failing_checks,
   agent_count and maintenance_mode on the core.resources client and site records".
2. **Contract row `ui.authenticated.modulePreferences`: the merged-result wording (UI 0.12.109).** The row now says what each call of a merged
   `set()` and `remove()` resolves. Closes the request "Contract row ui.authenticated.modulePreferences: the merged-result wording" and the
   held Low from the 0.12.108 review. Documentation only.

## What changed

- **Three read-only keys, appended last.** After `block_policy_inheritance`, every client record and every site record carries
  `failing_checks` (`{"error": bool, "warning": bool}`), `agent_count` (an integer) and `maintenance_mode` (a boolean). The keys are on
  `list_clients`, `get_client`, `list_sites`, `get_site`, `resolve_resource`, the nested `sites` of a client, and the records returned by
  `create_client`, `update_client`, `create_site` and `update_site`. Agent records never carry them. `CLIENT_FIELDS` and `SITE_FIELDS` list them last.
- **Where the values come from.** `failing_checks` is the value Tactical stores on the client or site, as its own `GET /clients/` returns it.
  A null, a non-object or a non-boolean value reads `false`. Tactical refreshes it only in its periodic cache task, so it can lag a few minutes.
  Treat it as a hint, not a live check. `agent_count` and `maintenance_mode` are read when you call.
- **Scope rule (AD-12).** A site record is computed from its own agents only. A client record is computed only from the sites the caller may see
  (the same `Site.filter_by_role` rule as the nested sites). `agent_count` is the sum over those sites. `maintenance_mode` is true when any of them
  has an agent in maintenance. `failing_checks` is Tactical's stored client value only when the caller sees every site of the client (an
  unrestricted caller and a trusted global service context always do). Otherwise it is the OR of the visible sites' values. A site-only role
  never learns that a hidden site is failing or how many agents it has. A client with no visible site reads `0`, `false` and both `false`.
- **No `can_list_agents` gate.** Tactical's own `GET /clients/` gives these three values to a role with List clients alone, so Tec-Tac does the
  same (AD-5, AD-25). The counts stay limited to what the role may see. Recorded as CQ120.
- **No query per row.** One grouped agent query covers a page of sites, and one covers the nested sites of a page of clients. The failing value
  and the real site count of the clients come from two more queries per page. The count does not grow with the rows, so a 500-row page stays cheap.
- **Audit stays stable.** `client_row` and `site_row` do not carry the keys. They are added at the public return points. `_audit_view` also drops
  them, and `update_client` and `update_site` compare the plain rows, so a Tactical refresh of `failing_checks` between the read and the save
  does not write a `modify` row.
- **Contract export and docs.** `CONTRACT_VERSION` is `1.10.0`. `resource_contract_metadata` lists the three names in the client and site
  fields, and carries the new text keys `failing_checks_agent_count_maintenance_mode` and `live_state`. The `contracts.py` rows for
  `list_clients`, `get_client`, `list_sites`, `get_site` and `resolve_resource` name the keys, and the create and update rows say the returned
  record carries them. `docs/resource-directory.md` has the new header, a "Contract 1.10" paragraph and a "Live state (since 1.10.0)" section.
  The HTTP routes `GET /api/tfd/resources/clients/` and `sites/` pass records through unchanged, so they carry the keys. `install.sh` needs
  no change: its check is tied to `CONTRACT_VERSION` and the range `>=1.1.0,<2.0.0`.
- **Module preferences wording.** In the `ui.authenticated.modulePreferences` row, "Every call whose write was merged gets the same outcome" is
  replaced by the per-caller rule: the last operation in the 400 ms window decides. When it is a `set()`, every `set()` resolves the value Core
  stored and every `remove()` resolves `false`. When it is a `remove()`, every `remove()` resolves `true` or `false` as Core answered and every
  `set()` resolves `undefined`. Every merged caller gets the same rejection. The purpose line names UI 0.12.109 or later, because the earlier
  helper gave a result of the wrong type. `docs/module-preferences.md` carries the same two lines. No number, operation, refusal or capability
  version changed: 400 ms, 2 seconds and `flush()` stay.
- **The root release note of 1.17.39** moved to `docs/releases/RELEASE_NOTES_1.17.39.md`, as earlier releases were moved.

## Module-facing changes

Every change is additive. A module that reads only named keys is unaffected.

- **`core.resources` 1.9.0 to 1.10.0 (needs framework 1.17.40 or later).** Client and site records gain `failing_checks`, `agent_count` and
  `maintenance_mode` after `block_policy_inheritance`. The scope rule above decides what each caller sees. Nothing else in the contract moved:
  no keyword, route, error or filter. Grepped `modules/`: 19 modules call `core.resources` (agents, alerts, audit, automation, checks, cyberhoot,
  endpoints, governance-compliance, huntress, licensing, networkprobe, notifications, patching, reportmanager, scoutdns, scriptexecution,
  software, tasks, userinvite). All read named keys. None checks an exact key set or reads the three new names on a client or site record.
- **Endpoints.** Core builds nothing on the Endpoints side. Sorting the Scope pane on `failing_checks` waits for the fresh contract export
  that lists the new fields (see `reviews/questions/core.md`).
- **The module preferences row is documentation.** No code path changed. No module uses `core.module_preferences` or the row.

## Not done here

- Tests that need Django and Tactical did not run on the development PC. `tests/resource-live-state-runtime-1.17.40.py` compares the three
  keys with Tactical's own `ClientSerializer` and `SiteSerializer` output for a real client and site. It runs on the dev server only.
- The held Medium "Nested sites shown to a role without List sites" is not touched. The nested live keys follow the same visibility as the nested
  site record, so they open nothing more.
