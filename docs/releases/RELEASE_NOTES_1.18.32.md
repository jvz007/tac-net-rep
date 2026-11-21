# Tec-Tac Framework 1.18.32

Date: 21 November 2026. Agent records in the Resource Directory now say whether the agent is online and which agent version it runs. Core's service-user migration keeps Tactical's own account defaults. Two notes and a test guard from 1.18.31 are corrected. `main` stays held.

## Module-facing change

`core.resources` goes from 1.12.0 to 1.13.0. It is additive and still major 1. Needs framework >=1.18.32. Feature-detect with `core.resources >= 1.13.0`.

- Every agent record from `list_agents`, `get_agent`, `GET /api/tfd/resources/agents/` and `GET /api/tfd/resources/agents/<id>/` gains two read-only keys at the end: `status` and `version`. The nine old keys keep their names and places. `AGENT_FIELDS` is now the nine old keys plus `status`, `version`.
- `status` is Tactical's own word: `online`, `offline` or `overdue`. Core works it out from the agent row's `last_seen`, `offline_time` and `overdue_time` with the rule of Tactical's `Agent.status`. An agent that never reported is `offline`. Older than `offline_time` minutes (default 4) and not older than `overdue_time` minutes (default 30) is `offline`. Older than both is `overdue`. Anything else is `online`, including a `last_seen` exactly on a limit, as in Tactical. No state is invented.
- `version` is Tactical's agent version text. It is an empty string when Tactical holds none.
- The rows come from the same scoped query as before. There is no new route, permission or global read, and no sort or filter on the two keys.
- No module in `modules/` compares a whole agent record against a fixed key set. The modules read the record key by key, so they keep working. Remote Background 0.11.2 reads `status` and `version` when present and falls back otherwise.
- The contract text for `list_agents` and `get_agent`, `resource_contract_metadata()` and `docs/resource-directory.md` carry the change.

## Closes

- The request from remote-background 0.11.2 (21 November 2026): status and version on the agent record of `core.resources`. The release manager removes that entry from `reviews/requests/core.md`, naming 1.18.32.
- Two held Low findings from the Core 1.18.31 and 1.18.31-1 reviews: the raw INSERT dropped Tactical's model defaults for the service user, and the rebuild-label guard of `version-1.18.31.py` checked the wrong version. The release manager removes both from `reviews/core/BACKLOG-new-findings.md`.

## What changed and why

- `framwork/tec_tac/resources_adapter.py`: `agent_status` (new, pure, takes an optional `now`) re-expresses Tactical's rule from the columns. It uses Tactical's defaults 4 and 30 when a row lacks the limits, and treats a `last_seen` that is not a datetime as never reported. `agent_row` adds the two keys. `page_agents` and `get_agent_row` also read `offline_time`, `overdue_time` and `version`. Core copies no Tactical code.
- `framwork/tec_tac/resources.py`: `AGENT_FIELDS`, `CONTRACT_VERSION` 1.13.0 and a history comment. `framwork/tec_tac/contracts.py`: the purpose text of `list_agents` and `get_agent`.
- `docs/resource-directory.md`: header, a "Contract 1.13" paragraph, the sample record, the stable-fields line, a section "Agent status and version (since 1.13.0)" and a versioning entry.
- `framwork/tec_tac/migrations/0038_communicator_service_user.py`: the raw INSERT now takes the value from the historical model for every column the model knows and that has a default. Django's old `create()` wrote these, and the 1.18.31 INSERT dropped them. The service user now gets dark mode on, 50 agents per page, a splitter at 11, a red loading bar, the `editagent` double-click action and the other defaults, including callable ones. Columns the model does not know (the Tactical 1.6.1 columns from accounts `0043` and `0044`) keep the neutral values. The role stays least privilege: every boolean is false except `can_send_cmd`, even where the model default is true. Values the migration passes explicitly (username, role, `block_dashboard_login`, `is_active`) still win. `_row_values` stays pure and takes a `model_defaults` mapping. `0045` reuses this code, so only its comment changed.
- Corrected notes: `tests/version-1.18.31.py` now looks for a rebuild label of 1.18.31, not 1.18.30. The 1.18.31 release notes said "One dependency line changes. No behaviour changes." That was wrong. They now say that `0038` is pinned to accounts `0042`, that it inserts over the live table columns, and that the new idempotent migration `0045` retries the creation. Text and test only.
- `tests/release-integrity.sh` runs the new defaults test before every pack.
- Version 1.18.32 in `VERSION` and `tec_tac_package.json`.

## Assumptions

- Tactical v1.5.2's `Agent.status` is the rule to follow, equality quirk included: a `last_seen` exactly on `offline_time` or `overdue_time` is `online`. The rule was read from the v1.5.2 reference only; it was not checked against 1.6.1.
- A naive `last_seen` is read as UTC. Tactical stores aware times, so this only protects old stubs.
- No repair migration for service-user rows that 1.18.31 already wrote with neutral values on fresh Tactical 1.5.2 installs. That user cannot sign in (`block_dashboard_login` is true), and the build is on `dev` only. Left out. Revisit if Johan asks.

## Retired or changed checks

- `tests/version-1.18.31.py` moved to `tests/legacy/` and `RELEASE_NOTES_1.18.31.md` moved to `docs/releases/`. Release integrity allows one root note. The guard was fixed and run before the move.
- Ten existing tests that pinned contract 1.12.0 now pin 1.13.0: `resource-alert-template-1.17.17.py`, `resource-client-sites-1.17.22.py`, `resource-custom-field-definitions-1.17.23.py`, `resource-directory-foundation.py`, `resource-expected-guard-1.17.51.py`, `resource-live-state-1.17.40.py`, `resource-move-site-1.17.25.py`, `resource-policy-fields-1.17.24.py`, `resource-service-context-1.17.30.py` and `resources-agent-sort-1.17.58.py`. `resource-alert-template-1.17.17.py` now checks that the first nine agent keys are unchanged, and its shared stub tolerates a row without the three new columns. `resource-directory-foundation.py` carries the two keys in its stub agents. `installer-rollback-verify-1.17.98.py` uses its own stub value and is unchanged.

## New tests

- `tests/resources-agent-status-version-1.18.32.py`: the field list, the status rule as a table with a fixed clock (never reported, online, offline, overdue, custom limits, the limits themselves, a naive time, a non-datetime), `list_agents` and `get_agent` key order, scope (nothing new readable), old stub rows, contract version, docs and contract text.
- `tests/communicator-service-user-defaults-1.18.32.py`: the sqlite stand-in of 1.18.31 with a stub model that has `concrete_fields`. It checks the user defaults, the neutral values for unknown columns, a role with only `can_send_cmd` true even when a model default is true, that passed values win, and that a model stub without `concrete_fields` still works.
- `tests/version-1.18.32.py`: release bookkeeping, including the corrected 1.18.31 notes and the 1.18.32 rebuild-label pattern.

## What could not be run here

Django is not installed for these tests. The new tests stub it, and sqlite stands in for the accounts tables. A real `migrate` on Tactical 1.5.2 and 1.6.1 did not run. The `*-runtime-*` resource tests need Django and a database and did not run. `tests/resource-directory-foundation.py` passes its agent checks and then stops at the first real database call (`create_client` needs Django settings). It stopped at the same line before this change.

## Johan dev02 checklist

1. Call `GET /api/tfd/resources/agents/` as a signed-in user and look at one record.
   - PASS: the record ends with `status` (`online`, `offline` or `overdue`) and `version`, and the old keys are as before.
   - FAIL: either key is missing, or the old keys changed. Send the JSON of one record.
2. Compare one online agent and one switched-off agent with Tactical's own agents screen.
   - PASS: `status` matches Tactical's word for both, and `version` matches the agent version Tactical shows.
   - FAIL: any mismatch. Send the hostname, Tactical's status and the record.
3. Sign in as a user limited to one site and list agents.
   - PASS: only that site's agents appear, as on 1.18.31.
   - FAIL: an agent from another site appears. Send a screenshot.
4. Open Remote Background and look at an agent's status.
   - PASS: the screen works as before.
   - FAIL: any error page or empty list. Send the message and the time.
5. On a fresh Tactical 1.5.2 install, install Core, run `manage.py migrate`, then look at the Communicator user's settings in Tactical.
   - PASS: the user exists with the send-commands role only, and its dark mode, page size and loading bar colour match Tactical's defaults.
   - FAIL: the user is missing, or "could not be made" appears in the Core log. Send the log.

## Exit list

- Agent `status` and `version`, contract 1.13.0, docs, tests: done.
- Service-user defaults in `0038`, test: done.
- 1.18.31 guard and notes corrected: done.
- Real Django `migrate`, signing and review: not done here (pipeline, dev02).
- Not done: a sort or filter on `status` or `version` (not asked; Agents owns the status word for its screens), a repair migration for 1.18.31 service-user rows (see Assumptions), the binary relay and the other open requests in `reviews/requests/core.md`, and a refreshed `docs/contracts/tec-tac-public-contracts*.md` (generated on the server after install).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
