# Tec-Tac Framework 1.18.30

Date: 21 November 2026. Core now has the three building blocks that Remote Background needs for Tactical 1.6.1's file browser. Nothing changes for anyone until Remote Background declares file operations in a later release. Core adds no file feature of its own: it only says who may declare the routes and how long a path may be. `main` stays held.

## Module-facing change

`core.tactical_operations` goes from 1.16.0 to 1.17.0. It is additive and still major 1. An operation declared the 1.18.29 way registers and runs exactly as before. A module that uses any of the items below must require `framework >=1.18.30` and can feature-detect with `core.tactical_operations >= 1.17.0`.

1. Two route owners. `agents/{}/files/` and `agents/{}/file-browser-defaults/` belong to `remote-background` (and an AD-20 replacement that Core honours). Agents, Agent Management, Take Control, Endpoints, Script Execution and every premium or server module are refused with the usual owner message. The longest-prefix rule applies, so these two win over `agents/`. Every other owner rule is unchanged.
2. A `uuid` route parameter kind, written `{session_id:uuid}`. It takes only the lowercase canonical form (8-4-4-4-12 hex digits with hyphens). That is what Django's `<uuid:...>` converter in Tactical matches. Uppercase, a missing hyphen, a wrong length, a slash, `..`, a blank value and anything that is not text are refused 400 `invalid_params`. A uuid parameter can never be an agent, client, site or `agent_pk` scope source (refused at registration), because a session id is not one of those ids. `audit.params` and `audit.object_param` may name it. The path is built unquoted, as for the other kinds.
3. A new optional keyword, `register_tactical_operation(path_query_params=[...])`. It lists at most 4 query names, each also listed in `query_params`. Those values may hold up to 4096 characters (`limits.path_query_value_chars`). Every other query value stays at 512. Registration refuses a name that is not in `query_params`, a repeat, a secret-looking name, five or more names, and anything that is not a list of names. The other rules hold for both limits: a string or whole number, not blank, no control characters, no `..` path segment (also percent-decoded), names stay a whitelist. `list_operations`, `get_operation` and the metadata show the new key and limit.

The exact declaration `remote-background` should use for a listing:

```python
register_tactical_operation(
    "file-list", "remote-background", "GET", "agents/{agent_id:agent}/files/",
    ["can_use_file_browser"], [{"type": "agent", "source": "path:agent_id"}], [],
    {"action": "custom:file-list", "object_type": "agent", "audit_fields": []},
    query_params=["path"], path_query_params=["path"],
)
```

For a session route, use `agents/{agent_id:agent}/files/{session_id:uuid}/chunks/` with `{session_id}` in `audit.params`. Register the file operations only when Tactical's Role has the flag `can_use_file_browser` (Tactical 1.6.1 has it, 1.5.2 does not). Core refuses an unknown flag, so a module on 1.5.2 must not declare them.

Modules in `modules/`: the compatibility test reads every route declared there as data. No module declares `agents/{}/files` or `file-browser-defaults`, none has an untyped parameter at the third segment under `agents/`, and none uses `path_query_params` or a uuid kind. All 108 declared routes are judged exactly as before. No compatibility path is needed.

## Closes

- The ORDER "Core 1.18.30, file browser routes part 1" in `reviews/requests/core.md` (plan A1, Johan, 21 November 2026): all three items.

## What changed and why

- `framwork/tec_tac/tactical_operations.py`: the two `ROUTE_OWNERS` rules next to processes, registry, eventlog and terminal-defaults; the `uuid` value pattern, the route-parameter pattern and its error text; `_expansion_rules` treats `uuid` like `agent` and `int`, so a uuid segment never widens the rules a route is judged against; the scope-source check refuses a uuid; `MAX_PATH_QUERY_VALUE` and `MAX_PATH_QUERY_NAMES`; `path_query_params` on the declaration, in `describe()` and in the metadata; `_clean_query` picks the limit per name; capability version 1.17.0 with `declaration_keys_added_in_1_17_0` and `behaviour_added_in_1_17_0`.
- `framwork/tec_tac/contracts.py` (CRLF kept): a new "Added in 1.18.30" note and the three sentences that said 512 characters.
- `docs/tactical-operations.md` (CRLF kept): the route row, the owner table, the two limit sentences, the capability header and a new section after the last one.
- Why a separate keyword and not a bigger limit: a path needs room, a flag or a name does not. The opt-in keeps the 512 limit for every existing declaration.
- Not in this release: the binary chunk relay and the audit rule for it (1.18.31). There is no audit change here. A declared audit field copied from a long query is stored by the existing row rules, including the row's own size cap.

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- The uuid kind is lowercase canonical only, as Django's converter is, and it is refused as a scope source.
- The 4096 allowance is opt-in through `path_query_params`, so every existing declaration keeps 512.
- The capability moves to 1.17.0 so `remote-background` can feature-detect.
- No audit change.

## Retired or changed checks

- Version bookkeeping test `tests/version-1.18.29.py` moved to `tests/legacy/`, and `RELEASE_NOTES_1.18.29.md` moved to `docs/releases/`. Release integrity allows one root note.
- 21 earlier tests pinned the capability version `1.16.0` for `core.tactical_operations`. They now say `1.17.0`. Nothing else in them changed.

## New tests

- `tests/tactical-operation-file-browser-routes-1.18.30.py`: owners (accepted and refused), the expansion rules, the uuid kind (accepted, refused, scope source, audit param), `path_query_params` (4096 passes and reaches `request.GET` and `QUERY_STRING`, 4097 and a 600-character undeclared value are refused, registration refusals, control characters, `..` and blank values, a 1.18.29-style declaration), metadata and docs text, and the module compatibility check.
- `tests/version-1.18.30.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. The stub-based tests run (they reuse the stubs of `tests/tactical-operations-1.17.7.py`). The real URL resolver, DRF views and the database were not exercised. The first real use comes with the Remote Background release that declares file operations.

## Johan dev02 checklist

Run it on dev02 after the signed build installs. Nothing in the file browser works yet, and that is expected.

1. Open the Public Contracts page in Core UI and find `core.tactical_operations`.
   - PASS: the version reads 1.17.0 and the text "Added in 1.18.30" is present.
   - FAIL: it still reads 1.16.0, or the export page errors. Send the page text back.
2. Open Remote Background in Core UI and browse the registry of any online agent.
   - PASS: it loads and edits as before.
   - FAIL: any error that did not appear on 1.18.29. Send the message, the time and the agent.
3. Open the terminal defaults or Take Control on the same agent.
   - PASS: both open as before.
   - FAIL: "route owner" or "not found" errors. Send the message.
4. Reboot an agent from Agents (a test agent only).
   - PASS: the reboot request goes through and the audit log shows one row.
   - FAIL: refused, or no audit row. Send the audit log time and the message.
5. Open Core's service log on dev02 and search for "TacticalOperationRegistrationError" since the install.
   - PASS: none.
   - FAIL: any line. Send the line and the module id.

## Exit list

- Code, docs and contract text for the three items: done.
- 21 old capability-version tests updated, new tests added: done.
- Real Django run, signing and review: not done here (pipeline).
- `remote-background` using the new routes: waits on this release (its own request).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
