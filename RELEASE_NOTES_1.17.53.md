# Tec-Tac Framework 1.17.53

The public contract now lists FilterEditor, the shared filter editor in the browser.

Modules can read, in the contract export, what the editor takes and sends. Nothing a module does today changes: this release only adds one member to a
documentation row. No endpoint, capability or version moves (`core.filter_sets` stays 1.1.0, `core.tactical_operations` stays 1.15.0).

## Module-facing changes

- **Browser contract row `ui.authenticated.components` gains a member: `FilterEditor` (additive, documentation only).** It is appended last, so the first six members
  (`SearchSelect`, `TagEditor`, `DataTable`, `FormRow`, `EditorWindow`, `Stepper`) keep their places and their text. Request: "core: add FilterEditor to the row
  ui.authenticated.components".
  - Props `viewKey` (required, `^[a-z0-9][a-z0-9_-]{0,60}$`), `modelValue` (a definition or `null`) and `disabled`. Events `update:modelValue` and `apply`, with the
    payload `{ definition, filterSetId }`: exactly one is set, and both `null` means no filter. Never send an empty definition.
  - No module id prop: the loader binds each module's copy to its own id. No AD-20 replacement exception. Not a sandbox: Core decides what a person may read.
  - It reads only `GET /api/tfd/filter-sets/fields/`, `GET /api/tfd/filter-values/` and `/api/tfd/filter-sets/` (POST, PUT and DELETE for Only me sets).
    `registerPublic` gets no components. Needs UI 0.12.116 and Core 1.17.50 (`core.filter_sets` 1.0.0).
  - Date and number controls (UI 0.12.117, Core 1.17.52, `core.filter_sets` 1.1.0): operators, constraints and `relative_units` come from the fields answer. Date
    values are strict `YYYY-MM-DD`, `between` is `{from, to}`, `in_the_last` and `not_in_the_last` are `{amount, unit}`. Numbers are JSON numbers inside `minimum`
    and `maximum`. Days are UTC days. A module declares such a field only once UI 0.12.117 is installed.
  - The wording matches `tec-tac-ui/docs/module-filters.md`. The row's `docs` stays the single path `tec-tac-ui/docs/module-components.md` (CQ158).
  - **No module uses it yet.** Script Manager 0.5.0 is the first planned adopter. A module can build on FilterEditor only after Johan installs 1.17.53 and exports a
    fresh contract: that export is made on the running dev server, and the 1.17.52 export does not list the member.

## Other changes

- `docs/filter-sets.md` gets a short "Browser editor" section that points at the row.
- `RELEASE_NOTES_1.17.52.md` moved to `docs/releases/`, because the release-integrity check allows one root note.

## Tests

- New `tests/browser-contract-rows-1.17.53.py`: the operations list, every FilterEditor needle, the earlier members unchanged (the 1.17.42, 1.17.44, 1.17.50 and
  1.17.51 tests run from it), both exports, the two capability versions, and a cross-check with the UI docs when they sit beside this repository.
- `tests/browser-contract-rows-1.17.50.py` and `1.17.51.py` pinned the exact operations list. They now pin the first six and assert `FilterEditor` is last.

## What could not run here

Django is not installed on this PC. The row is plain data, so the tests read `contracts.py` with `ast` and run the real render functions. Nothing ran against Django.

## Requests closed or answered

- Closed: "core: add FilterEditor to the row ui.authenticated.components".
