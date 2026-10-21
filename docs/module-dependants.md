# Module dependants (Core 1.17.71)

Groups must not let a person delete a group that something still uses (Johan, 21 October 2026). Core helps by telling a module which installed modules depend on it. Core does not look inside those modules.

## What you get

`tec_tac.module_dependants.dependants(*, context=None)`, also the capability `core.module_dependants` 1.0.0 (operation `dependants`, needs framework >=1.17.71). It returns:

```
{"module": "<caller id>",
 "dependants": [{"id", "name", "version", "relation", "constraint", "enabled", "capabilities": [{"id", "version"}]}],
 "complete": True}
```

- `relation` is `required` (the dependant lists you under `dependencies`) or `optional` (under `optional_dependencies`). Required wins if both.
- `constraint` is the version constraint the dependant declared for you.
- `enabled` is the dependant's current state. A disabled module is still listed, because its saved configuration still points at you and enabling it later would use it again.
- `capabilities` are the `{id, version}` pairs the dependant's signed manifest declares. Ask only those, through `get_capability`.
- Rows are sorted by id, at most 200. `complete` is False when more exist. Treat False as "could not check".

Nothing else is returned: no routes, permissions, settings, paths, audit events or data of the dependant. Legacy modules, reportsets and the caller itself are never listed.

## Who may ask

Only a verified, enabled, non-legacy module (rule 1.10, AD-26). Core itself, an unverified caller, a disabled module or a legacy module is refused with `DependantsRefused`. The text names no module. The answer is about the calling module's own id only: a module cannot list the dependants of another.

## When Core cannot read

An unreadable module list or module state raises `DependantsUnavailable`. It never answers an empty list. Groups treats it as "could not check, do not delete".

## What Core does not do

Core calls no provider on behalf of a module. For Groups, a dependant that declares `<id>.groups_usage` is a provider that Groups asks itself through `get_capability`, failing closed. A dependant that declares none is "in use, not checked".

## Registry fields

`registry.PluginSpec` gets `dependencies` and `optional_dependencies`: sorted `(module id, constraint)` pairs, empty when the key is missing or malformed (the registry reads leniently and never stops Tactical starting; the module manager already refuses a malformed manifest at install). Both are left out of equality, so every older `PluginSpec(...)` construction still works.
