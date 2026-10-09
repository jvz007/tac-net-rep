# Tec-Tac Framework 1.17.9

Core can now honour a module that replaces a core module (AD-20). Advanced Patch Management can take over Windows Patching's Tactical routes and capability names while Windows Patching is disabled, and Core refuses to run both. The release also closes the held Medium from the 1.17.8 review: an untyped route parameter can no longer carry a module onto a route another module owns.

Closes: the "AD-20 replacement mechanism" entry and the "Provider replace/conflict policy" entry in `reviews/requests/core.md` (the `replaces` half; `conflicts_with` is not built), and the held Medium from the 1.17.8 review. The "Module mutual exclusion" entry narrows to a note: only the replacement pair is covered.

## What changed

- **Manifest keys `replaces` and `capabilities` (AD-20 condition 1).** Both are optional and additive, for extensions only. `replaces` names one core module. `capabilities` maps a capability id to `X.Y.Z`. Core reads it from the manifest because a disabled core module's code is never loaded. A reportset that declares either is refused, `replaces` is refused on a core module and on the module itself, and a core module's capability ids must start with its own id.
- **Honoured replacement (new `tec_tac/module_replacement.py`).** Core computes it from manifests and module state on every call, never from the run-time registry, so start-up order cannot change the answer. It is honoured only when the replacement is enabled, the core module is installed and disabled, no other enabled module replaces the same core module, the core module declares `capabilities` (an empty `{}` is allowed, an absent key is not), and the replacement declares every one of them at the same major version with a minor and patch that are not lower (AD-20 condition 3). When it is not honoured, the status says why with a reason code. A declared capability that is not registered at run time sets `degraded`, which is information only.
- **Lifecycle (AD-20 conditions 1 and 4).** Core refuses to enable a replacement while its core module is enabled, to enable a core module while an enabled replacement points at it, to enable a replacement that fails the capability check, and to install a replacement while its core module is enabled or missing or when the check fails (problem types `replacement_conflict` and `replacement_incomplete`). The operator disables the core module first, so the two are never enabled together. If state shows both enabled anyway, Core disables neither, does not honour the replacement and logs a warning: starting up never stops Tactical. Disabling the replacement drops its routes and capability names at once, because nothing is stored. Core never re-enables the core module by itself.
- **Tactical operations (AD-20 condition 2).** An honoured replacement joins the owners of every route rule the replaced core module owns (for Windows Patching: `winupdate/` and `automation/patchpolicy/`) and no other. Core's own rules, rules with no owner, and every rule the replaced module does not own stay refused. At dispatch Core answers 404 `tactical_operation_not_found` for a non-core operation owner whose replacement is no longer honoured, so an operation registered in this process stops working the moment the operator changes state, before any restart.
- **Capability names (AD-20 condition 3).** `register_capability` keeps its signature. An id under the replaced module's prefix is accepted from the honoured replacement only when the id is in its declared `capabilities`. Any other module still gets the "must begin with provider module prefix" error. `capability_status` reports the replacement as the provider, so consumers keep calling the same name. `list_capabilities` rows gain `replaces`. While the replaced module is disabled and the replacement has not registered a name, the state is `capability-unavailable` and the reason names the replacement.
- **Held Medium from the 1.17.8 review (route ownership).** The owner check no longer skips a parameter that holds a reserved route word followed by more route. It now looks at the parameter kind. A parameter of kind `agent` or `int` can never hold a route word. A plain `{name}` parameter keeps every expansion, so `agents/{agent_id:agent}/{p}/create-key/` is judged against Remote Background's registry rules and refused to Agents, `agents/{a:agent}/{t}/{l}/{d:int}/` reaches eventlog and webvnc, and `agents/{x}/` reaches update, versions and bulkrecovery. The length-based skip is deleted. One rule, `agents/{}/{}/webvnc/`, now matches only a path of exactly that length, because it names a single route. Without that, Remote Background could not declare `agents/{agent_id:agent}/eventlog/{logtype}/{days:int}/`, since a `logtype` of `webvnc` would land on Take Control's rule. Defence in depth at dispatch: after the concrete path is built, Core finds the rule it lands on and refuses unless the operation's module owns that rule.
- **Catalogue rows.** `GET /api/tfd/modules/v2/` rows gain `replaces`, `replacement` (a status object) and `replaced_by`, and the module-manager package preview gains `replaces` and `capabilities`.
- **Docs and contract.** New `docs/module-replacement.md`. `docs/tactical-operations.md`, `docs/capabilities.md` and `docs/module-interoperability.md` updated. The contract catalog lists `tec_tac.module_replacement.honoured_replacement`, `replaced_by` and `replacement_status`, the new rule, and the problem types.
- **Superseded.** The sentence in the 1.17.8 notes that premium replacement modules are still refused is superseded by this release.

## Module-facing changes

Everything here is additive except the last item.

- **New manifest keys** `replaces` and `capabilities` in `tec_tac.json`. A module that uses them must require `framework >=1.17.9`.
- **New problem types** `replacement_conflict` and `replacement_incomplete` on enable and install (HTTP 400, as before).
- **New catalogue fields** `replaces`, `replacement` and `replaced_by` on module rows, and `replaces` on capability rows.
- **New Python contract** `tec_tac.module_replacement`: `honoured_replacement(module_id)`, `replaced_by(core_module_id)`, `replacement_status(module_id=None)`.
- **`register_capability`** accepts a replaced module's capability ids from its honoured replacement. No other module's registration changes. A scan of every `register_capability` call in `modules/` that can be read statically shows that all of them still follow the plain prefix rule.
- **Needed before the mechanism is usable.** Windows Patching (`patching`) must declare `capabilities` in `tec_tac.json` (an empty `{}` is fine today) and Advanced Patch Management (`patchmanagement`) must declare `replaces = "patching"` and every capability patching publishes, at the same major version. Both are requests in `reviews/requests/`.
- **Breaking, no compatibility path (held Medium).** A Tactical operation route with an untyped parameter that a reserved route can also match is now refused at registration. Declare `{agent_id:agent}`. The old tolerance was the defect, so no compatibility path is possible. Only the Checks module declares operations today, and its routes use `{agent_id:agent}` and `int` parameters, so nothing in `modules/` is affected.

## Not built

- A general `conflicts_with` key. AD-20 decides replacement only.
- Treating an honoured replacement as satisfying a hard `dependencies` entry on the replaced module's id. Other modules call capabilities by name. No module in `modules/` hard-depends on `patching` today.
- A Core-held allow-list of which module may replace which. AD-20 states the conditions and none is a list. Johan can ask for one.

## Tests

- `tests/module-replacement-1.17.9.py`: manifest parsing, every reason code, enable and install refusal in both orders, both-enabled at start-up, hand back, catalogue rows. The real registry, module state, capability registry and module manager run against a folder of real manifests.
- `tests/module-replacement-owner-1.17.9.py`: the owner table with a replacement, dispatch while honoured and after it stops, the dispatch recheck.
- `tests/module-replacement-capabilities-1.17.9.py`: capability registration and status, and the scan of `modules/`.
- `tests/tactical-operation-route-owners-1.17.9.py`: the parameter-kind rule and Checks' eight real routes.
- `tests/tactical-operations-1.17.7.py` and `tests/tactical-operation-route-owners-1.17.8.py` now use `{agent_id:agent}` (and one case that relied on the old tolerance is now a refusal). `tests/audit-declared-browser-events-1.16.0.py` expects the new fields after `audit_events`.

Not run on the development PC: Django and Tactical are not installed. The root job helper (which calls `set_enabled` without re-running `validate_enable`) and the start-up both-enabled path are proven against stubs and real manifests only. Check on the dev server after the update: enabling Advanced Patch Management while Windows Patching is enabled must be refused. Disable Windows Patching, then enable Advanced Patch Management, and its `winupdate/` operations must register and the capability name must resolve to it.

## Fixed after precheck

- A replacement module whose replacement is not honoured (both enabled, both disabled, parity lost) no longer raises
  `ValueError` from `register_capability` inside its `AppConfig.ready()`. Core logs a warning and leaves the name
  unregistered, so Tactical still starts. Names the replacement does not declare still raise. Status APIs keep explaining why
  the name is unavailable.
- `validate_enable` now counts queued, dispatched and running enable/disable jobs as already applied, so two queued
  jobs (enable `patching`, enable `patchmanagement`) can no longer both pass and produce a both-enabled state.
- Tests: `tests/module-replacement-capabilities-1.17.9.py` (no raise for non-honoured replacement) and
  `tests/module-replacement-1.17.9.py` (pending-job recheck).
- Module-facing: none beyond the above; the registry call returns an unregistered registration object in the skipped case.
