# Replacing a core module (AD-20)

Some premium modules do the whole job of a core module and do it better. Advanced Patch Management replaces Windows Patching. Core lets one module take over another's place, safely, without both ever running.

This page is for module authors and administrators. The decision is AD-20 (`docs/review-accepted-decisions.md`).

## The two manifest keys

Both keys are optional and additive. A manifest without them parses and behaves exactly as before. Only an extension may use them. A reportset that declares either is refused.

```json
{
  "id": "patchmanagement",
  "replaces": "patching",
  "capabilities": {
    "patching.windows": "1.2.0",
    "patching.scan": "1.1.0",
    "patchmanagement.extra": "1.0.0"
  }
}
```

| Key | Meaning |
| --- | --- |
| `replaces` | The id of one core module this module replaces. Refused on a core module and on the module itself. |
| `capabilities` | A map of capability id to `X.Y.Z`: the public contracts the module publishes. Core reads this from the manifest because a disabled module's code is never loaded. A core module's ids must begin with its own id and a dot. |

A core module that a replacement could target must declare `capabilities`. An empty `{}` is fine for a module that publishes none. A missing key is not: it would let a core module hide a contract, so Core refuses to honour any replacement of it.

A module that uses either key must require `framework >=1.17.9`.

## When Core honours a replacement

Core works this out from manifests and module state on every call. It never looks at what is registered at run time, so start-up order cannot change the answer. A replacement is honoured only when all five hold:

1. The replacement is enabled.
2. The replaced module is installed, is a core module, and is **disabled**.
3. No other enabled module replaces the same core module.
4. The replaced module declares `capabilities`.
5. The replacement declares every one of those ids at the **same major version**, with a minor and patch that are not lower. Extra capabilities are fine.

Otherwise the replacement is simply not honoured, and its status says why:

| Reason | What it means |
| --- | --- |
| `replacement-disabled` | The replacement is not enabled. |
| `target-missing` | The core module is not installed. |
| `target-not-core` | The module it names is not a core module. |
| `target-enabled` | The core module is still enabled. |
| `competing-replacement` | Another enabled module replaces the same core module. |
| `capabilities-undeclared` | The core module declares no `capabilities` key. |
| `capability-missing` | The replacement lacks one of the core module's capabilities. |
| `capability-major-mismatch` | A capability is at a different major version. |
| `capability-version-lower` | A capability has the same major version but a lower minor or patch. |

`replacement_status(module_id)` returns the status object. It also carries `degraded`: true when a declared capability is not registered at run time. That is information, never a refusal. `registered_mismatch` (1.17.10) also sets it.

## What Core checks at registration (1.17.10)

Declaring is not the same as registering, so Core compares the two when a module registers a capability. It never raises out of `AppConfig.ready()`. It logs one warning, registers nothing, and the name stays `capability-unavailable`.

- A core module that declares `capabilities` registers exactly those ids. A core module with no `capabilities` key is unchanged. If Core cannot read module state, it lets the registration through.
- An honoured replacement registers a replaced module's id at the declared major version, with a minor.patch that is not lower. `capability-major-mismatch` and `capability-version-lower` are the reason codes, the same as the parity check.
- `replacement_status` lists each refused registration in `registered_mismatch` as `{capability, declared, registered, reason}`, and `degraded` becomes true. The list lives in the running process and clears on restart.

## What changes while a replacement is honoured

- **Tactical routes.** The replacement joins the owners of every Tactical operation rule the replaced module owns, and of no other. For Windows Patching that is `winupdate/` and `automation/patchpolicy/`. Core refuses everything else to it. See `docs/tactical-operations.md`.
- **Capability names.** The replacement may register the replaced module's capability ids, only the ones it declares. Consumers keep calling the same names and get whichever module is installed (`docs/capabilities.md`).
- **Catalogue.** Rows from `GET /api/tfd/modules/v2/` gain `replaces`, `replacement` (the status object) and `replaced_by`.

## What Core refuses

| Action | Problem type |
| --- | --- |
| Enable a replacement while its core module is enabled, or while another replacement of it is enabled | `replacement_conflict` |
| Enable a core module while an enabled replacement points at it | `replacement_conflict` |
| Enable a replacement whose target is missing or whose capabilities do not cover the core module's | `replacement_incomplete` |
| Install a replacement while its core module is enabled | `replacement_conflict` |
| Install a replacement whose core module is missing, or that fails the capability check | `replacement_incomplete` |

To switch: disable the core module, then enable (or install) the replacement. To switch back: disable the replacement, then enable the core module. Core never switches for you, and never runs both.

## If both end up enabled anyway

A hand-edited state file, or a privileged job that races, can leave both enabled. Core never stops Tactical for this. It does not disable either module. It does not honour the replacement, logs a warning, and reports `target-enabled`. The core module keeps its routes and contracts. The administrator disables one of the two.

## Hand back

There is nothing to hand back. Honouring is computed from state on every call, so disabling the replacement drops its routes and capability names at once. After the normal reload the core module registers its own again.

## What this does not do

- It adds no general `conflicts_with` key. AD-20 decides replacement only.
- A hard `dependencies` entry on the replaced module's id is not satisfied by its replacement. Modules call capabilities by name instead.
- There is no allow-list of which module may replace which. The guards are signed packages, an administrator disabling the core module, full capability parity, and routes limited to the replaced module's own rules.
