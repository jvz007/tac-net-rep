# Tec-Tac Module Visibility Contract

## Status

Design contract for the next Module Management iteration. This document describes the agreed behaviour and should be implemented without changing the meaning of the existing `enabled` state.

## Why visibility is separate from runtime state

Not every installed Tec-Tac module needs to be a permanent navigation destination.

Supporting modules such as **Checks** or **Automation** may be required by other modules, may expose APIs or routes, and may participate in backend workflows while adding little value as a standalone item in the main navigation rail.

Tec-Tac therefore treats module runtime state and module navigation visibility as two separate concerns.

## State model

| Runtime state | Visibility state | Result |
| --- | --- | --- |
| Enabled | Visible | Module is loaded and its declared navigation entry is shown. |
| Enabled | Hidden | Module is loaded and fully operational, but its declared navigation entry is not shown in the main Tec-Tac navigation. |
| Disabled | Hidden | Module is not loaded into the active runtime and is not shown in navigation. |

A disabled module must never be treated as visible. The UI may represent this by disabling the visibility control while the module is disabled or by showing visibility as effectively hidden.

## Meaning of `Hidden`

Hidden means **hide from normal navigation only**.

When a module is enabled but hidden:

- backend APIs remain available;
- Django routes and other runtime services remain available;
- background processing remains available;
- other enabled modules may depend on it;
- other Tec-Tac pages may link directly to its UI routes when appropriate;
- the module remains visible on the Modules administration page;
- backend RBAC and authorization continue to apply normally.

Hidden must not be interpreted as disabled, uninstalled, inaccessible, or unauthorized.

## Dependencies

Visibility must not participate in dependency satisfaction.

For dependency purposes a required module is valid when it is installed, enabled, and satisfies the required version constraint. A hidden enabled dependency is still a valid dependency.

Example:

```text
Endpoints -> requires Checks >=0.1.0

Checks
  Runtime: Enabled
  Visibility: Hidden

Result: dependency satisfied.
```

Disabling Checks may be blocked by enabled dependants such as Endpoints. Hiding Checks must never be blocked merely because another module depends on it.

## Default behaviour

Existing modules and newly installed modules default to:

```text
enabled = true
visible = true
```

This preserves current behaviour during upgrade and avoids unexpectedly removing existing navigation entries.

## Persistent state

Visibility should live beside the existing runtime state in:

```text
/var/lib/tec-tac/module-manager/module-state.json
```

Recommended shape:

```json
{
  "schema": 1,
  "modules": {
    "checks": {
      "enabled": true,
      "visible": false
    },
    "endpoints": {
      "enabled": true,
      "visible": true
    }
  }
}
```

Missing `visible` state must be interpreted as `true` for backward compatibility.

## Framework behaviour

The framework should expose both effective runtime state and visibility state in the module catalog.

Changing visibility must:

1. require module-management authorization;
2. update persistent module state through the privileged lifecycle path;
3. synchronize the deployed UI module manifest;
4. not unload the backend module;
5. not affect dependency validation;
6. not require database migrations;
7. be auditable through the existing module job/history model where practical.

Disabling a module remains a runtime lifecycle action and should continue to exclude the module from active runtime loading and deployed UI synchronization.

## UI behaviour

The Modules administration page should expose runtime and visibility separately.

Recommended presentation:

```text
Module       Runtime     Visibility     Status
Checks       Enabled     Hidden         Healthy
Automation   Enabled     Hidden         Healthy
Endpoints    Enabled     Visible        Healthy
```

The module detail surface should provide a dedicated visibility control:

```text
Visibility
[ Visible ] [ Hidden ]
```

Rules:

- changing visibility must not be presented as enable/disable;
- hiding a module should not require a destructive typed confirmation;
- disabling/removing retains the stronger lifecycle confirmation already used by Module Management;
- hidden modules always remain visible inside Modules administration;
- navigation should update after the visibility job completes and UI module synchronization runs;
- if a module is disabled, its effective visibility is hidden.

## Navigation contract

The UI synchronizer/runtime manifest may still contain metadata for an enabled hidden module if needed for direct route registration, but `addNavigation()` must not expose its normal navigation entry.

The implementation must preserve the distinction between:

- **route availability**, and
- **navigation discoverability**.

This allows a page such as Endpoints to link into a hidden Checks view without adding Checks permanently to the left rail.

## Example: Checks

Checks is a strong candidate for hidden operation:

```text
Checks
  Installed: Yes
  Runtime: Enabled
  Visibility: Hidden
```

Endpoints, reporting, health summaries, or diagnostics may continue to consume Checks capabilities while technicians see only the higher-level workflows they use during normal operations.

## Example: Automation

Automation may similarly remain enabled and hidden when its primary purpose is to support actions surfaced from Endpoints, policies, schedules, or other modules rather than acting as a frequent standalone destination.

## Security note

Visibility is presentation state only. It must never be used as an authorization control. A hidden module's backend endpoints remain protected by their normal Tactical/Tec-Tac RBAC requirements.
## Visibility precedence (1.6.1)

A module package may declare a default navigation visibility in its UI manifest. That value is a default only; it is never a permanent lock.

Effective visibility is resolved in this order:

1. Explicit operator override stored in `module-state.json` (`visible: true` or `visible: false`).
2. Package UI visibility default.
3. `true` when neither source specifies a value.

This means a package can ship hidden by default (useful for support modules such as Checks), while an administrator can still choose **Show** in Module Manager. Package upgrades must preserve the administrator override. Runtime enablement remains independent from navigation visibility.

