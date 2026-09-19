# Tec-Tac Framework 1.14.1

## Manifest-declared licensing enforcement

Module extension manifests may now declare a required licensing entitlement:

```json
{
  "licensing": {
    "required": true,
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "capability_version": ">=1.0.0,<2.0.0"
  }
}
```

Module Management v2 validates this requirement during package inspection and resolves it again during the install request. Installation is denied if the capability provider is missing, disabled, unhealthy, incompatible, exposes an invalid entitlement contract, errors during the entitlement call, or reports the product as unlicensed.

Licensing failures return HTTP 403 with `code=licensing_requirement_failed` and a structured `licensing` diagnostic object.

The public licensing capability contract requires `check_entitlement(product=..., module_id=..., module_version=...)` and accepts a boolean or an object containing `licensed`, `entitled`, or `allowed` plus optional `reason`/details.
