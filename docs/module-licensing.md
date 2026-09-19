# Module licensing requirement

**Framework baseline:** 1.14.1+

Tec-Tac modules may declare that installation requires a live entitlement from a versioned backend capability. Licensing is enforced by Core; modules and the browser do not decide whether installation is allowed.

## Manifest contract

Declare `licensing` in the extension `tec_tac.json`:

```json
{
  "id": "reportmanager",
  "type": "extension",
  "version": "1.0.0",
  "licensing": {
    "required": true,
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "capability_version": ">=1.0.0,<2.0.0"
  }
}
```

Fields:

- `required` - boolean. When false/omitted no licensing gate is applied.
- `product` - stable licensing product identifier.
- `capability` - namespaced Tec-Tac backend capability ID.
- `capability_version` - required public capability contract version range.

When `required=true`, all other fields are mandatory.

## Enforcement points

Core checks entitlement during package inspection and **again** during the install request. The installation check resolves the live capability/provider again and does not trust a prior inspection result.

For bundles and multi-package batches every contained module is checked independently. At install time Core re-reads each staged package manifest before evaluating entitlement.

## Licensing provider contract

The declared capability must resolve through `tec_tac.capabilities` and pass normal capability checks (installed/enabled provider, contract version, provider health).

The provider object must expose:

```python
check_entitlement(
    *,
    product: str,
    module_id: str,
    module_version: str,
)
```

Accepted return values:

```python
True
False
{"licensed": True}
{"licensed": False, "reason": "subscription expired"}
{"entitled": True, "edition": "professional"}
{"allowed": False, "reason": "product not assigned"}
```

Provider-specific JSON-safe fields are retained as diagnostic details.

## Failure contract

Inspection or installation fails closed when the provider is missing, disabled, unhealthy, capability-incompatible/unregistered, has an invalid contract, raises during the check, or denies entitlement.

HTTP responses use status `403`:

```json
{
  "detail": "Product 'reportmanager' is not licensed.",
  "code": "licensing_requirement_failed",
  "licensing": {
    "required": true,
    "module": "reportmanager",
    "module_version": "1.0.0",
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "required_capability_version": ">=1.0.0,<2.0.0",
    "state": "unlicensed",
    "licensed": false,
    "reason": "subscription expired"
  }
}
```

Capability availability failures retain the registry state such as `missing`, `disabled`, `unhealthy`, `version-incompatible`, or `capability-unavailable`.

## Security boundary

- The package manifest declares the requirement; it does not grant entitlement.
- The browser cannot bypass the check by editing inspection state.
- The install request resolves entitlement again from the live capability provider.
- Modules must not implement a client-side licensing decision as a substitute for Core enforcement.
