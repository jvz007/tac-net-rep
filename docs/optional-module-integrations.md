# Optional module integrations

Tec-Tac modules may enrich one another, but an optional provider must never become a hidden hard dependency of the consuming module.

## Rule

Use two separate checks for two separate jobs:

- **UI presentation:** use the Core `modules` runtime service to decide whether optional provider UI should be shown.
- **Backend execution/data:** use the Core capability registry and resolve optional providers with `required=False`.

Public Contracts, Module Manager endpoints, filesystem scans, and direct imports of another module's private implementation are **not** runtime discovery mechanisms.

## UI runtime contract

Authenticated UI modules receive `modules` in `register(context)`. It is built from the module snapshot already returned by `GET /api/tfd/ui/context/`; lookups do not make HTTP requests.

```js
export async function register({ modules }) {
  if (modules.isActive('cybercns')) {
    // expose CyberCNS enrichment in this module's UI
  }
}
```

Available operations:

```text
modules.list()
modules.get(moduleId)
modules.has(moduleId)
modules.isInstalled(moduleId)
modules.isEnabled(moduleId)
modules.isActive(moduleId)
modules.version(moduleId)
modules.satisfies(moduleId, versionConstraint)
```

`get()` returns a read-only snapshot with the stable shape:

```json
{
  "id": "cybercns",
  "version": "0.1.13",
  "installed": true,
  "enabled": true,
  "active": true,
  "legacy": false
}
```

An installed but disabled module returns `installed=true`, `enabled=false`, `active=false`. A missing module returns `null` from `get()` and `false` from the boolean helpers.

The browser snapshot is for presentation and startup optimisation only. It is not an authorization or execution guarantee and may become stale after lifecycle changes until the shell reloads.

## Backend capability contract

A provider should expose a narrow, versioned capability. A consumer that can function without it must resolve it as optional:

```python
from tec_tac.capabilities import get_capability

provider = get_capability(
    "cybercns.endpoint_security",
    version=">=1.0.0,<2.0.0",
    required=False,
)

if provider is None:
    # Continue without CyberCNS enrichment.
    ...
```

The capability registry already treats missing, disabled, version-incompatible and unhealthy providers as unavailable. `required=False` converts those expected optional-integration states into `None` rather than failing the consuming feature.

If the provider is genuinely mandatory for the consumer to operate, declare it as a normal hard module dependency and use a required capability lookup. Do not model a mandatory dependency as optional UI logic.

## CyberCNS + Endpoints example

Endpoints should remain usable on servers where CyberCNS is not licensed, not installed, removed, or disabled.

```text
Endpoints page opens
    |
    +-- modules.isActive('cybercns') == false
    |      -> do not render CyberCNS fields/actions/cards
    |      -> do not make CyberCNS-specific UI calls
    |
    +-- modules.isActive('cybercns') == true
           -> render CyberCNS enrichment surface
           -> backend still resolves cybercns.endpoint_security at execution time
```

The backend response may make optional enrichment explicit:

```json
{
  "endpoint": { "id": "..." },
  "integrations": {
    "cybercns": {
      "available": false
    }
  }
}
```

When available, that integration object can contain provider-owned data such as scan state, last scan time, and vulnerability counts.

## Required degradation behaviour

Optional consumers must:

1. continue their primary workflow if the provider is missing or disabled;
2. hide or disable provider-specific UI instead of showing an application error;
3. avoid querying provider APIs when the UI snapshot says the provider is inactive;
4. still validate capability availability on the backend at the moment of use;
5. tolerate the provider becoming unavailable after the browser snapshot was created;
6. never treat UI visibility as authorization;
7. avoid repeated Public Contracts or Module Manager calls merely to discover provider state.

A provider being absent because the customer did not deploy that product is an expected configuration, not an error condition.
