# Tec-Tac Developer Contract Catalog

**Framework baseline:** 1.10.0+

Tec-Tac provides a live developer-contract catalog so module developers and coding agents can discover the public surfaces they may safely build against.

## Why this exists

Static documentation is still useful for design rules and detailed explanations, but module capabilities and scheduler actions are registered at runtime. A hand-written handoff can therefore become stale after modules are installed, upgraded, disabled, or removed.

The Developer Contract catalog combines stable framework contracts with the current live runtime registrations.

## API

```text
GET /api/tfd/contracts/
GET /api/tfd/contracts/export/?format=md
GET /api/tfd/contracts/export/?format=txt
```

These endpoints require an authenticated Tactical user with server-maintenance/superuser authority.

## What is included

### Core Python contracts

The stable framework functions modules may import directly, including:

```text
tec_tac.scheduler
tec_tac.capabilities
tec_tac.registry
tec_tac.module_state
tec_tac.rbac
```

### Registered capabilities

Capabilities currently registered through:

```python
register_capability(...)
```

The catalog includes:

```text
capability ID
provider module
capability version
provider package version
runtime availability state
operations
description
diagnostic reason
```

### Schedulable actions

Actions currently registered through:

```python
register_scheduled_action(...)
```

The catalog includes:

```text
action ID
provider module
label / description
target types
required permission
dangerous flag
```

### Extension permissions

Permission groups and codenames declared by installed extensions.

### HTTP boundary

The currently registered `/api/tfd/` routes and HTTP methods. These are intended for browser or external-process integration.

Backend Tec-Tac modules should still use Python `tec_tac.*` contracts rather than loopback HTTP.

## UI

Tec-Tac UI 0.9.0 adds:

```text
Administration -> Public Contracts
```

The page provides:

- live contract counts;
- search across contracts/modules/permissions/routes;
- runtime capability state;
- registered scheduler actions;
- permission contracts;
- HTTP route listing;
- **Export Markdown**;
- **Export Text**;
- live refresh.

## Recommended coding-agent workflow

Before developing a module:

1. Open **Administration -> Public Contracts**.
2. Click **Export Markdown**.
3. Give the generated `.md` file to the module coding agent.
4. Tell the agent to treat the export and current framework repository as the integration source of truth.
5. For deeper semantics, also read:

```text
docs/core-functions.md
docs/capabilities.md
docs/module-interoperability.md
docs/module-scheduling.md
docs/scheduler.md
```

## Important limitation

The exported catalog documents **public integration surfaces**, not another module's implementation.

It deliberately does not expose:

```text
provider Python objects
private models/helpers
private database schema
secrets/credentials
filesystem internals
```

A consumer should only rely on the public contract shown by the catalog and the provider's documented operation semantics.
