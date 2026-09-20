# Tec-Tac Developer Contract Catalog

**Framework baseline:** 1.10.0+

Tec-Tac provides a live developer-contract catalog so module developers and coding agents can discover the public surfaces they may safely build against.

## Why this exists

Static documentation is still useful for design rules and detailed explanations, but module capabilities and scheduler actions are registered at runtime. A hand-written handoff can therefore become stale after modules are installed, upgraded, disabled, or removed.

The Developer Contract catalog combines stable framework contracts with the current live runtime registrations.

## API

```text
GET /api/tfd/contracts/
GET /api/tfd/contracts/export/?export_format=md
GET /api/tfd/contracts/export/?export_format=txt
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

Backend modules that own generated schedule definitions use the public scheduler reconciliation contract:

```python
reconcile_schedule(...)
disable_owned_schedule(...)
remove_owned_schedule(...)
```

This keeps schedule ownership/idempotency inside Core and avoids direct `TecTacSchedule` model imports or localhost HTTP calls.

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

## Execution semantics in exported rules

Framework 1.10.3 adds execution-result guidance to the generated Markdown/Text handoff. Coding agents should treat these rules as part of the public development contract:

- transport acknowledgement is not operation success;
- scheduled handlers must propagate downstream execution failure;
- providers should distinguish `dispatched` from verified `executed`/`delivered`;
- raw OS commands must be built and tested for the exact shell used by the production agent transport;
- Windows `cmd.exe` quoting, especially executable paths under `Program Files`, must be tested end-to-end.

These rules prevent a scheduler/capability operation from being recorded as successful when only the transport succeeded while the endpoint application or shell command actually failed.

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


## Scheduler hardening in Framework 1.11.0

- Completed or expired one-off schedule definitions are cleaned automatically after the configured retention period. The default is 48 hours and operators may configure 1-720 hours from the Scheduler configuration surface. Run history is preserved independently of the schedule definition.
- Scheduler diagnostics expose tick freshness, queue/dispatch state, enabled schedule count, queued/running runs and recent failures.
- Framework self-tests cover immediate dispatch, true scheduled execution, deliberate permanent failure and retry/recovery.
- Permanent failures must not be blindly retried. Module handlers may raise `SchedulerPermanentError` or `SchedulerTransientError`; capability unavailable/version mismatch/disabled and validation-style failures are treated as permanent.
- A handler must only report success after its owned downstream operation has completed successfully. Transport acknowledgement alone is not business-operation success.
