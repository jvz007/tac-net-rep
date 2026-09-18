# Tec-Tac Framework 1.10.0

## Live Developer Contract Catalog

Framework 1.10.0 adds a canonical live catalog of the public contracts available to Tec-Tac module developers.

### New backend contract catalog

- `GET /api/tfd/contracts/`
- `GET /api/tfd/contracts/export/?format=md`
- `GET /api/tfd/contracts/export/?format=txt`

The catalog combines:

- stable Tec-Tac core Python contracts;
- runtime-registered cross-module capabilities;
- runtime-registered Scheduler actions;
- extension permission contracts;
- authenticated `/api/tfd/` HTTP routes and supported methods.

### Canonical exports

Markdown and plain-text exports are generated server-side from the same live catalog used by the UI. This gives coding agents a current, self-contained development handoff rather than relying on a manually maintained snapshot.

### Access

The Developer Contract catalog requires authenticated server-maintenance/superuser authority. The contracts contain integration metadata only; the endpoint does not expose provider objects or private module implementation.

### Architecture

No existing Scheduler or capability-registry contract changes in this release. Framework 1.10.0 builds on Framework 1.9.0 and exposes those contracts for introspection/export.
