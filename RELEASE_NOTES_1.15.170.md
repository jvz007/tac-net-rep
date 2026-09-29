# Tec-Tac Core 1.15.170

Module-development contract catalog release.

## Browser / UI contracts in Public Contracts
- Adds a first-class `browser` section to the live Developer Contract catalog.
- The browser catalog is present even when no provider modules are installed, so coding agents can discover stable UI integration services from the same export used for backend contracts.
- Cataloged authenticated services include Core-owned API transport, audit, context actions/interactions, resource views, code editor, dashboard widgets, Quick Actions, notifications, Help, header contributions, module status and read-only runtime context.
- Cataloged public services include the bounded `registerPublic(context)` runtime and SSO provider registry.
- Each browser row publishes its phase, service, supported operations, audience, canonical UI documentation path and purpose.

## Export behavior
- Markdown export now includes a `Browser / UI module contracts` section.
- Text export now includes a `BROWSER / UI MODULE CONTRACTS` section.
- Adds a development rule requiring UI modules to use the documented runtime contracts rather than Core UI internals or Tactical authentication storage.

## Documentation
- `docs/developer-contracts.md` now describes browser contracts as part of the canonical generated handoff.

## Regression coverage
- `tests/browser-contract-catalog-1.15.170.py`
- `tests/contracts-foundation.sh`
