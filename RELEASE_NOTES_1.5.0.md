# Tec-Tac Framework 1.5.0

Module installation queue and ordered batch-install release.

## Added

- Accepts an explicit requested install order for staged batches and bundles.
- The framework enforces hard dependency precedence server-side; a requested order that places a dependant before its staged dependency is rejected.
- Independent packages may be installed in an operator-selected sequence.
- Adds a v2 staged-artifact discard endpoint so cancelled package queues can be cleaned up safely.

## Compatibility

- Existing Module Management v2 package and bundle formats remain supported.
- Omitting an explicit order keeps the framework-resolved dependency order.
- Matching UI: Tec-Tac UI 0.5.0.
