# Tec-Tac Framework 1.12.2

Framework release-integrity cleanup.

## Completed outstanding maintenance

- Preserves the 1.12.1 Recovery Toolkit executable-permission repair and installer verification.
- Replaces stale hardcoded framework-version assertions in foundation tests with VERSION/package-manifest consistency checks.
- Fixes the long-standing Access API foundation test that still expected Framework 1.2.0.
- Adds release-integrity regression coverage for VERSION/manifest agreement, current release-note placement, and Recovery Toolkit executable bits.
- Restores the documentation convention that historical release notes live under `docs/releases/` and only the current release note remains at repository root.

No Scheduler data model, Module Manager lifecycle, capability contract, or module runtime behavior changes are included.
