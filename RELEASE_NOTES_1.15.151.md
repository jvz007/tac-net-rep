# Tec-Tac Core 1.15.151

## Remaining tracker closure

- D2/D3: promoted the existing restore downgrade, recovery identity, trust merge and service-state checks into one release-gating behavioral closure suite.
- M18/L04/L07/L10/L15/L24/L25/L61/L76: added release-gating execution of the existing behavioral regressions so these boundaries are proven by runnable tests rather than grep-only evidence.
- L26: added a real `SystemUpdateTrustPolicyView.get_throttles()` regression proving only PUT receives the dedicated authenticated Trust Policy throttles.
- L27: bounded the install-time immediate `check-revert` call with `timeout`; failures and hung checks are non-fatal because the persistent timer remains the recovery path.
- L63: archived 1.15.150 under its clean release identity and kept release-archive integrity in the release gate.

## Compatibility

No public capability version changes are required. The Trust Policy timeout changes installer resilience only; Trust Policy semantics are unchanged.
