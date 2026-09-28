# Tec-Tac Core 1.15.150

## Trust Policy closure

- Added executable coverage for authenticated Trust Policy throttling. The real TrustPolicyMinThrottle and TrustPolicyDayThrottle classes now have behavioral regression coverage proving signed-in users receive distinct, non-empty cache keys.
- Added executable install-block coverage proving an immediate `check-revert` failure cannot abort installation after the persistent revert timer is enabled.
- Added a cross-process locking regression proving `set_level()` and `check_revert_due()` cannot enter their mutation bodies concurrently.
- Repaired the historical 1.15.51 regression to assert the current non-fatal immediate check and shared Scheduler retry-delay helper rather than obsolete implementation strings.

No production Trust Policy logic changed in this release; the existing implementation satisfied the intended behavior and this release closes the remaining evidence gaps.
