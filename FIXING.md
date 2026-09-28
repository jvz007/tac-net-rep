# FIXING.md — Core 1.15.146

## Scope

Review closure release for **D2 + D3 + M18 + L61 + L62** from the Core/UI tracker.

Production restore behavior was already present in the review-passed 1.15.145 baseline. This release deliberately avoids unrelated production changes and strengthens runner/test/document closure:

- D2/D3 behavioral restore suites are wired into the normal server-backup foundation;
- the two intentionally root-required security tests are removed from normal foundations and centralized in a dedicated root-required runner;
- portable L61 tests stay in review hygiene and execute with only narrow ownership fixtures;
- the corrected 1.15.83 release-note wording is regression-guarded so structural assertions are not overclaimed as full behavioral coverage.

## Validation intent

- restore downgrade/version-transition behavior remains executable in the normal backup suite;
- recovery identity/trust and service-state continuity remain executable in the normal backup suite;
- ordinary runners no longer accidentally require root for the two M18 security tests;
- the dedicated root runner clearly skips when non-root and runs both privileged tests when root;
- 1.15.83 documentation continues to distinguish structural assertions from behavioral regression coverage.
