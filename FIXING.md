# Fixing — Core 1.15.156

This release hardens trust-policy state publication. The root trust-policy CLI and upgrade migration must use unique, same-directory temporary files for atomic replacement; predictable `.tmp` or PID-derived names are not permitted.

Regression: `tests/trust-policy-atomic-state-1.15.156.py`.
