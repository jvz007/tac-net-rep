# FIXING.md — Core 1.15.145

## Scope

Review closure release for **M19 + L10 + L14 + L15 + L76** from the Core/UI tracker.

The production behavior for these findings was already present in the review-passed 1.15.144 baseline. This release deliberately avoids unrelated production changes and replaces structural/partial evidence with executable failure-injection and behavior tests.

## Validation intent

- native Tactical archive cleanup survives later failures;
- non-manager repository synchronization errors never expose raw details;
- destination archive publication cannot become visible before its sidecar;
- custom installer config pointers are honored and symlink pointers rejected;
- host rollback snapshot size is included in restore disk preflight;
- recovery-key trust/identity reads are isolated, config-derived and no-follow/root-owned.
