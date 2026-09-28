# Tec-Tac Core 1.15.144

## Scheduler hardening and closure

- **M13:** Dynamic Scheduler filter values now reject explicit Tactical scope selectors that use Django lookup suffixes or primary-key spellings, including forms such as `site_id__in`, `payload__clientIds__exact`, `site.pk`, and `endpoint__pk__isnull`, while preserving ordinary module-owned values such as `ticket.client`.
- **L18:** Scheduler managers can delete an orphaned user schedule after its registered action disappears. Non-managers still fail closed because no action permission remains to authorize against.
- **L19:** Occurrences that predate the current schedule revision are consumed before due/missed evaluation. A newly created or materially edited schedule therefore cannot execute or emit a synthetic missed row for an occurrence from the previous revision.
- **L20:** Force-delete remains protected by a strict Core audit write inside the delete transaction. New executable coverage proves an audit failure prevents the schedule deletion.
- **L21:** Added executable ORM-boundary coverage proving stale queued-run recovery applies the stale cutoff filter before row-lock results are materialized.
- **L22:** Scheduler recovery and the Celery execution worker now share `effective_retry_delay_seconds()` as the single fallback path; zero, missing, or invalid retry-delay values resolve to 60 seconds.

## Regression coverage

- Added `tests/scheduler-closure-1.15.144.py` and wired it into `tests/scheduler-foundation.sh`.
- Updated the older Scheduler hardening and resource/audit tests to assert the current manager-safe delete and shared retry-helper contracts.
- Preserved the existing dynamic-filter compatibility, Scheduler scope, durability, interval, and history/health tests.

No unrelated subsystem behavior is changed in this release.
