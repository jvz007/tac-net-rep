# Tec-Tac Framework 1.15.30

## Optional ReportSets

Tec-Tac modules may now ship as an extension-only package or as an extension plus a matching ReportSet. ReportSets remain optional reporting companions rather than a mandatory placeholder for every module.

- Package inspection requires exactly one extension and permits zero or one ReportSet.
- A present ReportSet must use the same module ID and version as its extension.
- The runtime registry accepts extension-only modules but still rejects orphan ReportSets.
- Install, replace, remove, migration, backup/rollback and hotfix paths handle modules without ReportSets.
- Bundle dependency planning therefore accepts suites that mix reporting modules and operational extension-only modules.

This specifically fixes bundles such as Alerts Suite where `notifications` and `advancedalerts` do not own reporting code.
