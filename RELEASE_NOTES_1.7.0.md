# Tec-Tac Framework 1.7.0

## Module repositories and online catalog

- Adds configurable multiple module repositories with enable/disable, priority and trust metadata.
- Adds bounded repository index sync with persistent cache/health state.
- Adds an online module catalog that compares installed and available versions, runtime/dependency compatibility and source conflicts.
- Adds SHA-256 verified online package staging that feeds the existing Module Management v2 inspection/install pipeline.
- Records repository provenance for successfully installed online packages without changing local/offline package behavior.
- Installed modules remain pinned to their recorded repository source; another repository is reported as an alternate source rather than silently taking ownership.

Repository index schema remains intentionally small and metadata-only. Package archives remain authoritative and are re-inspected before installation.
