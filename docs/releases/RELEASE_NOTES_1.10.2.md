# Tec-Tac Framework 1.10.2

Corrective release for Public Contracts exports.

- Prevents DRF Accept-header content negotiation from rejecting Markdown/Text attachment requests before the export view runs.
- Keeps `export_format=md|txt` as the explicit export selector.
- Preserves authentication and server-maintenance authorization.
- No Scheduler, capability-registry, module lifecycle, or data-model changes.
