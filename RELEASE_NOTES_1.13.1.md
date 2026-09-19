# Tec-Tac Framework 1.13.1

## Layout migration preflight hardening

- Validates persistent Module Manager state against physical extension/reportset trees before layout migration.
- Aborts when `module-state.json` references a module whose extension or reportset files are absent.
- Invalid or unreadable module state fails preflight instead of being silently ignored.
- Directs the operator to recover missing module trees before retrying migration.

This prevents a superficially valid registry from allowing migration to continue when state-backed installed modules have disappeared from disk.
