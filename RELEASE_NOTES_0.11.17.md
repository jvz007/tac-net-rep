# Tec-Tac UI 0.11.17

## Core module notification service

- Adds the shared module-scoped `notifications` runtime contract.
- Supports info, success, warning and error toasts.
- Supports optional title, bounded timeout/sticky notices, stable dedupe keys, dismissal and one module-owned action.
- Limits the global surface to five visible notifications and renders notification content as plain text.
- Failed notification actions surface a Core-owned error toast instead of silently failing.
- Adds the notification contract to Public Contracts and `docs/module-notifications.md`.
- Modules should use this service instead of bundling independent toast/popup frameworks.
