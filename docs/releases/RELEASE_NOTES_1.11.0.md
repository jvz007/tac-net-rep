# Tec-Tac Framework 1.11.0

Scheduler hardening and configuration release.

- Adds configurable one-off schedule retention (default 48h, range 1-720h).
- Preserves scheduler run history after one-off schedule definitions are cleaned or manually deleted.
- Adds scheduler runtime health/config/self-test APIs.
- Adds dispatch-failure recording and tick diagnostics.
- Adds deliberate failure and retry self-test actions.
- Adds permanent/transient retry classification.
- Adds attempt number to scheduled-action handler context.
- Extends Public Contracts and scheduler developer guidance.
