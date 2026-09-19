# Tec-Tac Framework 1.10.3

## Module execution-result contract hardening

This documentation-focused framework release captures a production integration lesson as a reusable public contract rule.

### Changed

- Public Contracts Markdown/Text exports now explicitly state that transport acknowledgement is not operation success.
- Scheduled handlers must propagate downstream command/application failures so Scheduler history and retry semantics reflect the real result.
- Provider contracts should distinguish requested/dispatched from verified executed/delivered states.
- Raw OS commands must be built and tested for the exact shell selected by the agent transport.
- Windows `cmd.exe` quoting and executable paths containing spaces are called out explicitly.
- `docs/module-scheduling.md`, `docs/module-interoperability.md`, `docs/developer-contracts.md`, and the extension/reportset tutorial were updated.
- The HTML tutorial was regenerated from the updated Markdown tutorial.

### Why

A Tactical/NATS raw-command transport can return a response even when the endpoint shell/application itself failed. Modules must not convert transport response into successful delivery without verifying the actual execution result.

No scheduler timing, capability-registry, module-manager, or API behaviour changed in this release.
