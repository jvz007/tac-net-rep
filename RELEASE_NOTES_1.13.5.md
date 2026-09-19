# Tec-Tac Framework 1.13.5

Lifecycle concurrency hardening and architecture diagnostics.

- Adds a shared exclusive lifecycle lock at `/var/lib/tec-tac/lifecycle.lock`.
- Framework/UI System Updates cannot overlap module install/remove jobs.
- Module Management v1 and v2/bundle jobs cannot mutate modules while a System Update is active.
- Prevents legitimate concurrent module upgrades from being misclassified as Framework module corruption.
- Retains strict byte-for-byte dynamic module preservation verification during Framework updates and rollback.
- Includes the 1.13.4 architecture diagnostics: clean source Git checkouts, Git-free runtime, source/runtime separation, source/runtime version alignment, deployed UI alignment, configured path assertions, and live Tec-Tac import-path verification.
- Architecture failures contribute to diagnostics exit status and are exposed in `--json` output.
