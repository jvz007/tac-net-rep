# Tec-Tac Framework 1.6.1

Module visibility precedence hotfix.

- Package UI metadata may declare a default visible/hidden navigation state.
- Persisted Module Manager visibility is now an explicit operator override and takes precedence over the package default.
- Package upgrades no longer create/reset a visibility override while recording module versions.
- Catalog reporting exposes the effective visibility while retaining the package default for diagnostics.
- Modules without a package visibility default remain visible by default.
