# Tec-Tac Framework 1.13.4

Architecture diagnostics and source/runtime finalization.

- Diagnostics now verify that Framework and UI source roots are clean Git checkouts.
- Diagnostics fail if the Tec-Tac runtime tree contains Git metadata.
- Diagnostics verify the configured split-layout paths for Framework source, UI source, Framework runtime, and deployed UI.
- Diagnostics verify that Framework source and runtime resolve to different paths.
- Diagnostics compare Framework source/runtime versions and UI source/deployed versions.
- Diagnostics verify the live Tactical process imports `tec_tac` from the runtime Framework path.
- JSON diagnostics now expose `architecture_ok`, source versions, the live framework import path, and detailed architecture checks.
- Architecture failures now contribute to the diagnostics command exit status.
