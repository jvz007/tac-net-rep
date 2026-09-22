# Tec-Tac Core 1.15.23

- Narrows GitHub release-integrity validation to release/package correctness only.
- Keeps the current and immediately previous `RELEASE_NOTES_*.md` files valid in the repository root.
- Requires `RELEASE_NOTES_${VERSION}.md` for the current release.
- Removes Unix executable-bit checks for recovery shell files from release publication validation; runtime/install permission repair remains separate from release metadata validation.
- Carries forward the public durable `core.server_maintenance` capability introduced in 1.15.22.
