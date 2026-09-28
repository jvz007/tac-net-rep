# Tec-Tac Core release-note archive

The canonical note for the package currently being built is the single
`RELEASE_NOTES_<VERSION>.md` file at repository root. When the next clean release
is created, that note is copied here under the **clean release identity**.

## Archive rules

- Internal rebuild suffixes (`-1`, `-2`, and so on) are never archive identities.
  A review-passed rebuild is archived as its clean release, for example
  `1.15.138-1` -> `RELEASE_NOTES_1.15.138.md`.
- The archive is continuous from **1.15.113** onward. `tests/release-integrity.sh`
  fails if a clean release in that range is missing, duplicated, or rebuild-named.
- The first heading in each enforced archive note must match its clean release
  identity.
- Earlier notes are retained exactly where authoritative source material exists.
  Historical gaps before 1.15.113 are legacy gaps and are **not reconstructed or
  invented** merely to make the numbering continuous.

This keeps rebuild numbers internal while preserving the actual reviewed release
notes available to the project.
