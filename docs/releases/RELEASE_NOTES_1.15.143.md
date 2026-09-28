# Tec-Tac Core 1.15.143

## Release archive integrity

- **L63:** Canonicalized archived release-note filenames so internal rebuild suffixes are no longer archive identities.
- Recovered the authoritative release notes available to this project for clean releases `1.15.113` through `1.15.142`, using the final retained source artifact for releases that had internal rebuilds.
- Normalized the legacy `docs/releases/1.15.96.md` filename to `RELEASE_NOTES_1.15.96.md`.
- Removed the stale historical root note now that `1.15.113` is archived; a release tree now contains exactly one root release note: the current package note.
- Documented that pre-`1.15.113` gaps are legacy-unavailable history and are not reconstructed without authoritative source material.

## Regression coverage

- Added `tests/release-archive-integrity.py`.
- `tests/release-integrity.sh` now rejects rebuild-suffixed archive filenames, missing clean archive releases from `1.15.113` onward, mismatched archive headings, noncanonical legacy filenames, and multiple root release notes.
- The release build-junk check now also rejects `.pytest_cache`, `.mypy_cache`, and `.ruff_cache` directories.

No unrelated runtime behavior is changed in this release.
