# Tec-Tac Framework 1.15.21

## Release integrity rule correction

- Root release-note retention now allows the current release note plus the immediately previous release note.
- `tests/release-integrity.sh` requires `RELEASE_NOTES_${VERSION}.md` to exist.
- The integrity test fails when more than two root `RELEASE_NOTES_*.md` files are present.
- Older release notes remain archived under `docs/releases/`.
- No release workflow behaviour was changed.
