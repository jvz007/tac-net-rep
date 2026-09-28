# FIXING.md — Core 1.15.143

Release-archive integrity release closing L63.

- Canonicalizes archived release notes to clean release identities rather than internal rebuild suffixes.
- Restores the authoritative clean-release archive continuously from 1.15.113 through 1.15.142 using retained project artifacts.
- Enforces archive continuity/heading rules and exactly one current root release note in release integrity.
- Extends build-junk rejection to pytest/mypy/ruff cache directories.
