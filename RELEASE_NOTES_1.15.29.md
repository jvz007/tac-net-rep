# Tec-Tac Framework 1.15.29

## Bundle-aware module update intake

- Module Management v2 now classifies ZIP artifacts for `tec_tac_bundle.json` before invoking the legacy single-package parser. Valid bundles no longer fail with the misleading `Package must contain exactly one extension manifest; found 0` error caused by inspecting the outer bundle ZIP as though it were one module package.
- ZIP uploads are staged once and replayed from a path-backed upload facade, avoiding dependence on whether an uploaded file object can be read twice.
- Malformed bundle archives remain bundle errors: if a bundle manifest is present, Core validates the bundle contract instead of falling back to single-package interpretation.
- Repository-backed staging may now accept a bundle when the requested repository module and version are one of the bundle's child packages. The complete bundle dependency plan is retained for inspection and install.
- Repository provenance is attached to bundle installs and propagated to each module installed from that bundle.

## Validation

- Added a bundle-first classifier regression test that proves a valid bundle never reaches the legacy exactly-one-extension parser.
- Added a repository staging regression test that proves an online repository artifact may be a bundle containing the requested module/version.
