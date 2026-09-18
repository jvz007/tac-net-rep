# Tec-Tac Framework 1.7.1

Corrective release for Module Repository installation.

- Makes `dependencies`, `optional_dependencies`, and `requires` part of the canonical plugin registry schema so fresh installer processes accept Module Manager v2 manifests.
- Removes the Module Manager v2 import-time registry schema mutation.
- Adds a regression test that validates v2 metadata through a fresh direct registry import.
- Retains the 1.7.0 repository and installer hardening fixes.
