# Tec-Tac Framework 1.15.4

## Module Manager independent batch fix

- Multiple uploaded module packages no longer need to declare dependencies on one another to form a valid install batch.
- Dependency declarations are treated only as ordering/version constraints when they exist.
- Completely independent batches preserve the operator's upload order and install sequentially through the existing lifecycle worker.
- Mixed batches keep unrelated packages while still forcing declared dependencies ahead of their dependants.
- Added a focused regression test for independent and mixed multi-package install plans.

No UI update is required.
