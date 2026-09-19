# Tec-Tac Framework 1.13.7

System Update dynamic-module preservation hardening.

- Dynamic module preservation checks now ignore runtime-generated Python bytecode/cache artifacts (`__pycache__`, `.pyc`, `.pyo`).
- Persistent module content remains protected byte-for-byte, including source, manifests, migrations, UI assets, and other package files.
- Prevents Tactical service restarts from creating false module-change failures during Framework updates and rollback verification.
- Adds regression coverage proving cache churn is ignored while real module source changes are still detected.
- Retains the 1.13.6 structural package classification fix for multi-file module uploads.
