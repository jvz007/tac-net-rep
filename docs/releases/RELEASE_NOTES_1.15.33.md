# Tec-Tac Framework 1.15.33

## Migration hygiene

- adds the committed Core migration for `TecTacSessionSecurityConfig.trusted_proxies`, removing the `tec_tac` model/migration drift reported by Django;
- makes Core migration drift a framework install failure so Core releases cannot silently ship model changes without migrations;
- adds a non-writing installed-module migration drift report during framework installation;
- module-owned drift is reported by Django app name but does not block a Core framework upgrade, preserving module ownership of schema changes;
- adds regression coverage for the Core migration and installer migration-state checks.
