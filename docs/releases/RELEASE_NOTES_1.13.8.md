# Tec-Tac Framework 1.13.8

Installer permission prompt cleanup.

- Repeat installs no longer ask whether to change/add a reporting ingest permission assignment when one or more granted assignments already exist.
- Existing reporting permission assignments are listed and preserved automatically.
- `TEC_TAC_REPORTING_USERNAME` remains the explicit unattended override for granting the permission to another Tactical user role.
- First-time interactive installs may still offer the username prompt when no reporting ingest permission assignment exists.
