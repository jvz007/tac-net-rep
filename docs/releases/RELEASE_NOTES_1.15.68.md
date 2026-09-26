# Tec-Tac Framework 1.15.68

## R1 privileged Python boundary

- Root lifecycle helpers no longer execute Tactical's virtualenv Python for archive parsing, plugin registry validation, permission-manifest parsing, syntax compilation, or post-update Django verification.
- `install-extension.sh` and `remove-extension.sh` use fixed `/usr/bin/python3 -I` for root-side structural and registry checks. Registry imports explicitly add the root-owned Tec-Tac framework path instead of trusting `PYTHONPATH`.
- Django/manage.py operations continue to use Tactical's virtualenv, but only after demotion to the configured Tactical service account with `runuser`.
- `module-hotfix-job-helper.py` now uses `/usr/bin/python3 -I -m py_compile` for root-side syntax validation; its Django check remains Tactical-user execution.
- `system-update-helper.py` now demotes every Tactical manage.py verification command to the Tactical service account before execution, preventing Tactical-owned virtualenv `.pth` files or `local_settings.py` from executing as root.
- `migrate-layout.sh` now follows the same invariant for its final Django verification instead of running Tactical Python as root.
- Added `tests/root-python-boundary.sh`, including an isolated-mode regression proving hostile `PYTHONPATH`/`sitecustomize.py` content is ignored by the root structural-check interpreter.

No public capability or contract change is required.
