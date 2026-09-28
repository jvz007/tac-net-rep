# Fixing / review notes — Core 1.15.163

Tracker closure focus: L07 and L76. Strengthened root Bash executable validation and recovery-key trust-root/config/isolation boundaries with direct behavioral tests.
Recovery-key import no longer follows the final import path or reads an unbounded source as root. Imported trust-key publication also fsyncs the trust directory.

Regression: `tests/recovery-key-import-1.15.158.py`.


## 1.15.162-1

Tracker closure focus: D2 and D3. Added the missing native Backup & Restore HTTP surface over registered destinations, non-destructive validation, exact recovery identity/version transition display data, and explicit destructive restore confirmation.
