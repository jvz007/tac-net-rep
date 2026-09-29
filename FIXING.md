# Fixing / review notes — Core 1.15.169


Tracker closure focus: D2, D3, L10, F4 and F11. Adds Tactical UI values to authenticated module context, automatic Swagger grouping for every /api/tfd endpoint, and one explicit runner for the existing D2/D3/L10 behavioral closure tests.
Tracker closure focus: D2, D3, L10, L15, L24 and L25. Final restore, backup-publication and Scheduler target-parity cleanup with behavioral regressions.
Recovery-key import no longer follows the final import path or reads an unbounded source as root. Imported trust-key publication also fsyncs the trust directory.

Regression: `tests/recovery-key-import-1.15.158.py`.


## 1.15.162-1

Tracker closure focus: D2 and D3. Added the missing native Backup & Restore HTTP surface over registered destinations, non-destructive validation, exact recovery identity/version transition display data, and explicit destructive restore confirmation.

## 1.15.164-1

Blocking Scheduler compatibility rebuild: preserve module-declared native target types (`endpoints`, `agents`, `clients`, `sites`) through normalization, persistence, migration repair and handler dispatch. Singular Tactical kinds remain internal to Core scope/authorization. Regression: `tests/scheduler-native-type-compat-1.15.164-1.py`.
## 1.15.165-1

Tracker closure focus: L10, L24 and L25. Remote recovery publication now treats final archive/sidecar names as immutable; migration target repair fails closed on unsupported keys; and endpoint PK aliases are canonicalized to agent_id again immediately before handler execution. Regression: `tests/tracker-closure-1.15.165.py`.


## 1.15.167

Feature release F1-F4: My Account self-service for password change, TOTP reset/re-enrollment, revoke-other-sessions and Tactical agent action preferences.

## 1.15.166

Tracker decision closure focus: D2 and D3. Adds an ordinary-CI behavioral regression over the real restore-validation result and exact restored-Core verifier. The accepted UI 0.12.59 remains the matching restore UI and consumes the same source identity, signer fingerprint and downgrade transition fields. No restore mechanism or public contract change.
