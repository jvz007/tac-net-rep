# Review scope: Core 1.15.96

This unsigned review build is intentionally narrow. Review the D3 recovery-trust items below only unless a regression is directly caused by these changes.

## Tracker items in scope

### M20 — Browser trust request can redirect stored backup credentials
- `POST /api/tfd/system/recovery/trust/` no longer accepts a destination object.
- Successful `validate_destination(...)` now registers the validated destination in a root-owned Core registry.
- Recovery trust submits only `destination_id`; the privileged helper resolves the registered destination server-side.
- An unregistered remote destination is refused before any backup download/credential use.

### M21 — Trust decision not bound to displayed signer fingerprint
- Trust approval now includes the exact confirmed installation ID, server name, key ID and SHA-256 fingerprint.
- The privileged helper re-downloads/verifies the bundle and compares all four values before writing trust.
- Any mismatch fails without creating a trust key.

### M22 — Recovery identity GET authorization
- Recovery identity and trust-job status now require an effective Tactical superuser in addition to `SessionAuthenticated`.
- Unauthorized callers are denied before a privileged recovery-identity job can be dispatched.

### M23 — Missing Core audit record for signer trust
- Core writes a strict Tactical audit record for the exact superuser approval before privileged dispatch.
- The existing root-owned `/var/log/tec-tac/recovery-audit.jsonl` success record remains the second audit layer.

### M24 — Synchronous recovery trust web request
- Trust POST now queues the privileged operation and returns HTTP 202 with a job ID.
- `GET /api/tfd/system/recovery/trust/?job_id=<uuid>` returns sanitized polling status.
- The web request no longer waits for the remote backup verification/download job to finish.

## Regression coverage
- `tests/recovery-trust-http-boundary.py`
  - non-superuser GET denied before root work;
  - raw destination payload rejected;
  - strict Core audit exercised;
  - valid POST returns 202 and passes only destination ID + confirmed identity;
  - trust-job polling exercised.
- `tests/recovery-trust-async-core.py`
  - proves Core queues without synchronous job polling.
- `tests/server-backup-d2-d3.py`
  - actual helper signer verification/trust;
  - confirmed fingerprint mismatch refused before trust write;
  - registered remote destination resolution exercised;
  - unregistered remote destination refused.
- Existing recovery/capability/foundation suites are also run for regression coverage.

## Explicitly not in this release
- The backup module/UI work to display installation ID, server name and fingerprint before confirmation is not part of the base Core/UI repositories in this package.
- D2 backup-UI downgrade notice is still owned by the consuming backup module/UI.
- M2–M19, M25–M31, U1–U4 and unrelated Low items are not being addressed here.
