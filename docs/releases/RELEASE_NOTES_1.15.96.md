# Core 1.15.96

## D3 recovery-trust hardening — M20–M24

- Recovery trust no longer accepts browser-supplied destination definitions. Successful destination validation registers a root-owned Core destination record, and trust resolves only that server-side destination ID.
- Superuser confirmation is bound to the exact source installation ID, server name, signer key ID and SHA-256 fingerprint. The privileged helper re-verifies all four fields before writing trust.
- Recovery identity and trust-job polling require an effective Tactical superuser.
- Signer trust approval now writes a strict Core/Tactical audit record before privileged dispatch while retaining the root-owned recovery-success audit as the second record.
- Recovery trust is asynchronous: POST returns HTTP 202 with a job ID, and the same endpoint can be polled with `?job_id=<uuid>`.
- The recovery HTTP contract and server-backup documentation now describe the hardened request/response shape and destination-registration requirement.

## Verification

Behavioural regressions cover HTTP authorization/audit/202 semantics, asynchronous Core dispatch, registered destination resolution, confirmed signer identity mismatch rejection, and the existing D2/D3 recovery trust flow.
