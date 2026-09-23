# Tec-Tac Framework 1.15.36

## Trusted publisher verification

- adds `tec_tac.trusted_publishers` as the Core-owned Ed25519 package trust boundary;
- validates exact package SHA-256, release schema/algorithm/canonical filenames, local publisher identity, active key status, environment and publisher permissions before accepting a signed release;
- treats release metadata as untrusted selector/consistency data and resolves all trust decisions from the local root-managed publisher policy;
- supports key rotation/revocation records and raw/base64/`ed25519:`/PEM Ed25519 public-key encodings;
- adds optional detached signature + release metadata intake to Module Manager v1/v2 and signed online repository releases;
- preserves a transitional unsigned path for normal modules while requiring trusted signatures for extensions declaring privileged publisher permissions;
- adds `publisher_permissions` manifest metadata with `server_maintenance.register` as the first privileged permission gate;
- re-verifies publisher trust immediately before install dispatch and has root-owned lifecycle workers re-hash staged package bytes before executing module installation;
- records publisher/key/hash/trust decision in durable module lifecycle metadata and logs;
- installs `/etc/tec-tac/trusted-publishers` as a root-owned read-only trust root and adds `TEC_TAC_ENVIRONMENT` configuration;
- exposes trusted-publisher discovery through Public Contracts and the Core diagnostics report;
- documents offline/repository signing integration and security invariants;
- adds regression tests for valid signatures, tampering, wrong/unknown keys, revoked keys, environment mismatch, permission denial and unsigned privileged packages.
