# Tec-Tac Framework 1.15.18

## Module identity contract hardening

- Audits Core for the retired `security` WAF module identifier; no hard-coded legacy mapping or alias was present.
- Documents `securityWAF` as the canonical WAF module identifier example: capability `securityWAF.waf`, permissions `securityWAF.read` / `securityWAF.manage`, API root `/api/tfd/securityWAF/`, UI route `/extensions/securityWAF`, and matched `extensions/securityWAF/` + `reportsets/securityWAF/`.
- Makes the existing Core contract explicit: module identifiers are case-sensitive and case-preserving.
- Adds regression coverage proving mixed-case module IDs survive registry discovery, capability registration/status and module-state persistence unchanged.
- Adds static guard coverage for repository/licensing validators and prevents an accidental generic `security` -> `securityWAF` alias from entering Core.

No runtime alias or migration shim is added because Core contains no deployed hard-coded `security` contract requiring one.
