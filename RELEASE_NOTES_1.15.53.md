# Tec-Tac Framework 1.15.53

## Trust-policy Help contract

- The trust-policy guidance response now identifies the built-in Knowledge Base article as `core.trust-policy` instead of returning a configurable external URL.
- Removed `TEC_TAC_HELP_TRUST_POLICY_URL` from the managed Core configuration and installer.
- Raising the trust level remains available from the UI; lowering remains console-controlled and audited.

## Compatibility

- No database migration is required.
- UI 0.12.24 consumes the new `help_article` response field.
