# Tec-Tac Framework 1.15.50

## Trust-policy lowering redesign

- Removed the Tactical Knox/TOTP database lookup from root trust decisions.
- Removed the `--set-trust-policy-auth` NOPASSWD sudo path.
- `tec-tac-system-update --set-trust-policy` remains raise-only.
- Added root-console `tec-tac-trust-policy set <level> --reason <text> [--hours N]`.
- Console lowering uses normal sudo authentication, explicit confirmation, a root-owned JSONL audit log, and a persistent systemd timer that restores the previous floor after 8 hours by default.
- Web/API lowering returns `status=console_required` guidance instead of an error.
- `TEC_TAC_HELP_TRUST_POLICY_URL` controls the help link without a new release.
- UI-originated console requests are recorded in the Core audit log as `console_change_requested`.

## Scheduler

- Retains the 1.15.49 `last_queued_at` stale-run recovery fix unchanged.
