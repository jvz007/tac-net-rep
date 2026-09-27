# Review brief — Core 1.15.95

This is a narrow D2 restore-safety release. Review only the tracker items below plus regressions caused by these changes.

## In scope

### M25 — restore must not turn D1 protection off
- Capture the target `account-security-policy.json` before restore.
- Merge current/restored D1 policy with stricter-wins semantics: protection `on` wins.
- Treat malformed present policy data fail-closed as protection `on`.
- Audit an effective merge through the root-owned account-security-policy audit and recovery audit.

### L75 — deleted publishers must not come back
- Treat the current target `/etc/tec-tac/trusted-publishers` set as authoritative.
- Current publisher/key contents overwrite restored copies.
- Restored-only publishers are removed when absent from the current target set.
- Recovery signer trust remains a separate D3 mechanism and is not sourced from publisher trust restoration.

## Behavioural regression

`tests/server-backup-d2-d3.py` now restores a deliberately older/weaker security state and proves that:
- a target-revoked key stays revoked;
- a publisher deleted after backup stays deleted;
- the stricter target trust floor survives;
- target D1 protection `on` survives restored `off`;
- the D1 merge writes both required audit records.

## Explicitly not in scope

- D2 backup-module/UI downgrade confirmation notice. Core already exposes `version_transition.notice`; the consuming backup UI still needs to display it before restore.
- D3 / M20–M24.
- D4, D5, D6a.
- M2 onward outside the D2 decision work.
