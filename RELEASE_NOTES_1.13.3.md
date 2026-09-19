# Tec-Tac Framework 1.13.3

System Update offline reinstall hardening.

- Offline package updates now use an explicit empty audit commit when the staged tree is byte-for-byte identical to the current source checkout.
- Reinstalling the currently installed Framework or UI version therefore remains a valid System Update transaction instead of failing with `nothing to commit`.
- Rollback continues to restore the exact previous branch and HEAD and removes the temporary offline branch.
- Added regression coverage for identical offline reinstall transactions.
