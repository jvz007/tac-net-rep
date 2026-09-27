# FIXING.md — Core 1.15.118

This build continues from the review-passed 1.15.117 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass.

## M2 — revoke Tec-Tac sessions at the Tactical Knox credential layer

- `revoke_user_sessions()` now deletes all other Tactical Knox credentials belonging to the target username, not only credentials already observed by Tec-Tac.
- When `except_session_id` is supplied, only the Knox digest linked to that excluded/current session is preserved.
- Existing individual-session revocation continues to delete the directly linked Knox credential.

## L06 — preserve historical no-parameter history limits

- Added closure guards requiring Module Management v2 job history and session audit history to retain the legacy no-parameter 200-row bound.
- Explicit paginated requests retain the 50-row page default.

## L07 — trusted Bash path portability

- Added closure guards across all privileged Core helpers requiring `_trusted_bash()` resolution from `/bin/bash` or `/usr/bin/bash`.
- Guards reject direct subprocess command construction that pins only `/usr/bin/bash`.

## Regression coverage

- `tests/session-knox-revocation.py`
- `tests/open-list-closure-1.15.118.py`
