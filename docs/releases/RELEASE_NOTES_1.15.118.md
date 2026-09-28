# Tec-Tac Core 1.15.118

## Scope

This release continues from the review-passed 1.15.117 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass. This pass closes **M2 + L06 + L07** from the supplied open-review list.

## Fixed

### M2 - Tec-Tac revoke-others could leave unobserved Tactical Knox tokens active

Tec-Tac session revocation already removed the Knox token linked to an individual observed Tec-Tac session. The remaining gap was the revoke-other-sessions workflow: it deleted only Knox digests already attached to Tec-Tac trust rows. A second valid Tactical Knox token for the same user that had never called a Tec-Tac endpoint could therefore remain usable on Tactical-native APIs.

`revoke_user_sessions()` now applies the operation at both layers:

- Tec-Tac trust rows other than the explicitly excluded session are revoked;
- the Knox credential linked to the excluded/current session is preserved;
- every other Knox token for that Tactical username is deleted, including tokens Tec-Tac has not previously observed.

This keeps "revoke other sessions" semantically consistent across Tec-Tac and Tactical itself.

### L06 - legacy no-parameter history row counts

Closure guards now protect the compatibility response shape for:

- `/api/tfd/modules/v2/jobs/`; and
- session audit history.

No-parameter callers continue to receive the historical bounded **up-to-200-row** result rather than silently falling onto the paginated 50-row default. Explicit pagination continues to default to 50 rows per page.

### L07 - privileged Bash path portability

Closure guards now require each privileged Core helper to resolve a trusted root-owned Bash executable from either `/bin/bash` or `/usr/bin/bash`. Direct command construction that assumes `/usr/bin/bash` is rejected by the regression guard.

## Regression coverage

- `tests/session-knox-revocation.py` now includes an unobserved Knox credential and proves revoke-others removes it while preserving the current credential.
- `tests/open-list-closure-1.15.118.py` protects L06 legacy row counts and L07 trusted Bash resolution.
