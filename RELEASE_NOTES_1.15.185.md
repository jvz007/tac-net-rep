# Tec-Tac Core 1.15.185

## F8 SSO acceptance closure

No SSO production behavior changes in this release. This release adds portable behavioural acceptance for the final F8 done-when: an ordinary non-SSO Knox credential without local TOTP is stopped by the MFA-enrollment gate, while an SSO account follows Tactical's external-provider MFA model and still crosses the real Core `SessionAuthenticated` / `ensure_request_session` boundary. The test proves a new trusted SSO session persists its Knox binding and creates the standard `session_created` audit row.

The F8 acceptance test is wired into the normal review-hygiene runner so future regressions cannot silently drop the MFA/session/audit portion of the SSO completion contract.
The active review-hygiene runner also stops executing three superseded legacy tracker/F11 tests whose assertions describe the pre-F11 design; the files remain under `tests/legacy/` for historical reference.

This release is unsigned.
