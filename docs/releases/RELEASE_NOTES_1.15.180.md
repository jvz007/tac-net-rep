# Core 1.15.180

## F8 SSO ownership contract

Clarifies the public SSO contract: feature modules may register and initiate providers before authentication, but the browser callback, Tactical SSO token exchange and transition into the Tec-Tac session-security boundary are Core-owned. Public module runtime never receives Tactical credentials, Django session state, CSRF material or the issued Knox token.

Companion UI: 0.12.72.
