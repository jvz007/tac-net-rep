# Tec-Tac Framework 1.15.44

## Tec-Tac MFA issuer URL

- TOTP QR enrollment no longer inherits Tactical's first `CORS_ORIGIN_WHITELIST` entry as the authenticator issuer.
- Core now builds the TOTP provisioning URI with the actual Tec-Tac UI base URL supplied by the browser.
- The UI URL is normalized to HTTP/HTTPS, stripped of query/fragment/userinfo, and bounded before it is used as the issuer label.
- `Origin` and `Referer` are safe fallbacks; the API host is used only as a final fallback.
- Tactical remains the TOTP secret and verification authority; only the enrollment issuer/account URI is changed.
- QR responses remain `no-store` and continue to be generated locally on the Tec-Tac/Tactical server.
