# Tec-Tac 1.2.5

## Added

- `GET /api/tfd/auth/totp/qr/` for Tec-Tac-owned authenticator enrollment.
- QR generation is performed locally on the Tactical API server using Tactical's existing Python `qrcode` dependency.
- Reuses Tactical's own `TOTPSetupSerializer` provisioning URI so issuer/account formatting stays native to Tactical.
- SVG QR responses are marked `Cache-Control: no-store` and require Tactical authentication.

## Security

The QR payload is generated on the same Tactical server that owns the TOTP secret. Tec-Tac does not call an external QR-code service and does not persist the generated image.
