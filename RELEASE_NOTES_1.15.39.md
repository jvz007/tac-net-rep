# Tec-Tac Framework 1.15.39

## Shared update and module trust acceptance policy

- Added one Core-enforced minimum trust policy shared by System Updates and Module Management.
- Supported levels are `unsigned`, `signed_development`, `signed_production`, and `secure_signed`, ordered from least to most restrictive.
- Module package intake now applies the global trust floor in addition to existing publisher-permission signing requirements; stricter module rules continue to win.
- System Update inspection and install queueing apply the same trust floor, while existing component-specific signing rules remain able to impose stricter requirements.
- Trusted publisher/key policy may mark an Ed25519 signing identity with `assurance: secure`; `secure_signed` additionally requires a production publisher environment.
- Publisher environment isolation remains enforced and is not bypassed by lowering the global acceptance setting.
- Added `/api/tfd/system/updates/trust-policy/` GET/PUT endpoints and exposed the effective policy in System Update status.
- Stable-release discovery now reports whether the discovered release meets the current global acceptance floor.
- Added regression coverage proving an unsigned normal module and unsigned Framework package are blocked when `signed_development` is selected.
