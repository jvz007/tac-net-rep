# Client address (`core.client_address` 1.0.0)

**Framework baseline:** 1.18.6

A module that needs the person's address for a request calls one operation:

```python
from tec_tac.capabilities import has_capability
from tec_tac.client_address import client_address

if has_capability("core.client_address"):
    address = client_address(request)   # '' means unknown: refuse
```

List `core.client_address` under `dependencies` and require framework `>=1.18.6`.

## What it returns

The address Core itself uses for sessions. It calls `tec_tac.session_security.effective_client_ip(request)` with no policy argument. The stored `trusted_proxies` (default: loopback only) and the same parsing apply: `X-Forwarded-For`, then `Forwarded`, then `X-Real-IP`. Core walks every hop from right to left and trusts the address to its left only when the hop that gave it is trusted. A peer that is not a trusted proxy always gives its own address, whatever the headers say.

## Rules for the caller

* `''` means unknown. It comes back for a request without `META`, a non-request object, no peer address, or any internal error. The function never raises. Treat `''` as unknown and refuse (fail closed).
* There is no `policy` argument on purpose. A module that passed its own proxy list would widen trust.
* Nothing is changed or audited. One read of the session policy per call, the same read every signed-in request already does.
* Behind Nginx the answer is the real address only when Nginx forwards `X-Forwarded-For` or `X-Real-IP` from the loopback peer. If it does not, the answer is `127.0.0.1`. Refuse to treat a loopback or private-proxy answer as the person's address.

The operation is in the public contract export as `tec_tac.client_address client_address`. Test: `tests/client-address-1.18.6.py`.
