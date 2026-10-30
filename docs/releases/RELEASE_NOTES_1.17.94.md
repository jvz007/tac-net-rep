# Tec-Tac Framework 1.17.94

Date: 29 October 2026. Endpoint transport owner. Core now accepts the module `endpoint-comms` as the owner of the endpoint transport, and keeps accepting `nats-comms` until the dev server has moved. The capability `core.endpoint_transport` stays at 1.0.0.

Closes the request "accept endpoint-comms as the transport owner" in `reviews/requests/core.md` (AD-54, third amendment).

## What changed and why

1. **Two owner ids, one owner at runtime.** `endpoint_transport.py` has `OWNER_MODULES = ("endpoint-comms", "nats-comms")`. `OWNER_MODULE` stays and is now `endpoint-comms`, the preferred id.
2. **Registration is first come, and endpoint-comms wins a tie.** Once a process holds an owner, `register_owner` from the other id gets `denied` ("another module already owns the transport"), even with the same task path. The same id and path is idempotent `ok`. The same id and a different path is `invalid`. When both extensions are installed and enabled, `nats-comms` is refused at `register_owner` and the reason names `endpoint-comms`. Every process reads the same installed state, so the choice is the same in each.
3. **The hot path costs nothing extra.** `request`, `send_many` and `presence` read the verified caller and the in-memory owner. They do no plugin scan. After an owner is registered only that module id passes. Before registration either id may call, as `nats-comms` could before.
4. **Same checks as before.** Every operation still needs `module_id` to equal the verified id. Another module, Core itself and an unverifiable caller get `denied`. The task must still lie in the owner's own folder.
5. **Text.** The contract metadata (owner and the four operation purposes), `docs/endpoint-transport.md` and `docs/capabilities.md` name `endpoint-comms` and say `nats-comms` is accepted until the dev server has moved.

Not changed: the category or the AD-34 deny allowance, the consumer, the limits, the close codes and the audit rows (they carry the owner's id from `get_owner()`).

## Module-facing change

* `endpoint-comms` can call `register_owner`, `request`, `send_many` and `presence` of `core.endpoint_transport` 1.0.0.
* `nats-comms` keeps working unchanged. Alone on a server it behaves exactly as in 1.17.93.
* If both are installed and enabled, `nats-comms` cannot register. Uninstall `nats-comms` on dev02 before you install `endpoint-comms`.
* The contract version stays 1.0.0. The owner is prose in the metadata. No operation, signature or return shape changed, so version ranges in modules keep working.

Decisions taken (information, no answer needed): see `reviews/questions/core.md`, "Endpoint transport owner, Core 1.17.94".

## Tests

* New: `tests/endpoint-transport-owner-1.17.94.py` and `tests/endpoint-transport-docs-1.17.94.py`.
* Two tidy changes to older tests: `endpoint-transport-contract-1.17.90.py` stubs `_owner_folder` with an optional id argument (the function now takes one). `endpoint-transport-docs-1.17.93.py` no longer demands that VERSION starts with 1.17.93 and reads the 1.17.93 notes by name from docs/releases.

## Not done here

* The `audit.record` deny rows for a core module (AD-34, `audit.py`) are a separate patch.
* `nats-comms` is not removed from the owner list. A later release does that once the dev server has moved.
* The public contract needs exporting again into `docs/contracts` after install on dev02.
