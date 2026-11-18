"""Public operation: the client address of a request, as Core itself resolves it (core.client_address 1.0.0, Core 1.18.6).

Read-only. It reports the address of the request the caller already holds. It adds no trust: it calls
session_security.effective_client_ip with no policy argument, so the stored trusted_proxies and the same header parsing apply.
A module cannot pass its own proxy list on purpose. An empty string means "unknown": the caller must refuse (fail closed).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

CAPABILITY_ID = "core.client_address"
CAPABILITY_VERSION = "1.0.0"
REQUIRES_FRAMEWORK = ">=1.18.6"


def client_address(request) -> str:
    """Return the person's address for this request, or '' when it cannot be told. Never raises."""
    try:
        if not hasattr(request, "META"):
            return ""
        # Imported here so this file loads without Django.
        from .session_security import effective_client_ip

        return str(effective_client_ip(request) or "")
    except Exception:
        logger.warning("core.client_address could not resolve the request address", exc_info=True)
        return ""


class ClientAddressProvider:
    """Capability provider object; the operation is the module-level function."""

    @staticmethod
    def client_address(request) -> str:
        return client_address(request)


def client_address_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.client_address",
        "operations": ["client_address"],
        "python": "client_address(request) -> str",
        "empty_means": "unknown: the caller must refuse (fail closed). The function never raises.",
        "trust_source": "core.session_security trusted_proxies",
        "requires_framework": REQUIRES_FRAMEWORK,
        "notes": "Behind Nginx the answer is the real address only when Nginx forwards X-Forwarded-For or X-Real-IP from the loopback peer. Otherwise it is the proxy address (127.0.0.1): refuse to treat a loopback or private-proxy answer as the person's address.",
    }


def register_core_client_address_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=ClientAddressProvider(),
        description="The address of a request as Core resolves it, using Core's own trusted proxy list.",
        operations=("client_address",),
        metadata=client_address_contract_metadata(),
    )
