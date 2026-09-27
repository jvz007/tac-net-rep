#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import tempfile

from tec_tac import capabilities
from tec_tac.server_backup import (
    get_server_backup_provider,
    register_core_server_backup_capability,
)


def main() -> None:
    capabilities._clear_capabilities_for_tests()
    registration = register_core_server_backup_capability()
    assert "trust_recovery_signer" not in registration.operations
    assert "recovery_identity" not in registration.operations

    provider = get_server_backup_provider()
    assert not hasattr(provider, "trust_recovery_signer"), (
        "public capability provider must not expose recovery trust"
    )
    assert not hasattr(provider, "recovery_identity"), (
        "public capability provider must not expose recovery identity"
    )

    # get_capability() returns the provider object itself, so the security
    # boundary must hold even for a module that resolves core.server_backup.
    old_health = registration.health
    object.__setattr__(registration, "health", lambda: {"healthy": True})
    try:
        resolved = capabilities.get_capability("core.server_backup")
        assert resolved is provider
        with tempfile.TemporaryDirectory() as td:
            trust_root = pathlib.Path(td) / "recovery-trust"
            os.environ["TEC_TAC_RECOVERY_TRUST_ROOT"] = str(trust_root)
            try:
                try:
                    resolved.trust_recovery_signer(  # type: ignore[attr-defined]
                        backup_ref="crafted.tgz",
                        destination=None,
                        context={"source_module": "untrusted-module"},
                    )
                except AttributeError:
                    pass
                else:
                    raise AssertionError("provider unexpectedly exposed a recovery trust path")
                assert not trust_root.exists() or not any(trust_root.iterdir()), (
                    "provider trust attempt wrote into the recovery trust store"
                )
            finally:
                os.environ.pop("TEC_TAC_RECOVERY_TRUST_ROOT", None)
    finally:
        object.__setattr__(registration, "health", old_health)

    print("server backup recovery trust capability boundary: PASS")


if __name__ == "__main__":
    main()
