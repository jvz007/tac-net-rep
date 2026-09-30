#!/usr/bin/env python3
"""Regression: installed Backups module 1.x capability range must keep resolving."""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))

import tec_tac.capabilities as capabilities
import tec_tac.server_backup as server_backup

capabilities._clear_capabilities_for_tests()
old_health = server_backup._PROVIDER.health
server_backup._PROVIDER.health = lambda: {"healthy": True}
try:
    registration = server_backup.register_core_server_backup_capability()
    assert registration.version == "1.9.0", registration.version
    provider = capabilities.get_capability(
        "core.server_backup",
        version=">=1.6.0,<2.0.0",
    )
    assert provider is server_backup.get_server_backup_provider()
finally:
    server_backup._PROVIDER.health = old_health
    capabilities._clear_capabilities_for_tests()

print("[TEST] PASS core.server_backup remains compatible with Backups module 1.x range")
