"""Tec-Tac installation-layout configuration."""
from __future__ import annotations
import os
from pathlib import Path

DEFAULT_CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")

def load_layout(path: str | os.PathLike | None = None) -> dict[str, str]:
    cfg_path = Path(path or os.environ.get("TEC_TAC_CONFIG_FILE") or DEFAULT_CONFIG)
    values: dict[str, str] = {}
    if cfg_path.is_file():
        for raw in cfg_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    defaults = {
        "TEC_TAC_ROOT": "/opt/tec-tac",
        "TEC_TAC_SOURCE_ROOT": "/opt/tec-tac-src",
        "TEC_TAC_FRAMEWORK_SOURCE": "/opt/tec-tac-src/framework",
        "TEC_TAC_UI_SOURCE": "/opt/tec-tac-src/ui",
        "TEC_TAC_FRAMEWORK_ROOT": "/opt/tec-tac/framework",
        "TEC_TAC_EXTENSIONS_ROOT": "/opt/tec-tac/extensions",
        "TEC_TAC_REPORTSETS_ROOT": "/opt/tec-tac/reportsets",
        "TEC_TAC_SCRIPTS_ROOT": "/opt/tec-tac/scripts",
        "TEC_TAC_STATE_ROOT": "/var/lib/tec-tac",
        "TEC_TAC_MODULE_STATE_ROOT": "/var/lib/tec-tac/module-manager",
        "TEC_TAC_SYSTEM_UPDATE_ROOT": "/var/lib/tec-tac/system-updates",
        "TEC_TAC_SERVER_BACKUP_ROOT": "/var/lib/tec-tac/server-backup",
        "TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS": "/rmmbackups,/mnt,/media,/srv,/backup,/backups",
        "TEC_TAC_UI_DEPLOY_ROOT": "/var/lib/tec-tac/ui/tec-tac",
        "TACTICAL_ROOT": "/rmm",
        "TACTICAL_BACKEND_ROOT": "/rmm/api/tacticalrmm",
        "TACTICAL_PYTHON": "/rmm/api/env/bin/python",
        "TACTICAL_USER": "tactical",
    }
    for key, value in defaults.items():
        values.setdefault(key, os.environ.get(key, value))
    values["TEC_TAC_CONFIG_FILE"] = str(cfg_path)
    return values
