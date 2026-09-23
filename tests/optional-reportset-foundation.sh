#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT}/framwork"
python - <<'PY'
import json
import tempfile
import zipfile
from pathlib import Path
from tec_tac.registry import RegistryError, discover_plugins
from tec_tac.module_manager import _extract_archive, _find_pair

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    ext = root / "extensions" / "notifications"
    ext.mkdir(parents=True)
    (root / "reportsets").mkdir()
    manifest = {"id":"notifications","type":"extension","version":"0.1.0","python_paths":["."],"django_apps":[]}
    (ext / "tec_tac.json").write_text(json.dumps(manifest), encoding="utf-8")
    plugins = discover_plugins(root / "extensions", root / "reportsets")
    assert [(p.plugin_type,p.plugin_id) for p in plugins] == [("extension","notifications")]

    package = root / "notifications-0.1.0.zip"
    with zipfile.ZipFile(package, "w") as zf:
        zf.writestr("notifications-0.1.0/extensions/notifications/tec_tac.json", json.dumps(manifest))
    unpacked = root / "unpacked"
    unpacked.mkdir()
    _extract_archive(package, unpacked)
    ext_root, rep_root = _find_pair(unpacked)
    assert ext_root.name == "notifications"
    assert rep_root is None

    orphan = root / "orphan"
    (orphan / "extensions").mkdir(parents=True)
    rep = orphan / "reportsets" / "notifications"
    rep.mkdir(parents=True)
    (rep / "tec_tac.json").write_text(json.dumps({"id":"notifications","type":"reportset","version":"0.1.0","python_paths":["."],"django_apps":[]}), encoding="utf-8")
    try:
        discover_plugins(orphan / "extensions", orphan / "reportsets")
    except RegistryError as exc:
        assert "without matching extension" in str(exc)
    else:
        raise AssertionError("orphan reportset accepted")
print("optional_reportset=OK")
PY

grep -q 'package may contain at most one reportset manifest' "${ROOT}/scripts/install-extension.sh"
! grep -q 'Matching reportset not found' "${ROOT}/scripts/remove-extension.sh"
echo '[TEST] PASS optional reportset module contract'
