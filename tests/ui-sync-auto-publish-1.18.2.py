#!/usr/bin/env python3
"""Regression: the UI sync script is published by a root path unit after a UI install (Core 1.18.2)."""
import importlib.util
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
install = (ROOT / "install.sh").read_text(encoding="utf-8")
helper_path = ROOT / "scripts" / "system-update-helper.py"
helper_src = helper_path.read_text(encoding="utf-8")

for p in (ROOT / "install.sh", helper_path):
    assert b"\r" not in p.read_bytes(), f"{p.name} must stay LF"

# (1) install.sh: path unit + oneshot root service
assert 'UI_SYNC_PUBLISH_PATH="/etc/systemd/system/tec-tac-ui-sync-publish.path"' in install
assert 'UI_SYNC_PUBLISH_SERVICE="/etc/systemd/system/tec-tac-ui-sync-publish.service"' in install
assert "TEC_TAC_UI_DEPLOY_ROOT:-/var/lib/tec-tac/ui/tec-tac}/VERSION" in install
assert "PathChanged=${UI_DEPLOYED_VERSION_FILE}" in install
start = install.index("UI_SYNC_PUBLISH_SERVICE=")
end = install.index("systemctl enable --now tec-tac-ui-sync-publish.path") + 60
block = install[start:end]
assert "Type=oneshot" in block and "User=root" in block and "Group=root" in block
assert "ExecStartPre=/bin/sleep 5" in block
assert re.search(r"^ExecStart=/usr/bin/python3 -I \$\{SYSTEM_UPDATE_LIB\}/system-update-helper\.py --publish-ui-sync$", block, re.MULTILINE)
assert 'chown root:root "${UI_SYNC_PUBLISH_SERVICE}" "${UI_SYNC_PUBLISH_PATH}"' in block
assert 'chmod 0644 "${UI_SYNC_PUBLISH_SERVICE}" "${UI_SYNC_PUBLISH_PATH}"' in block
assert "systemctl daemon-reload" in block
assert "systemctl enable --now tec-tac-ui-sync-publish.path" in block

# (2) no sudoers line for it; the direct call stays and now carries the reason
assert not any("publish-ui-sync" in line for line in install.splitlines() if "NOPASSWD" in line)
assert '--publish-ui-sync 2>&1 >/dev/null)" || {' in install
assert "a later UI install publishes it automatically" in install

# (3) helper staging and verification unchanged
fn = helper_src[helper_src.index("def publish_ui_sync_from_checkout") : helper_src.index("def _read_provenance")]
assert 'stage_release_tree(target, stage_dir / "tree", "ui")' in fn
assert 'verify_rollback_tree(cfg, staged, "ui", version, purpose="UI module sync")' in fn
assert 'installed_version("ui", cfg)' in fn
stage_at = helper_src.index("def stage_release_tree")
assert "open_source_checkout" in helper_src[stage_at : stage_at + 4000]

# (4) the entry prints exactly one stderr line and exits non-zero
branch_at = helper_src.index('sys.argv[1] == "--publish-ui-sync"')
branch = helper_src[branch_at : helper_src.index('sys.argv[1] == "--install-restored"')]
assert "except (RuntimeError, OSError) as exc:" in branch
assert "[TEC-TAC] UI module sync script not published: {reason}" in branch
assert "raise SystemExit(1)" in branch

# Run the __main__ block of the helper with the publish function patched to fail (no root needed: geteuid is faked).
mod = None
spec = importlib.util.spec_from_file_location("sysupd_1182", helper_path)
try:
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
except ImportError as exc:  # no fcntl on Windows: the static check above stands
    mod = None
    print("note: helper not importable here (" + str(exc) + "); branch checked statically")

if mod is not None:
    def boom(out=None):
        raise RuntimeError("/opt/tec-tac-src is not root-owned or is group/world writable")

    mod.publish_ui_sync_from_checkout = boom
    mod.os.geteuid = lambda: 0
    main_src = helper_src[helper_src.index('if __name__ == "__main__":') :]
    old_argv, old_err = sys.argv, sys.stderr
    sys.argv, sys.stderr = ["helper", "--publish-ui-sync"], io.StringIO()
    code = None
    try:
        try:
            exec(compile(main_src.replace('if __name__ == "__main__":', "if True:", 1), "helper-main", "exec"), mod.__dict__)  # noqa: S102 - runs the helper's own main block, not user input
        except SystemExit as exc:
            code = exc.code
        text = sys.stderr.getvalue()
    finally:
        sys.argv, sys.stderr = old_argv, old_err
    assert code not in (None, 0), code
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1 and lines[0].startswith("[TEC-TAC] UI module sync script not published:"), text
    assert "not root-owned" in lines[0]

print("ui sync auto publish 1.18.2 regression: PASS")
