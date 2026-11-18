#!/usr/bin/env python3
"""Regression: the UI sync script is published by a root path unit after a UI install (Core 1.18.2, lock and install log Core 1.18.3)."""
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
assert "a later UI install publishes it automatically" in install

# (2b) 1.18.3: install.sh keeps the helper's stdout (install log) and builds the warning from stderr only
call_at = install.index('UI_SYNC_ERR="$(mktemp)"')
call_end = install.index('rm -f "${UI_SYNC_ERR}"', call_at) + len('rm -f "${UI_SYNC_ERR}"')
snippet = install[call_at:call_end]
direct = [ln for ln in snippet.splitlines() if "--publish-ui-sync" in ln]
assert len(direct) == 1 and "/dev/null" not in direct[0] and "2>&1" not in direct[0], direct
assert '2>"${UI_SYNC_ERR}"' in direct[0] and direct[0].lstrip().startswith("if !")
assert "/dev/null" not in snippet
assert snippet.count("UI_SYNC_REASON=") == 2 and '< "${UI_SYNC_ERR}"' in snippet
assert "WARNING: ${UI_SYNC_REASON:-the UI module sync script was not published from a verified UI checkout}." in snippet
assert "Module UI sync stays off until a UI install or System Update publishes it" in snippet
assert "a later UI install publishes it automatically" in snippet

import shutil
import subprocess
import tempfile

if shutil.which("bash"):
    def run_snippet(stub_body):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            tmp = Path(tmp)
            stub = tmp / "stub.sh"
            stub.write_text(stub_body, encoding="utf-8", newline="\n")
            script = tmp / "run.sh"
            # the stub stands in for python3 + helper: the call line is rewritten to run the stub
            call = snippet.replace('/usr/bin/python3 -I "${SOURCE_ROOT}/scripts/system-update-helper.py" --publish-ui-sync', "bash stub.sh")
            script.write_text('set -euo pipefail\nlog() { echo "LOG: $*"; }\nUI_SYNC_SCRIPT_PATH=/x\n' + call + '\necho DONE\n', encoding="utf-8", newline="\n")
            res = subprocess.run(["bash", "run.sh"], capture_output=True, text=True, timeout=30, cwd=tmp, check=False)
            return res
    bad = run_snippet("echo STDOUT-LINE\necho 'stderr reason' >&2\nexit 1\n")
    assert bad.returncode == 0 and "DONE" in bad.stdout, bad
    assert "STDOUT-LINE" in bad.stdout
    assert "LOG: WARNING: stderr reason. Module UI sync" in bad.stdout and "STDOUT-LINE." not in bad.stdout, bad.stdout
    good = run_snippet("echo STDOUT-LINE\nexit 0\n")
    assert good.returncode == 0 and "STDOUT-LINE" in good.stdout and "WARNING" not in good.stdout, good
else:
    print("note: bash not found; install.sh snippet behaviour not run")

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
# 1.18.4: two lines, one per failure source (lock failure, publish failure); each is a single stderr line and exit 1
assert branch.count("sys.stderr.write") == 2

# (4b) 1.18.3: the lifecycle lock is taken before the publish; busy means a stdout skip line and exit 0
assert branch.index("acquire_lifecycle_lock()") < branch.index("publish_ui_sync_from_checkout()")
# 1.18.4 adds an "except OSError" clause (one stderr line, exit 1); the busy clause is what comes before it
lock_part = branch[: branch.index("except OSError as exc:")]
assert "except RuntimeError:" in lock_part
assert "sys.stdout.write(" in lock_part and "a System Update, restore or module job is running" in lock_part
assert "raise SystemExit(0)" in lock_part and "SystemExit(1)" not in lock_part
assert lock_part.count("sys.stdout.write(") == 1 and "sys.stderr" not in lock_part
assert "_LIFECYCLE_LOCK_HANDLE = handle" in helper_src  # the handle lives in a module global for the whole process
# the other publishers call publish_ui_sync_tools under their own lock, never the from_checkout entry (no deadlock)
assert helper_src.count("publish_ui_sync_from_checkout()") == 1

# Run the __main__ block of the helper with the publish function patched to fail (no root needed: geteuid is faked).
mod = None
spec = importlib.util.spec_from_file_location("sysupd_1183", helper_path)
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

# Linux part: a busy lock skips, a free lock publishes (needs fcntl; skipped on Windows)
if mod is not None and hasattr(mod, "fcntl") and hasattr(mod.fcntl, "flock"):
    import fcntl as _fcntl

    def run_entry():
        calls = []
        held = {}
        mod.publish_ui_sync_from_checkout = lambda out=None: (calls.append("publish"), held.update(h=mod._LIFECYCLE_LOCK_HANDLE))
        mod.stage_release_tree = lambda *a, **k: calls.append("stage")
        mod.publish_ui_sync_tools = lambda *a, **k: calls.append("tools")
        mod.os.rename = lambda *a, **k: calls.append("rename")
        mod.os.geteuid = lambda: 0
        main_src2 = helper_src[helper_src.index('if __name__ == "__main__":') :]
        old_argv, old_out, old_err = sys.argv, sys.stdout, sys.stderr
        sys.argv, sys.stdout, sys.stderr = ["helper", "--publish-ui-sync"], io.StringIO(), io.StringIO()
        code = 0
        try:
            try:
                exec(compile(main_src2.replace('if __name__ == "__main__":', "if True:", 1), "helper-main", "exec"), mod.__dict__)  # noqa: S102 - the helper's own main block
            except SystemExit as exc:
                code = exc.code or 0
            out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err
        return code, out, err, calls, held

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        mod.LIFECYCLE_LOCK_PATH = Path(tmp) / "lifecycle.lock"
        holder = mod.LIFECYCLE_LOCK_PATH.open("a+")
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_EX)
        code, out, err, calls, held = run_entry()
        assert code == 0 and err == "" and calls == [], (code, out, err, calls)
        assert len([x for x in out.splitlines() if x]) == 1 and "a System Update, restore or module job is running" in out
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_UN)
        holder.close()
        mod._LIFECYCLE_LOCK_HANDLE = None
        code, out, err, calls, held = run_entry()
        assert code in (0, None) and calls == ["publish"], (code, out, err, calls)
        assert held.get("h") is not None and not held["h"].closed  # lock held while the publish function runs
else:
    print("note: no fcntl here; the lock-busy run is checked statically only")

print("ui sync auto publish 1.18.3 regression: PASS")
