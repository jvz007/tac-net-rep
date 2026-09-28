#!/usr/bin/env python3
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def run(*argv: str, as_nobody: bool = False, timeout: int = 90) -> None:
    cmd = list(argv)
    if as_nobody and os.geteuid() == 0 and subprocess.run(["id", "nobody"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        cmd = ["runuser", "-u", "nobody", "--", *cmd]
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise AssertionError(f"command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


# D2/D3: execute the restore downgrade, signer/trust continuity, and service-state regressions.
run(sys.executable, "tests/server-backup-d2-d3.py")
run(sys.executable, "tests/server-backup-d2-version-transition.py")
run(sys.executable, "tests/server-backup-d3-service-state.py")

# M18: both historically broken 1.15.52 regressions must execute successfully.
run(sys.executable, "tests/review-regressions-1.15.52.py")
run("bash", "tests/review-1.15.52-rebuild.sh")

# L04/L07: behaviorally exercise no-follow staged metadata and trusted Bash selection.
run(sys.executable, "tests/test_core_leftovers_1_15_139.py")
run(sys.executable, "tests/root-bash-boundary.py")

# L10/L15/L76: publication rollback, real disk-preflight accounting, and recovery-key trust boundaries.
run(sys.executable, "tests/backup-closure-1.15.145.py")
run(sys.executable, "tests/backup-recovery-system-update-1.15.140.py")

# L24/L25: migration/runtime endpoint identity compatibility and immutable run history.
run(sys.executable, "tests/scheduler-closure-1.15.149.py")
run(sys.executable, "tests/scheduler-legacy-target-regression.py")
run(sys.executable, "tests/scheduler-legacy-endpoint-pk-compat.py")

# L61: these regressions are part of ordinary portable CI and must pass without root.
for test in (
    "tests/privileged-helper-environment.py",
    "tests/module-artifact-immutable-claim.py",
    "tests/server-backup-recovery-trust.py",
):
    run(sys.executable, test, as_nobody=True)

# L63: clean release archive identities and continuity are release-gated.
run(sys.executable, "tests/release-archive-integrity.py")

# L26: execute the actual view method body with a minimal APIView stub. GET must have
# no throttles; PUT must instantiate exactly the dedicated authenticated policy throttles.
views_path = ROOT / "framwork/tec_tac/views.py"
tree = ast.parse(views_path.read_text(encoding="utf-8"))
view = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SystemUpdateTrustPolicyView")
get_throttles = next(n for n in view.body if isinstance(n, ast.FunctionDef) and n.name == "get_throttles")

class APIView:
    throttle_classes = []
    def get_throttles(self):
        return [cls() for cls in self.throttle_classes]

class TrustPolicyMinThrottle: pass
class TrustPolicyDayThrottle: pass
ns = {"APIView": APIView, "TrustPolicyMinThrottle": TrustPolicyMinThrottle, "TrustPolicyDayThrottle": TrustPolicyDayThrottle}
module = ast.Module(body=[ast.ClassDef(name="SystemUpdateTrustPolicyView", bases=[ast.Name(id="APIView", ctx=ast.Load())], keywords=[], body=[
    ast.Assign(targets=[ast.Name(id="throttle_classes", ctx=ast.Store())], value=ast.List(elts=[ast.Name(id="TrustPolicyMinThrottle", ctx=ast.Load()), ast.Name(id="TrustPolicyDayThrottle", ctx=ast.Load())], ctx=ast.Load())),
    get_throttles,
], decorator_list=[])], type_ignores=[])
ast.fix_missing_locations(module)
exec(compile(module, str(views_path), "exec"), ns)
cls = ns["SystemUpdateTrustPolicyView"]
obj = cls(); obj.request = SimpleNamespace(method="GET")
assert obj.get_throttles() == []
obj.request = SimpleNamespace(method="PUT")
throttles = obj.get_throttles()
assert [type(x) for x in throttles] == [TrustPolicyMinThrottle, TrustPolicyDayThrottle]

# L27: exercise the exact installer block with both a fast failure and a hung helper.
install = (ROOT / "install.sh").read_text(encoding="utf-8")
match = re.search(
    r'TRUST_POLICY_CHECK_TIMEOUT_SECONDS="\$\{TEC_TAC_TRUST_POLICY_CHECK_TIMEOUT_SECONDS:-30\}".*?\nfi\nlog "Installed persistent trust-policy revert service/timer\."',
    install,
    re.S,
)
assert match, "bounded immediate trust-policy check block not found"
block = match.group(0)
assert 'timeout --signal=TERM --kill-after=5s' in block
assert install.index("systemctl enable --now tec-tac-trust-policy-revert.timer") < match.start()

with tempfile.TemporaryDirectory(prefix="trust-policy-install-151-") as raw:
    td = Path(raw)
    for mode, body, max_elapsed in (
        ("fail", "echo failed-fast >&2\nexit 23\n", 3.0),
        ("hang", "sleep 30\necho should-not-print\n", 4.0),
    ):
        cli = td / f"cli-{mode}"
        cli.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        cli.chmod(0o755)
        script = td / f"probe-{mode}.sh"
        script.write_text(
            "#!/bin/bash\nset -e\n"
            f"TRUST_POLICY_CLI={cli!s}\n"
            "TEC_TAC_TRUST_POLICY_CHECK_TIMEOUT_SECONDS=1\n"
            "log(){ printf '%s\\n' \"$*\"; }\n"
            + block
            + "\nprintf 'AFTER-CHECK\\n'\n",
            encoding="utf-8",
        )
        started = time.monotonic()
        proc = subprocess.run(["bash", str(script)], text=True, capture_output=True, timeout=8)
        elapsed = time.monotonic() - started
        assert proc.returncode == 0, (mode, proc.returncode, proc.stdout, proc.stderr)
        assert "AFTER-CHECK" in proc.stdout
        assert "persistent timer will retry" in proc.stdout
        assert elapsed < max_elapsed, (mode, elapsed, proc.stdout, proc.stderr)

print("[TEST] PASS tracker partial closure 1.15.151")
