#!/usr/bin/env python3
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
THROTTLES = ROOT / "framwork/tec_tac/throttles.py"
INSTALL = ROOT / "install.sh"
CLI = ROOT / "scripts/trust-policy-cli.py"


def test_l26_authenticated_throttle_keys() -> None:
    source = THROTTLES.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {
        "_AuthenticatedAttemptThrottle",
        "TrustPolicyMinThrottle",
        "TrustPolicyDayThrottle",
    }
    nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in wanted]
    assert {n.name for n in nodes} == wanted

    class SimpleRateThrottle:
        cache_format = "throttle_%(scope)s_%(ident)s"

    ns = {"SimpleRateThrottle": SimpleRateThrottle}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(THROTTLES), "exec"), ns)

    req1 = SimpleNamespace(user=SimpleNamespace(pk=101), META={"REMOTE_ADDR": "10.0.0.5"})
    req2 = SimpleNamespace(user=SimpleNamespace(pk=202), META={"REMOTE_ADDR": "10.0.0.5"})
    for name in ("TrustPolicyMinThrottle", "TrustPolicyDayThrottle"):
        throttle = ns[name]()
        key1 = throttle.get_cache_key(req1, None)
        key2 = throttle.get_cache_key(req2, None)
        assert key1 and key2
        assert key1 != key2, (name, key1, key2)
        assert "101:10.0.0.5" in key1
        assert "202:10.0.0.5" in key2


def test_l27_failed_immediate_check_is_nonfatal() -> None:
    install = INSTALL.read_text(encoding="utf-8")
    match = re.search(
        r'if ! TRUST_POLICY_CHECK_OUTPUT="\$\(\$\{TRUST_POLICY_CLI\} check-revert 2>&1\)"; then\n'
        r'.*?\nfi',
        install,
        re.S,
    )
    assert match, "installer immediate trust-policy check block not found"
    block = match.group(0)
    assert install.index("systemctl enable --now tec-tac-trust-policy-revert.timer") < install.index(block)

    with tempfile.TemporaryDirectory(prefix="trust-policy-install-150-") as raw:
        td = Path(raw)
        fail_cli = td / "trust-policy-cli"
        fail_cli.write_text("#!/bin/sh\necho simulated-failure >&2\nexit 23\n", encoding="utf-8")
        fail_cli.chmod(0o755)
        script = td / "probe.sh"
        script.write_text(
            "#!/bin/bash\nset -e\n"
            f"TRUST_POLICY_CLI={fail_cli!s}\n"
            "log(){ printf '%s\\n' \"$*\"; }\n"
            + block
            + "\nprintf 'AFTER-CHECK\\n'\n",
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(script)], text=True, capture_output=True, check=False)
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        assert "AFTER-CHECK" in proc.stdout
        assert "persistent timer will retry" in proc.stdout
        assert "simulated-failure" in proc.stdout


def _child_lock_probe(mode: str, root: Path, log_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(f"trust_policy_cli_150_{mode}", CLI)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    mod.POLICY_ROOT = root
    mod.POLICY_FILE = root / "update-trust-policy.json"
    mod.PENDING_FILE = root / "pending-trust-policy-revert.json"
    mod.AUDIT_DIR = root / "audit"
    mod.AUDIT_FILE = mod.AUDIT_DIR / "trust-policy-audit.jsonl"
    mod.os.fchown = lambda *args, **kwargs: None

    def record(label: str) -> None:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"{label} {time.monotonic_ns()}\n")
            fh.flush()
            os.fsync(fh.fileno())

    if mode == "set":
        def fake_set(target: str, *, reason: str, hours: int):
            record("set-enter")
            time.sleep(0.45)
            record("set-exit")
            return {"status": "ok"}
        mod._set_level_locked = fake_set
        mod.set_level("signed_production", reason="probe", hours=8)
    elif mode == "check":
        def fake_check():
            record("check-enter")
            time.sleep(0.05)
            record("check-exit")
            return {"status": "ok"}
        mod._check_revert_due_locked = fake_check
        mod.check_revert_due()
    else:
        raise SystemExit(f"unknown child mode: {mode}")


def test_l28_set_and_check_revert_serialize() -> None:
    with tempfile.TemporaryDirectory(prefix="trust-policy-lock-150-") as raw:
        td = Path(raw)
        policy_root = td / "policy"
        policy_root.mkdir()
        log_path = td / "events.log"
        env = dict(os.environ)
        env["TEC_TAC_TEST_ALLOW_NONROOT"] = "1"
        p1 = subprocess.Popen([sys.executable, __file__, "--child", "set", str(policy_root), str(log_path)], env=env)
        deadline = time.time() + 5
        while time.time() < deadline:
            if log_path.exists() and "set-enter" in log_path.read_text(encoding="utf-8"):
                break
            time.sleep(0.01)
        else:
            p1.kill()
            raise AssertionError("set_level child did not enter locked mutation")
        p2 = subprocess.Popen([sys.executable, __file__, "--child", "check", str(policy_root), str(log_path)], env=env)
        assert p1.wait(timeout=5) == 0
        assert p2.wait(timeout=5) == 0
        events = {}
        for line in log_path.read_text(encoding="utf-8").splitlines():
            name, stamp = line.split()
            events[name] = int(stamp)
        assert events["set-enter"] < events["set-exit"]
        assert events["set-exit"] <= events["check-enter"], events
        assert events["check-enter"] < events["check-exit"]


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--child":
        _child_lock_probe(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]))
        return
    test_l26_authenticated_throttle_keys()
    test_l27_failed_immediate_check_is_nonfatal()
    test_l28_set_and_check_revert_serialize()
    print("trust-policy closure 1.15.150: PASS")


if __name__ == "__main__":
    main()
