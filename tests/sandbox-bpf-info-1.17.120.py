#!/usr/bin/env python3
"""1.17.120 regression: ``-BPF_FRAMEWORK`` is information, readiness comes from the behavioural probes (core.sandbox canary fix 2).

systemd's own BPF framework flag does not describe the kernel cgroup BPF that the address filter uses, so the selftest no longer fails on it:

* ``+PAM -BPF_FRAMEWORK`` with every probe passing: ready, the bpf_framework row is ok and says 'information only', and no reason mentions BPF;
* ``-BPF_FRAMEWORK`` with a loopback that stays reachable: not ready, with the address filter reason (never a weaker mode);
* ``+BPF_FRAMEWORK`` with a failing filter probe (loopback reachable, private range sent, control cannot connect): not ready;
* the row is always present and always ok (it is information), whatever the flag says.

Not runnable here: real systemd. The dev02 canary prints the real bpf_framework row.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_120b", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_120b", "sandbox-fake-runner-1.17.120.py")
sh, must, BASE = H.sh, H.must, H.BASE


def selftest(fake):
    return F.run_selftest(sh, H.RUN, BASE, fake)


NO_BPF = "systemd 255 (255.4-1ubuntu8)\n+PAM -BPF_FRAMEWORK\n"
WITH_BPF = "systemd 255 (255.4-1ubuntu8)\n+PAM +BPF_FRAMEWORK\n"

# ---- -BPF_FRAMEWORK and every probe passes: ready
status = selftest(F.Fake(systemctl=(0, NO_BPF)))
row = status["checks"]["bpf_framework"]
must(status["ready"] is True and status["reason"] == "ready", status)
must(row["ok"] is True and "information only" in row["detail"] and "BPF framework" in row["detail"] and "proved by the probes" in row["detail"], row)
must("BPF" not in status["reason"], status["reason"])
must(status["address_filter_ok"] is True, status)

# ---- +BPF_FRAMEWORK: the row says it is not disabled
status = selftest(F.Fake(systemctl=(0, WITH_BPF)))
must(status["ready"] is True and status["checks"]["bpf_framework"] == {"ok": True, "detail": "BPF_FRAMEWORK is not disabled"}, status["checks"]["bpf_framework"])

# ---- -BPF_FRAMEWORK and a loopback that stays reachable: not ready, with the address filter reason
status = selftest(F.Fake(systemctl=(0, NO_BPF), address_filter_loopback="leak"))
must(status["ready"] is False and "reaching the server itself" in status["reason"], status)
must(status["checks"]["address_filter_loopback"]["ok"] is False and status["address_filter_ok"] is False, status["checks"])
must(status["checks"]["bpf_framework"]["ok"] is True, "the row stays information")
must(status["reason"] != "ready" and "weaker" not in status["reason"], status["reason"])

# ---- +BPF_FRAMEWORK and a failing filter probe: not ready (the flag never makes a broken filter pass)
for label, overrides, part in (
    ("loopback reachable", {"address_filter_loopback": "leak"}, "reaching the server itself"),
    ("private range sent", {"address_filter_private": (0, "10.255.255.254 sent\n172.31.255.254 sent\n")}, "private-range"),
    ("control cannot connect", {"address_filter_control": (0, "blocked\n")}, "could not be checked"),
):
    status = selftest(F.Fake(systemctl=(0, WITH_BPF), **overrides))
    must(status["ready"] is False and part in status["reason"] and status["address_filter_ok"] is False, (label, status["reason"]))
    status = selftest(F.Fake(systemctl=(0, NO_BPF), **overrides))
    must(status["ready"] is False and part in status["reason"], (label, "same without the framework", status["reason"]))

# ---- the row exists in every case, even without any systemctl answer, and is never the reason for a failure
status = selftest(F.Fake(systemctl=(127, "")))
must("bpf_framework" in status["checks"] and status["checks"]["bpf_framework"]["ok"] is True and "BPF" not in status["reason"], status)

# ---- the helper source no longer fails the selftest on the flag
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must('fail("bpf_framework"' not in source, "no fail() call for bpf_framework")

print("[TEST] PASS sandbox bpf information 1.17.120")
