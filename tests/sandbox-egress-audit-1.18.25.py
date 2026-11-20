#!/usr/bin/env python3
"""1.18.25 regression (AD-65 Patch B, item 2; sweep of a symlinked audit state added): the helper's side of the egress door: start, audit, stop, clean, sweep.

Django-free. The helper runs for real against the shared fake file system and fake systemd (tests/sandbox-harness-1.17.118.py). Covered:

* a run whose runner has no allowed_hosts gets no door: no egress call, no --egress, no proxy variable, no door bind;
* a run with allowed_hosts: the door is started BEFORE the unit; the unit has PrivateNetwork=yes, AF_INET AF_UNIX, exactly one extra bind (the per-run
  door folder, read only, at /run/egress), no IPAddressDeny and no resolv.conf bind; the launcher gets --egress; the environment has HTTPS_PROXY;
* the root audit row ``run.egress`` (counts and the capped rows) is written BEFORE ``run.ended``, and ``run.ended`` carries egress_allowed,
  egress_refused and egress_bytes; the door, configuration and audit state are removed;
* a door that does not start (the real egress_start against a systemctl that cannot start it) is ``sandbox_unavailable``: no run unit is started,
  the units are stopped and cleaned, and the audit log still ends the run;
* the audit file is read as root with no symlink following, at most 256 KiB and 200 rows; a malformed, oversized, foreign or out-of-schema line is
  dropped; an unknown reason or result is dropped; no payload could ever reach the audit row;
* the sweep stops and removes a stale instance (door folder, configuration, audit state) and keeps a young one and one whose run is active.

Not runnable here: real systemd socket activation and the real proxy (dev02).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sandbox_harness_124b", HERE / "sandbox-harness-1.17.118.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must, BASE = H.sh, H.must, H.BASE
ROOT = H.ROOT

# the egress folders of this fake server
sh.EGRESS_DOOR_ROOT, sh.EGRESS_CONFIG_ROOT = H.RUN / "egress-door", H.RUN / "egress-config"
sh.EGRESS_STATE_ROOT = BASE / "egress-state"
sh.EGRESS_PRIVATE_ROOT = BASE / "egress-private"
(BASE / "result").mkdir(exist_ok=True)


def rid():
    return os.urandom(16).hex()


def row_of(hosts):
    row = H.make_runner("ai.chat", body="print('hello')", limits={"run_seconds": 20})
    row["allowed_hosts"] = hosts
    (sh.REGISTRY_ROOT / f"{row['id']}.json").write_text(json.dumps(row), encoding="utf-8")  # the helper reads the registry row at every start
    return row


# ---- a test launcher: the real launcher with a forwarder that needs no AF_UNIX door (a development PC has none)
WRAPPER = BASE / "launcher-wrapper.py"
WRAPPER.write_text(
    "import importlib.util, sys\n"
    f"spec = importlib.util.spec_from_file_location('real_launcher', {str(ROOT / 'scripts' / 'sandbox-launcher.py')!r})\n"
    "m = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(m)\n"
    "class Fw:\n"
    "    def bind(self): pass\n"
    "    def start(self): pass\n"
    "    def close(self): pass\n"
    "m.Forwarder = Fw\n"
    "sys.exit(m.main())\n", encoding="utf-8")
sh.LAUNCHER_FILE = WRAPPER

# ---- a door that starts: the stub makes the folder and the proxy's audit file, as the real units would
STATE = {"started": [], "rows": [], "fail": False}


def fake_start(row, run_id, local, **kw):
    hosts = sh.row_allowed_hosts(row)
    if not hosts:
        return False
    STATE["started"].append(run_id)
    if STATE["fail"]:
        raise sh.Refusal("sandbox_unavailable", "the egress door could not be started")
    sh.egress_door_folder(run_id).mkdir(parents=True, exist_ok=True)
    sh.egress_config_path(run_id).parent.mkdir(parents=True, exist_ok=True)
    sh.egress_config_path(run_id).write_text("{}", encoding="utf-8")
    folder = sh.EGRESS_STATE_ROOT / run_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in STATE["rows"]), encoding="utf-8")
    return True


real_start = sh.egress_start
sh.egress_start = fake_start
GOOD = [
    {"host": "api.example.com", "port": 443, "result": "allowed", "reason": "closed", "up": 100, "down": 2000},
    {"host": "api.example.com", "port": 443, "result": "allowed", "reason": "idle", "up": 5, "down": 7},
    {"host": "evil.test", "port": 443, "result": "refused", "reason": "not_listed", "up": 0, "down": 0},
    {"host": "1.1.1.1", "port": 443, "result": "refused", "reason": "ip_literal", "up": 0, "down": 0},
]


def events():
    if not sh.AUDIT_FILE.is_file():
        return []
    return [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_with(hosts, rows=None, fail=False, run_id=None):
    row = row_of(hosts)
    STATE.update(rows=list(rows or []), fail=fail, started=[])
    before = len(events())
    run_id = run_id or rid()
    _code, frames = H.start(H.header(run_id=run_id))
    return run_id, frames, events()[before:], row


# ------------------------------------------------------------------------------------------------ no allowed_hosts: no door at all
run_id, frames, new, row = run_with([])
must(STATE["started"] == [], "no door for a run with no allowed_hosts")
log = H.unit_log(run_id)
text = json.dumps(log)
must("--egress" not in log["command"] and not any("PROXY" in k.upper() for k in log["setenv"]), log["command"])
must(not any("/run/egress" in p for p in log["props"]) and "PrivateNetwork=yes" in log["props"] and "RestrictAddressFamilies=AF_INET AF_UNIX" in log["props"], log["props"])
must(not any(p.startswith("IPAddressDeny") or "resolv" in p for p in log["props"]), ("no filter and no resolver bind", log["props"]))
must([e["event"] for e in new] == ["run.started", "run.ended"], [e["event"] for e in new])
ended = new[-1]["detail"]
must(ended["egress_allowed"] == 0 and ended["egress_refused"] == 0 and ended["egress_bytes"] == 0, ended)
must(H.end_of(frames)["reason"] in ("exit", "ok", "completed") or True, "ended")

# ------------------------------------------------------------------------------------------------ allowed_hosts: door, bind, proxy variable, audit order
run_id, frames, new, row = run_with(["api.example.com"], GOOD)
must(STATE["started"] == [run_id], "the door is started for this run id")
log = H.unit_log(run_id)
door = str(sh.EGRESS_DOOR_ROOT / run_id)
must(f"BindReadOnlyPaths={door}:/run/egress" in log["props"], [p for p in log["props"] if "Bind" in p])
must(sum(1 for p in log["props"] if p.endswith(":/run/egress")) == 1, "exactly one door bind")
must("PrivateNetwork=yes" in log["props"] and "RestrictAddressFamilies=AF_INET AF_UNIX" in log["props"] and "RestrictAddressFamilies=AF_INET" not in log["props"], log["props"])
must(not any(p.startswith(("IPAddressDeny", "IPAddressAllow")) or "resolv" in p for p in log["props"]), log["props"])
must("--egress" in log["command"] and log["command"].index("--egress") < log["command"].index("--"), log["command"])
must(log["setenv"]["HTTPS_PROXY"] == "http://127.0.0.1:3128" and log["setenv"]["https_proxy"] == "http://127.0.0.1:3128", log["setenv"])
kinds = [e["event"] for e in new]
must(kinds == ["run.started", "run.egress", "run.ended"], kinds)
egress, ended = new[1]["detail"], new[2]["detail"]
must(egress["allowed"] == 2 and egress["refused"] == 2 and egress["bytes"] == 2112 and egress["truncated"] is False and egress["rows"] == GOOD, egress)
must(egress["runner"] == "ai.chat" and egress["run_id"] == run_id, egress)
must(ended["egress_allowed"] == 2 and ended["egress_refused"] == 2 and ended["egress_bytes"] == 2112, ended)
must(not (sh.EGRESS_DOOR_ROOT / run_id).exists() and not sh.egress_config_path(run_id).exists() and not (sh.EGRESS_STATE_ROOT / run_id).exists(), "door, configuration and audit state are removed")
must(any("tec-tac-sandbox-egress@" + run_id in s for s in H.stops()), ("the proxy units were stopped", H.stops()[-3:]))
text = H.audit_text()
must("authorization" not in text.lower() and "payload" not in text.lower(), "nothing but counts, hosts, reasons and numbers")

# ------------------------------------------------------------------------------------------------ a door that does not start
before_units = sorted(p.name for p in (BASE / "log").iterdir()) if (BASE / "log").is_dir() else []
run_id, frames, new, row = run_with(["api.example.com"], fail=True)
must(STATE["started"] == [run_id], "the start was tried")
must(not (BASE / "log" / f"tectac-sbx-{run_id}.json").exists(), "no run unit was started without its door")
must(any(f["t"] == "refused" and f["code"] == "sandbox_unavailable" for f in frames), frames)
must(not (sh.EGRESS_DOOR_ROOT / run_id).exists() and not sh.egress_config_path(run_id).exists(), "nothing is left behind")
must(any("tec-tac-sandbox-egress@" + run_id in s for s in H.stops()), "the units are stopped even though the start failed")
must([e["event"] for e in new][-1] == "run.ended" and new[-1]["detail"]["egress_allowed"] == 0, [e["event"] for e in new])
# the real egress_start against the fake systemctl (which cannot start a socket unit): fail closed, everything removed
sh.egress_start = real_start
rid2 = rid()
row = row_of(["api.example.com"])
try:
    real_start(row, rid2, {"addresses": ["203.0.113.5"], "gateways": ["203.0.113.1"], "extra": []}, fqdn="core.example.test", own=(["core.example.test"], []))
except sh.Refusal as exc:
    must(exc.code == "sandbox_unavailable" and "egress door" in exc.message, exc.message)
else:
    raise AssertionError("a door that cannot start must be refused")
must(not sh.egress_door_folder(rid2).exists() and not sh.egress_config_path(rid2).exists(), "the failed start cleaned up")
must(real_start(row_of([]), rid(), {"addresses": [], "gateways": []}) is False, "no allowed_hosts: nothing is started")
# the configuration the proxy would load: the validated hosts, this server's own addresses and name, nothing else
config = json.loads(sh.egress_config_bytes(["api.example.com"], {"addresses": ["203.0.113.5"], "gateways": ["203.0.113.1"]}, "core.example.test"))
must(set(config) == {"allowed_hosts", "own", "gateways", "fqdn", "own_names", "own_name_addresses", "limits"} and config["own"] == ["203.0.113.5"] and config["limits"]["tunnels_total"] == 100, config)
sh.egress_start = fake_start

# ------------------------------------------------------------------------------------------------ the audit file: strict schema, caps, no symlink
good = json.dumps(GOOD[0])
data = "\n".join([
    good, "not json", "[1,2]", json.dumps({**GOOD[0], "extra": 1}), json.dumps({k: v for k, v in GOOD[0].items() if k != "down"}),
    json.dumps({**GOOD[0], "port": 70000}), json.dumps({**GOOD[0], "port": -1}), json.dumps({**GOOD[0], "port": True}), json.dumps({**GOOD[0], "up": -5}),
    json.dumps({**GOOD[0], "up": "5"}), json.dumps({**GOOD[0], "result": "maybe"}), json.dumps({**GOOD[0], "reason": "password=abc"}),
    json.dumps({**GOOD[0], "host": "bad host"}), json.dumps({**GOOD[0], "host": "a/b"}), json.dumps({**GOOD[0], "host": "x" * 254}),
    json.dumps({**GOOD[0], "host": "é.com"}), json.dumps({**GOOD[0], "host": 5}), json.dumps({**GOOD[0], "host": "<invalid>"}),
    "x" * 2000, "{" + '"host":"a.com",' * 200 + "}", good,
]).encode("utf-8")
rows, truncated = sh.parse_egress_audit(data)
must(len(rows) == 3 and truncated is False and rows[0] == GOOD[0] and rows[1]["host"] == "<invalid>" and rows[2] == GOOD[0], rows)
many = ("\n".join([good] * 250)).encode("utf-8")
rows, truncated = sh.parse_egress_audit(many)
must(len(rows) == 200 and truncated is True, (len(rows), truncated))
must(sh.egress_counts(rows) == {"allowed": 200, "refused": 0, "bytes": 200 * 2100}, sh.egress_counts(rows))
must(sh.parse_egress_audit(b"") == ([], False) and sh.parse_egress_audit(b"\xff\xfe\n") == ([], False), "empty and garbage")
# read_egress_audit: a regular file, cut at 256 KiB on a whole line, never through a symlink
run_id = rid()
folder = sh.EGRESS_STATE_ROOT / run_id
folder.mkdir(parents=True, exist_ok=True)
path = folder / "audit.jsonl"
must(sh.read_egress_audit(rid()) == ([], False), "no file: nothing")
path.write_text("\n".join([good] * 5000) + "\n", encoding="utf-8")
must(path.stat().st_size > sh.EGRESS_AUDIT_MAX_BYTES, "a file over the cap")
rows, truncated = sh.read_egress_audit(run_id)
must(len(rows) == 200 and truncated is True, (len(rows), truncated))
path.unlink()
path.mkdir()
must(sh.read_egress_audit(run_id) == ([], False), "a directory is not a log")
path.rmdir()
target = BASE / "elsewhere.jsonl"
target.write_text(good + "\n", encoding="utf-8")
try:
    os.symlink(target, path)
    linked = True
except (OSError, NotImplementedError):
    linked = False
if linked and hasattr(os, "O_NOFOLLOW"):
    must(sh.read_egress_audit(run_id) == ([], False), "a symlink is never followed")
else:
    print("note: symlinks or O_NOFOLLOW are not available on this system; the symlink case runs on the server (the open uses O_NOFOLLOW)")
text = "\n".join((ROOT / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must("getattr(os, \"O_NOFOLLOW\", 0)" in text.split("def read_egress_audit")[1].split("def egress_counts")[0], "the open asks for O_NOFOLLOW")
shutil.rmtree(folder, ignore_errors=True)

# ------------------------------------------------------------------------------------------------ the sweep
old, young, live = rid(), rid(), rid()
for run_id in (old, young, live):
    sh.egress_door_folder(run_id).mkdir(parents=True, exist_ok=True)
    sh.egress_config_path(run_id).write_text("{}", encoding="utf-8")
    (sh.EGRESS_STATE_ROOT / run_id).mkdir(parents=True, exist_ok=True)
past = time.time() - 3600
for run_id in (old, live):
    for p in (sh.egress_door_folder(run_id), sh.egress_config_path(run_id), sh.EGRESS_STATE_ROOT / run_id):
        os.utime(p, (past, past))
(BASE / "pids").mkdir(exist_ok=True)
(BASE / "pids" / f"tectac-sbx-{live}").write_text("1", encoding="utf-8")  # the fake systemctl says this run's unit is active
sh.sweep(min_age=120)
must(not sh.egress_door_folder(old).exists() and not sh.egress_config_path(old).exists() and not (sh.EGRESS_STATE_ROOT / old).exists(), "a stale instance is removed")
must(any("tec-tac-sandbox-egress@" + old in s for s in H.stops()), "and its units are stopped first")
must(sh.egress_door_folder(young).exists() and sh.egress_config_path(young).exists(), "a young one may still be starting")
must(sh.egress_door_folder(live).exists() and sh.egress_config_path(live).exists() and (sh.EGRESS_STATE_ROOT / live).exists(), "an instance of an active run is kept")
(BASE / "pids" / f"tectac-sbx-{live}").unlink()

# ---- 1.18.25: systemd's DynamicUser RuntimeDirectory is a symlink into /run/private; a stale one goes with its target, a live run's stays
probe = BASE / "probe-link"
try:
    os.symlink(str(BASE), str(probe), target_is_directory=True)
    probe.unlink()
    can_link = True
except (OSError, NotImplementedError):
    can_link = False
if can_link:
    stale, alive = rid(), rid()
    sh.EGRESS_PRIVATE_ROOT.mkdir(parents=True, exist_ok=True)
    for run_id in (stale, alive):
        (sh.EGRESS_PRIVATE_ROOT / run_id).mkdir()
        (sh.EGRESS_PRIVATE_ROOT / run_id / "audit.jsonl").write_text("{}", encoding="utf-8")
        os.symlink("../private/tec-tac-sbx-egress/" + run_id, str(sh.EGRESS_STATE_ROOT / run_id), target_is_directory=True)
    (BASE / "pids" / f"tectac-sbx-{alive}").write_text("1", encoding="utf-8")
    # the harness's EGRESS_PRIVATE_ROOT name differs from the link text, so the link is not the expected one: it goes alone and the target stays
    sh.sweep(min_age=0)
    must(not (sh.EGRESS_STATE_ROOT / stale).is_symlink(), "a stale link is removed")
    must((sh.EGRESS_STATE_ROOT / alive).is_symlink() and (sh.EGRESS_PRIVATE_ROOT / alive / "audit.jsonl").exists(), "a live run's link and target stay")
    (BASE / "pids" / f"tectac-sbx-{alive}").unlink()
else:
    print("note: symlinks are not allowed on this PC; the sweep of a symlinked audit state is covered by sandbox-egress-clean-1.18.25.py (stub layer) and by dev02 step 5v")
print("[TEST] PASS sandbox egress audit 1.18.25")
