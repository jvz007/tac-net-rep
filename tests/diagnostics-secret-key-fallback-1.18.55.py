#!/usr/bin/env python3
"""Regression: Core 1.18.55 check core.secret_store.service-access when systemd cannot name a MainPID (celery is Type=forking with no PIDFile).
No Django needed. The key file is only stat-ed, never opened. The readers are fakes; the real systemctl and /proc run on dev02."""
import builtins
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
di = importlib.import_module("tec_tac.diagnostics_install")

GID, UID, OTHER_UID = 1001, 998, 0
SERVICES = ("rmm", "daphne", "celery", "celerybeat")


class KeyInfo:
    st_gid = GID


def status(uid, groups):
    return f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGroups:\t{' '.join(str(g) for g in groups)} \n"


GOOD = status(UID, (33, GID))
BAD = status(UID, (33,))
ROOT_HELPER = status(OTHER_UID, ())


def run(mainpids, active, cgroups, statuses, uid=UID):
    def pid_reader(unit):
        value = mainpids[unit.split(".")[0]]
        if isinstance(value, Exception):
            raise value
        return value

    def status_reader(pid):
        value = statuses[pid]
        if isinstance(value, Exception):
            raise value
        return value

    def active_reader(unit):
        value = active[unit.split(".")[0]]
        if isinstance(value, Exception):
            raise value
        return value

    def process_reader(unit):
        value = cgroups[unit.split(".")[0]]
        if isinstance(value, Exception):
            raise value
        return value

    return di.secret_key_service_access_check(
        key_stat=lambda p: KeyInfo(), pid_reader=pid_reader, status_reader=status_reader, active_reader=active_reader,
        process_reader=process_reader, uid_reader=lambda service: uid)


MAIN = {"rmm": "11", "daphne": "12", "celery": "0", "celerybeat": "14"}
ACTIVE = {name: "active" for name in SERVICES}
base_status = {11: GOOD, 12: GOOD, 14: GOOD}


def states(r):
    return {row["service"]: row["state"] for row in r["details"]["services"]}


real_open = builtins.open
builtins.open = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the key file must never be opened"))
try:
    # MainPID 0, active unit, good cgroup processes -> ok
    r = run(MAIN, ACTIVE, {"celery": [21, 22, 23]}, {**base_status, 21: GOOD, 22: GOOD, 23: GOOD})
    assert r["status"] == "pass" and states(r)["celery"] == "ok", r

    # a helper of another user without the group is ignored
    r = run(MAIN, ACTIVE, {"celery": [21, 22, 99]}, {**base_status, 21: GOOD, 22: GOOD, 99: ROOT_HELPER})
    assert r["status"] == "pass" and states(r)["celery"] == "ok", r

    # one process of the service lacks the group -> missing_group and the check fails
    r = run(MAIN, ACTIVE, {"celery": [21, 22]}, {**base_status, 21: GOOD, 22: BAD})
    assert r["status"] == "fail" and states(r)["celery"] == "missing_group" and "celery.service" in r["summary"], r

    # an unreadable cgroup -> unknown (the check is unknown, not a pass and not not_running)
    r = run(MAIN, ACTIVE, {"celery": OSError("no cgroup")}, base_status)
    assert r["status"] == "unknown" and states(r)["celery"] == "unknown", r
    assert "celery" in r["summary"]

    # an empty cgroup, or only processes of another user -> unknown
    r = run(MAIN, ACTIVE, {"celery": []}, base_status)
    assert r["status"] == "unknown" and states(r)["celery"] == "unknown", r
    r = run(MAIN, ACTIVE, {"celery": [99]}, {**base_status, 99: ROOT_HELPER})
    assert r["status"] == "unknown" and states(r)["celery"] == "unknown", r

    # a process that exits while it is read is skipped
    r = run(MAIN, ACTIVE, {"celery": [21, 22]}, {**base_status, 21: FileNotFoundError(2, "gone"), 22: GOOD})
    assert r["status"] == "pass" and states(r)["celery"] == "ok", r
    r = run(MAIN, ACTIVE, {"celery": [21]}, {**base_status, 21: FileNotFoundError(2, "gone")})
    assert r["status"] == "unknown" and states(r)["celery"] == "unknown", "nothing inspected is never a pass"

    # no user id known -> unknown
    r = run(MAIN, ACTIVE, {"celery": [21]}, {**base_status, 21: GOOD}, uid=None)
    assert r["status"] == "unknown" and states(r)["celery"] == "unknown", r

    # MainPID 0 with an inactive unit is not_running, as before
    r = run(MAIN, {**ACTIVE, "celery": "inactive"}, {"celery": [21]}, {**base_status, 21: BAD})
    assert states(r)["celery"] == "not_running" and r["status"] == "pass", r
    r = run(MAIN, {**ACTIVE, "celery": "failed"}, {}, base_status)
    assert states(r)["celery"] == "not_running", r

    # a state that cannot be read is unknown, never not_running
    r = run(MAIN, {**ACTIVE, "celery": TimeoutError("slow")}, {}, base_status)
    assert states(r)["celery"] == "unknown" and r["status"] == "unknown", r

    # an unreadable MainPID or one that is gone falls back to the cgroup when the readers are there
    r = run({**MAIN, "celery": OSError("no systemctl")}, ACTIVE, {"celery": [21]}, {**base_status, 21: GOOD})
    assert states(r)["celery"] == "ok", r
    r = run({**MAIN, "celery": "555"}, ACTIVE, {"celery": [21]}, {**base_status, 555: FileNotFoundError(2, "gone"), 21: BAD})
    assert states(r)["celery"] == "missing_group", r

    # a usable MainPID is still read directly (no cgroup call)
    r = run({**MAIN, "celery": "13"}, ACTIVE, {"celery": OSError("must not be read")}, {**base_status, 13: GOOD})
    assert states(r)["celery"] == "ok", r

    # without the new readers the 1.18.54 answers are unchanged
    r = di.secret_key_service_access_check(key_stat=lambda p: KeyInfo(), pid_reader=lambda u: "0", status_reader=lambda p: GOOD)
    assert r["status"] == "unknown" and all(row["state"] == "not_running" for row in r["details"]["services"]), r
finally:
    builtins.open = real_open

# the production wiring: diagnostics.py hands the default readers over and keeps them read-only
source = (PKG_DIR / "diagnostics.py").read_text(encoding="utf-8")
for needle in ('"ActiveState"', '"ControlGroup"', "/sys/fs/cgroup", "active_reader=_active_state", "process_reader=_cgroup_pids", "uid_reader=_service_uid", "timeout=3"):
    assert needle in source, needle
body = source.split("def _secret_key_access_check")[1].split("def _storage_check")[0]
assert "master.key" not in body.replace("master key", "") and "chmod" not in body, "the check never touches the key file"

print("diagnostics secret key fallback 1.18.55: PASS")
