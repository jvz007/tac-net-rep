#!/usr/bin/env python3
"""1.17.105: the daily module repository sync on a server with no Licensing module (held from 1.17.103).

Reuses tests/licensing-repository-1.17.103.py (run whole, so its own checks pass first) for its extracted module_repository functions.

1. No Licensing module (licensing.catalogue provider missing) and the Licensing source is the only enabled one: the run succeeds, the
   provider is never asked, one info line is logged and the audit row counts licensing_skipped.
2. The same with an ordinary repository next to it: only the Licensing source is skipped.
3. A Licensing module that is installed but disabled or unhealthy, or a state that cannot be read: the run still fails as before.
4. A disabled Licensing source is not counted as skipped. The Sync action (sync_all with no skip list) is unchanged.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE / "licensing-repository-1.17.103.py"
HARNESS = types.ModuleType("harness")
HARNESS.__file__ = str(BASE)
sys.modules["harness"] = HARNESS
NS: dict = HARNESS.__dict__
exec(compile(BASE.read_text(encoding="utf-8"), str(BASE), "exec"), NS)  # noqa: S102 - the shared test harness
must, ns, write_config, lic_record, AUDIT, CALLS, PROVIDER = (NS[k] for k in ("must", "ns", "write_config", "lic_record", "AUDIT", "CALLS", "PROVIDER"))
FakeProvider, state_answer = NS["FakeProvider"], NS["state_answer"]


class RecordingLog:
    def __init__(self):
        self.records = []

    def _add(self, level, message, *args, **kwargs):
        self.records.append((level, message % args if args else message))

    def info(self, message, *args, **kwargs):
        self._add("info", message, *args)

    def warning(self, message, *args, **kwargs):
        self._add("warning", message, *args)

    def error(self, message, *args, **kwargs):
        self._add("error", message, *args)


LOG = RecordingLog()
ns["logger"] = LOG
STATUS = {"state": "missing", "raise": False}


def capability_status(capability_id, *, version=None, module_id=None, check_health=True):
    if STATUS["raise"]:
        raise RuntimeError("registry unreadable")
    must(capability_id == "licensing.catalogue" and check_health is False, (capability_id, check_health))
    return {"id": capability_id, "module_id": "licensing", "state": STATUS["state"], "available": STATUS["state"] == "available"}


sys.modules["tec_tac.capabilities"].capability_status = capability_status
run = ns["run_scheduled_sync"]


def sync_rows():
    return [r for r in AUDIT.ROWS if r["object_type"] == "module_repository" and r["action"] == "sync"]


def failed_run():
    try:
        run({"parameters": {}})
    except RuntimeError as exc:
        return exc.__class__.__name__ == "SchedulerPermanentError"
    return False


# --- 1. only the Licensing source, no Licensing module
write_config([lic_record()], defaults_seeded=["tec-tac-licensing"])
PROVIDER["obj"] = FakeProvider(state_answer("licensing_unavailable"))
CALLS.clear()
LOG.records.clear()
AUDIT.ROWS.clear()
counts = run({"parameters": {}})
must(counts == {"repositories": 0, "ok": 0, "failed": 0, "entries_skipped": 0, "licensing_skipped": 1}, counts)
must(not [c for c in CALLS if c[0] == "get_capability"], "the provider was asked")
must([level for level, _ in LOG.records] == ["info"] and "Licensing module is not installed" in LOG.records[0][1], LOG.records)
rows = sync_rows()
must(len(rows) == 1, rows)
print("       1. no Licensing module, only the Licensing source: the run succeeds with one info line and licensing_skipped 1")

# --- 2. an ordinary repository next to it: only the Licensing source is skipped
seen = []
real_sync_repository = ns["sync_repository"]


def sync_repository(repository_id):
    seen.append(repository_id)
    if repository_id == "tec-tac-licensing":
        return real_sync_repository(repository_id)
    raise ns["ModuleRepositoryError"]("index unreachable")


ns["sync_repository"] = sync_repository
other = {"id": "partner", "name": "Partner", "url": "https://partner.example.test/index.json", "enabled": True, "priority": 10,
         "trust": "custom", "created_at": "x", "updated_at": "x"}
write_config([other, lic_record()], defaults_seeded=["tec-tac-licensing"])
must(failed_run(), "every repository that was tried failed: the run fails")
must(seen == ["partner"], seen)
seen.clear()
# --- 4. the Sync action (no skip list) still tries the Licensing source; a disabled Licensing source is never counted as skipped
results = ns["sync_all"](enabled_only=True)
must(seen == ["partner", "tec-tac-licensing"] and len(results) == 2, seen)
seen.clear()
write_config([lic_record(enabled=False)], defaults_seeded=["tec-tac-licensing"])
counts = run({"parameters": {}})
must(counts == {"repositories": 0, "ok": 0, "failed": 0, "entries_skipped": 0}, counts)
ns["sync_repository"] = real_sync_repository
print("       2, 4. only the Licensing source is skipped; the Sync action still tries it; a disabled source is not counted")

# --- 3. installed but disabled or unhealthy, or an unreadable state: the run still fails as before
write_config([lic_record()], defaults_seeded=["tec-tac-licensing"])
for state in ("disabled", "unhealthy", "capability-unavailable"):
    STATUS["state"] = state
    must(failed_run(), f"{state}: the run must still fail")
STATUS["raise"] = True
LOG.records.clear()
must(failed_run(), "an unreadable state skips nothing")
must(any(level == "warning" and "could not be read" in text for level, text in LOG.records), LOG.records)
STATUS.update({"state": "missing", "raise": False})
print("       3. a disabled or unhealthy Licensing module, or an unreadable state, still fails the run")

# --- docs and line endings
ROOT = NS["ROOT"]
repo_bytes = (ROOT / "framwork" / "tec_tac" / "module_repository.py").read_bytes()
must(b"\r\n" in repo_bytes and b"\n" not in repo_bytes.replace(b"\r\n", b""), "module_repository.py lost its CRLF")
doc = (ROOT / "docs" / "module-repositories.md").read_text(encoding="utf-8")
must("licensing_skipped" in doc and "1.17.105" in doc, "the help text of the skip")
print("[TEST] PASS licensing sync skip 1.17.105")
