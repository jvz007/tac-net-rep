#!/usr/bin/env python3
"""1.17.104: module update detection, notices and the read routes (module automatic updates, phase 1: notify and highlight only).

Covered: the level (patch, minor, major; a pre-release, a -N rebuild, build metadata, a two-part version, a leading zero, a lower or equal
version and junk are other); detection from the Online catalog (installed and update_available only; blocked reasons for a newer Core,
a missing or older dependency and a source change); one notice per module version, never repeated (a second run, a cleared notice, an
older version offered again), and a newer version notifies again; only the superusers are asked for (system_notice_recipients with no
usernames); one audit row per first detection with the system actor; no notice while offline, with a refused licence, refused
credentials or a retired repository (the cached list still shows the update, marked source_current false); a failed notice is retried
and writes no audit row; an unreadable record is rebuilt without notices; the routes refuse a person without module-manage; the
contract refuses an unverified caller; the sync routes only queue the check (never run it in the request) and the daily sync runs it;
the contract allows a verified server module and refuses (and audits) an unverified caller, a premium, core or test module and an unknown module; the Celery task exists; a release notes link is kept only when it is https with no credential, query or fragment.

module_updates.py imports nothing from Django at module level, so it is loaded from its file with stub modules for its lazy imports.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import re
import sys
import tempfile
import types
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork/tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ module_state's real version code
STATE_TREE = ast.parse((PKG / "module_state.py").read_text(encoding="utf-8"))
state_ns: dict = {"re": re, "__name__": __name__}
from dataclasses import dataclass

state_ns["dataclass"] = dataclass
wanted = {"_VERSION_RE", "_CONSTRAINT_RE", "ModuleStateError", "Version", "_compare", "version_satisfies"}
nodes = [n for n in STATE_TREE.body if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in wanted)
         or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets))]
exec(compile(ast.Module(body=nodes, type_ignores=[]), "module_state.py", "exec"), state_ns)

# ------------------------------------------------------------------------------------------------------------------------- stubs
CATALOG = {"value": None}
NOTICES: dict = {}  # (client_id, user) -> notice
PUBLISH_CALLS: list = []
RECIPIENT_CALLS: list = []
AUDIT_ROWS: list = []
FAIL_PUBLISH = {"on": False}
SUPERUSERS = ["admin", "root-role-user"]
CALLER = {"value": None}


def online_catalog():
    return CATALOG["value"]


def system_notice_recipients(usernames=()):
    RECIPIENT_CALLS.append(tuple(usernames))
    return list(SUPERUSERS)


def publish_system_notice(recipients, *, client_id, message, title="", level="error", source="core", action_label="", action_route=""):
    if FAIL_PUBLISH["on"]:
        raise RuntimeError("database down")
    PUBLISH_CALLS.append({"recipients": list(recipients), "client_id": client_id, "message": message, "title": title, "level": level,
                          "source": source, "action_route": action_route})
    created = 0
    for user in recipients:
        if (client_id, user) not in NOTICES:
            NOTICES[(client_id, user)] = message
            created += 1
    must(len(client_id) <= 64 and re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", client_id), f"bad client id {client_id}")
    return created


def record(**kwargs):
    AUDIT_ROWS.append(kwargs)
    return {"recorded": True}


def service_audit_actor(**kwargs):
    return ("service", kwargs["module_id"], kwargs["service"], kwargs["identity"])


def atomic_json(path, payload, *, mode=0o660, default=None):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def calling_module_for_core_provider(*, provider_file, cache_seconds=0):
    return CALLER["value"]


def stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


package = stub("tec_tac")
package.__path__ = []
stub("tec_tac.module_repository", online_catalog=online_catalog)
stub("tec_tac.notices", system_notice_recipients=system_notice_recipients, publish_system_notice=publish_system_notice)
stub("tec_tac.audit", record=record, service_audit_actor=service_audit_actor)
stub("tec_tac.safe_files", atomic_json=atomic_json)
stub("tec_tac.module_state", version_satisfies=state_ns["version_satisfies"])
stub("tec_tac.caller_identity", calling_module_for_core_provider=calling_module_for_core_provider)
PLUGINS: list = []
stub("tec_tac.registry", discover_plugins=lambda: list(PLUGINS))
stub("tec_tac.module_category", effective_category=lambda declared: str(declared or "").strip().lower() or "test")

spec = importlib.util.spec_from_file_location("tec_tac.module_updates", PKG / "module_updates.py")
mu = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.module_updates"] = mu
spec.loader.exec_module(mu)
mu.logger.disabled = True  # the expected warnings of the failure cases below

WORK = Path(tempfile.mkdtemp(prefix="module-updates-"))
mu.STATE_ROOT = WORK
mu.STATE_FILE = WORK / "update-notices.json"
mu.STATE_LOCK = WORK / "update-notices.lock"
mu._state_lock = contextlib.nullcontext  # fcntl is POSIX only; the lock itself is the same pattern as the repository configuration lock


def reset():
    NOTICES.clear()
    PUBLISH_CALLS.clear()
    RECIPIENT_CALLS.clear()
    AUDIT_ROWS.clear()
    FAIL_PUBLISH["on"] = False
    if mu.STATE_FILE.exists():
        mu.STATE_FILE.unlink()
    mu._invalidate_list_cache()


def repo(repo_id, status="ok", **sync):
    return {"id": repo_id, "name": repo_id, "enabled": True, "sync": {"status": status, "retired": False, "credentials_rejected": False, **sync}}


def module(module_id, installed, latest, *, repo_id="official", problems=(), source_conflict=False, update=True, notes=None):
    return {
        "id": module_id, "name": module_id.title(), "installed": installed is not None, "installed_version": installed,
        "latest_version": latest, "selected_repository_id": repo_id, "selected_repository_name": "Official",
        "update_available": update, "compatibility": {"compatible": not problems, "problems": list(problems)},
        "source_conflict": source_conflict, "channel": "stable",
        "releases": [{"repository_id": repo_id, "version": latest, "release_notes_url": notes}],
    }


def catalog(modules, repos=None):
    return {"modules": modules, "repositories": repos if repos is not None else [repo("official")],
            "availability": {"state": "ready", "message": ""}}


# ------------------------------------------------------------------------------------------------------------------------ 1. level
for old, new, level in [
    ("1.2.3", "1.2.4", "patch"), ("1.2.3", "1.3.0", "minor"), ("1.2.3", "2.0.0", "major"), ("0.9.9", "0.10.0", "minor"),
    ("1.2.3", "1.2.10", "patch"), ("1.2.3", "1.2.4-rc1", "other"), ("1.2.3", "1.2.4-2", "other"), ("1.2.3-1", "1.2.4", "other"),
    ("1.2.3", "1.2.4+build", "other"), ("1.2", "1.3.0", "other"), ("1.2.3", "01.2.4", "other"), ("1.2.3", "1.2.3", "other"),
    ("1.2.3", "1.2.2", "other"), ("abc", "1.0.0", "other"), (None, "1.0.0", "other"), ("1.2.3", "", "other"),
]:
    must(mu.update_level(old, new) == level, f"level {old} -> {new} should be {level}, got {mu.update_level(old, new)}")

# ------------------------------------------------------------------------------------------------------- 2. detection and reasons
CATALOG["value"] = catalog([
    module("alpha", "1.0.0", "1.0.1"),
    module("beta", "1.0.0", "2.0.0", problems=[{"type": "runtime", "component": "framework", "constraint": ">=1.18.0", "current": "1.17.104"}]),
    module("gamma", "1.0.0", "1.1.0", problems=[{"type": "dependency", "dependency": "delta", "constraint": ">=1.0.0", "installed_version": None},
                                                 {"type": "dependency", "dependency": "eps\x07ilon", "constraint": ">=2.0.0", "installed_version": "1.0.0"}]),
    module("zeta", "1.0.0", "1.0.1-rc1", source_conflict=True),
    module("eta", None, "1.0.0"),  # not installed: not an update
    module("theta", "1.0.0", "1.0.0", update=False),  # up to date
])
rows = mu.updates_from_catalog(CATALOG["value"], {"official"})
by_id = {row["module_id"]: row for row in rows}
must(sorted(by_id) == ["alpha", "beta", "gamma", "zeta"], f"rows {sorted(by_id)}")
must(by_id["alpha"]["installable"] and by_id["alpha"]["level"] == "patch" and by_id["alpha"]["blocked_reason"] is None, "alpha")
must([r["code"] for r in by_id["beta"]["blocked_reasons"]] == ["core_required"] and "1.18.0" in by_id["beta"]["blocked_reason"], "beta")
must(not by_id["beta"]["installable"] and by_id["beta"]["level"] == "major", "beta level")
must([r["code"] for r in by_id["gamma"]["blocked_reasons"]] == ["dependency_missing", "dependency_update"], "gamma codes")
must("\x07" not in json.dumps(by_id["gamma"]), "control characters from an index are removed")
must(by_id["zeta"]["level"] == "other" and by_id["zeta"]["blocked_reasons"][0]["code"] == "source_changed", "zeta")
must(all(row["source_current"] is True for row in rows), "source_current")

# ------------------------------------------------------------------------------------------- 3. notify once, superusers, audit
reset()
report = mu.detect_and_notify("manual-sync")
must(report["new"] == 4 and report["updates"] == 4 and report["error"] is None, f"first run {report}")
must(RECIPIENT_CALLS and all(call == () for call in RECIPIENT_CALLS), "recipients are the superusers only: no usernames are added")
must(all(call["recipients"] == SUPERUSERS for call in PUBLISH_CALLS), "every notice goes to the superusers")
must(all(call["source"] == "core" and call["level"] == "info" and call["title"] == "Module update available" for call in PUBLISH_CALLS), "notice fields")
must(any("from 1.0.0 to 1.0.1 (patch)" in call["message"] for call in PUBLISH_CALLS), "notice text")
must(any("cannot be installed yet" in call["message"] for call in PUBLISH_CALLS), "blocked reason in the notice")
must(len(AUDIT_ROWS) == 4, f"one audit row per detection, got {len(AUDIT_ROWS)}")
row = AUDIT_ROWS[0]
must(row["action"] == "custom:update-detected" and row["object_type"] == "module_update" and row["module_id"] == "core", "audit row")
must(row["actor"] == ("service", "core", "module-updates", "system (module update detection)"), f"actor {row['actor']}")
must(row["after"]["notified_users"] == 2 and row["after"]["trigger"] == "manual-sync", "audit after")

first_publishes = len(PUBLISH_CALLS)
report = mu.detect_and_notify("daily-sync")
must(report["new"] == 0 and len(PUBLISH_CALLS) == first_publishes and len(AUDIT_ROWS) == 4, "a second run announces nothing")
NOTICES.clear()  # the person pressed Clear read
report = mu.detect_and_notify("daily-sync")
must(report["new"] == 0 and len(PUBLISH_CALLS) == first_publishes, "a cleared notice is never raised again")

CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.2")])
report = mu.detect_and_notify("manual-sync")
must(report["new"] == 1 and len(AUDIT_ROWS) == 5, "a newer version notifies again")
CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.1")])
report = mu.detect_and_notify("manual-sync")
must(report["new"] == 0 and len(AUDIT_ROWS) == 5, "an older version offered again is never announced")
must(mu.notice_client_id("alpha", "1.0.1") != mu.notice_client_id("alpha", "1.0.2"), "one notice key per version")
must(mu.is_new_version(None, "1.0.0") and not mu.is_new_version({"version": "1.0.0"}, "1.0.0"), "is_new_version")

# --------------------------------------------------------------------------------- 4. offline and refused licence: no notice
for label, repos in [
    ("offline (last sync failed, cache kept)", [repo("official", status="error")]),
    ("licence refused", [repo("official", status="error", licensing_state="licence_refused")]),
    ("licensing not ok", [repo("official", licensing_state="licence_expired")]),
    ("credentials refused", [repo("official", credentials_rejected=True)]),
    ("retired", [repo("official", retired=True)]),
    ("never synced", [repo("official", status="never")]),
]:
    reset()
    CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.1")], repos)
    report = mu.detect_and_notify("daily-sync")
    must(report["new"] == 0 and not PUBLISH_CALLS and not AUDIT_ROWS, f"{label}: nothing is announced ({report})")
    listed = mu.list_updates(fresh=True)
    must(listed["count"] == 1 and listed["updates"][0]["source_current"] is False, f"{label}: the cached list still shows it, not current")

# ------------------------------------------------------------------------------------------------- 5. failures never lose a version
reset()
CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.1")])
FAIL_PUBLISH["on"] = True
report = mu.detect_and_notify("manual-sync")
must(report["failed"] == 1 and report["new"] == 0 and not AUDIT_ROWS, "a failed notice writes no audit row and is not recorded")
FAIL_PUBLISH["on"] = False
report = mu.detect_and_notify("manual-sync")
must(report["new"] == 1 and len(AUDIT_ROWS) == 1, "the next run tries again")

reset()
mu.STATE_FILE.write_text("{not json", encoding="utf-8")
report = mu.detect_and_notify("manual-sync")
must(report["error"] == "record_rebuilt" and report["new"] == 0 and not PUBLISH_CALLS, "an unreadable record is rebuilt without a flood")
must(json.loads(mu.STATE_FILE.read_text(encoding="utf-8"))["notified"]["alpha"]["version"] == "1.0.1", "rebuilt record")
CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.2")])
must(mu.detect_and_notify("manual-sync")["new"] == 1, "after a rebuild a new version notifies")


def broken_catalog():
    raise RuntimeError("cache unreadable")


saved = sys.modules["tec_tac.module_repository"].online_catalog
sys.modules["tec_tac.module_repository"].online_catalog = broken_catalog
must(mu.detect_and_notify("manual-sync")["error"] == "catalogue_unavailable", "detection never raises")
sys.modules["tec_tac.module_repository"].online_catalog = saved
must(mu.detect_and_notify("bogus")["trigger"] == "manual-sync", "an unknown trigger is not stored")

# ---------------------------------------------------------------------------------------------- 6. read model, badge, contract
reset()
CATALOG["value"] = catalog([module("alpha", "1.0.0", "1.0.1", notes="https://example.test/notes/alpha-1.0.1.html"),
                            module("beta", "1.0.0", "2.0.0", problems=[{"type": "runtime", "component": "framework", "constraint": ">=9.0.0"}])])
listed = mu.list_updates(fresh=True)
must(listed["count"] == 2 and listed["installable_count"] == 1 and listed["levels"] == {"major": 1, "minor": 0, "patch": 1, "other": 0}, f"{listed}")
must(listed["updates"][0]["release_notes_url"] == "https://example.test/notes/alpha-1.0.1.html", "release notes link")
must(listed["contract"] == "core.module_updates 1.0.0", "contract label")
count = mu.update_count()
must(count == {"schema": 1, "count": 2, "installable_count": 1, "levels": listed["levels"]}, f"badge {count}")
PLUGINS[:] = [types.SimpleNamespace(plugin_id=pid, plugin_type="extension", legacy=False, category=cat)
              for pid, cat in (("notifications", "server"), ("wapm", "premium"), ("endpoints", "core"), ("nocat", ""))]


def refused(caller_id, reason):
    AUDIT_ROWS.clear()
    CALLER["value"] = None if caller_id is None else types.SimpleNamespace(module_id=caller_id, kind="module", module_version="1.0.0")
    try:
        mu.updates_for_module()
        raise AssertionError(f"{caller_id}: must be refused")
    except mu.ModuleUpdatesError as exc:
        must(exc.code == "caller_not_allowed" and exc.status == 403, f"{caller_id}: refusal code")
    must(len(AUDIT_ROWS) == 1 and AUDIT_ROWS[0]["action"] == "deny" and AUDIT_ROWS[0]["metadata"]["reason"] == reason, f"{caller_id}: one deny row {AUDIT_ROWS}")


refused(None, "unverified_caller")
refused("wapm", "category_not_allowed")       # a premium module
refused("endpoints", "category_not_allowed")  # a core module
refused("nocat", "category_not_allowed")      # no category = test
refused("ghost", "category_unknown")          # not an installed extension
must(AUDIT_ROWS[0]["metadata"]["category"] is None, "unknown category recorded as null")
AUDIT_ROWS.clear()
CALLER["value"] = types.SimpleNamespace(module_id="wapm", kind="module", module_version="1.0.0")
for _ in range(3):
    try:
        mu.updates_for_module()
    except mu.ModuleUpdatesError:
        pass
must(not AUDIT_ROWS, "repeated refusals of one caller are rate limited")
AUDIT_ROWS.clear()
CALLER["value"] = types.SimpleNamespace(module_id="notifications", kind="module", module_version="1.0.0")
must(mu.updates_for_module()["count"] == 2 and not AUDIT_ROWS, "a verified server module reads the list, with no deny row")
meta = mu.module_updates_contract_metadata()
must(meta["id"] == "core.module_updates" and meta["version"] == "1.0.0" and meta["operations"] == ["updates_for_module"], "metadata")

# ------------------------------------------------------------------------------------------------------ 7. route permission
class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


def require_module_manager(user):
    if not getattr(user, "can_manage", False):
        raise PermissionDenied("Tec-Tac core.privileged_operations permission is required.")


stub("drf_spectacular")
stub("drf_spectacular.utils", extend_schema=lambda **kw: (lambda obj: obj), extend_schema_view=lambda **kw: (lambda obj: obj))
stub("rest_framework")
stub("rest_framework.response", Response=Response)
stub("rest_framework.views", APIView=type("APIView", (), {}))
stub("tec_tac.session_security", SessionAuthenticated=object)
stub("tec_tac.views", _require_module_manager=require_module_manager)
vspec = importlib.util.spec_from_file_location("tec_tac.module_update_views", PKG / "module_update_views.py")
views = importlib.util.module_from_spec(vspec)
sys.modules["tec_tac.module_update_views"] = views
vspec.loader.exec_module(views)
for view_class in (views.ModuleUpdateListView, views.ModuleUpdateCountView):
    request = types.SimpleNamespace(user=types.SimpleNamespace(can_manage=False))
    try:
        view_class().get(request)
        raise AssertionError(f"{view_class.__name__}: a person without module-manage must be refused")
    except PermissionDenied:
        pass
    answer = view_class().get(types.SimpleNamespace(user=types.SimpleNamespace(can_manage=True)))
    must(answer.status_code == 200 and answer.data["count"] == 2, f"{view_class.__name__} for a manager")
sys.modules["tec_tac.module_repository"].online_catalog = broken_catalog
mu._invalidate_list_cache()
answer = views.ModuleUpdateListView().get(types.SimpleNamespace(user=types.SimpleNamespace(can_manage=True)))
must(answer.status_code == 503 and "cache" not in json.dumps(answer.data), "an unreadable catalogue is a plain 503")
sys.modules["tec_tac.module_repository"].online_catalog = saved

# ------------------------------------------------------------------------------- 8. wiring: no detection in a request thread
REPO_VIEWS = ast.parse((PKG / "module_repository_views.py").read_text(encoding="utf-8"))


def calls_in(tree, class_name, method="post"):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method:
                    return {n.func.id for n in ast.walk(item) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    raise AssertionError(f"{class_name}.{method} not found")


for name in ("ModuleRepositorySyncView", "ModuleRepositorySyncAllView"):
    called = calls_in(REPO_VIEWS, name)
    must("queue_detection" in called and "detect_and_notify" not in called, f"{name} only queues the check")
repo_source = (PKG / "module_repository.py").read_text(encoding="utf-8")
sync_fn = next(n for n in ast.parse(repo_source).body if isinstance(n, ast.FunctionDef) and n.name == "run_scheduled_sync")
must("detect_and_notify(trigger=\"daily-sync\")" in ast.get_source_segment(repo_source, sync_fn), "the daily sync runs the check")
tasks_source = (PKG / "tasks.py").read_text(encoding="utf-8")
must('name="tec_tac.detect_module_updates"' in tasks_source and "detect_and_notify(trigger=trigger)" in tasks_source, "Celery task")
urls_source = (PKG / "urls.py").read_text(encoding="utf-8")
must('path("modules/updates/", ModuleUpdateListView.as_view()' in urls_source and 'path("modules/updates/count/", ModuleUpdateCountView.as_view()' in urls_source, "routes")
must("register_core_module_updates_capability()" in (PKG / "apps.py").read_text(encoding="utf-8"), "capability registered")
must("detect_and_notify" not in (PKG / "module_update_views.py").read_text(encoding="utf-8"), "the read routes never detect")

# ------------------------------------------------------------------------------------------------ 9. the release notes link
REPO_TREE = ast.parse(repo_source)
rns: dict = {"re": re, "urllib": urllib, "__name__": "repo_extract"}


class ModuleRepositoryError(RuntimeError):
    pass


rns.update({"ModuleRepositoryError": ModuleRepositoryError, "ModuleStateError": state_ns["ModuleStateError"],
            "version_satisfies": state_ns["version_satisfies"], "_validate_remote_url": lambda url, trust="custom": url})
want = {"_CONTROL_CHARACTERS", "_validate_release", "_informational_text"}
picked = [n for n in REPO_TREE.body if (isinstance(n, ast.FunctionDef) and n.name in want)
          or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in want for t in n.targets))]
exec(compile(ast.Module(body=picked, type_ignores=[]), "module_repository.py", "exec"), rns)
base = {"id": "alpha", "version": "1.0.1", "download": "alpha.zip", "sha256": "a" * 64}
for notes, expected in [
    ("notes/alpha.html", "https://repo.test/idx/notes/alpha.html"),
    ("https://docs.test/a.html?token=x#top", None),  # 1.17.105: null, as the contract says (it was stripped before)
    ("http://docs.test/a.html", None), ("javascript:alert(1)", None), ("https://user:pw@docs.test/a", None),
    ("https://docs.test/\x00", None), ("https://[bad/", None), (12, None), ("x" * 501, None), (None, None),
]:
    got = rns["_validate_release"]({**base, "release_notes": notes}, "https://repo.test/idx/index.json")["release_notes_url"]
    must(got == expected, f"release notes {notes!r}: {got!r} != {expected!r}")

print("[TEST] PASS module updates 1.17.104")
