#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.97 regression, Scheduler (b): the schedules of a module that is no longer installed show as 'Owner module not installed' with Disable and Remove;
a removal is remembered so the module cannot bring the schedule back by itself.

The real scheduler.py and scheduler_views.py on the stub harness of tests/scheduler-views-monthly-1.17.89.py (Django and DRF are not needed).
Covered: the rows show with orphaned, owner_module_installed and the label; GET /scheduler/orphaned/; single and all-of-module Disable and Remove, each
with a strict audit row (ids and count); a non-manager gets 403; a module that is installed, or a registry that cannot be read, gets 409
owner_module_installed; a queued or running run gets 409 active_runs; a bulk call without confirm true is a 400; an out-of-scope row is skipped and
counted; an audit failure changes nothing (503); after Remove, reconcile_schedule without a person's request creates nothing and returns None,
removed_owned_schedule answers the marker, and a person's own save recreates the schedule and clears the marker; a schedule that was only disabled comes
back unchanged when the module is installed again. The tick never runs an orphan: tests/scheduler-module-hide-1.17.97.py."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

_here = Path(__file__).resolve().parent
_source = (_here / "scheduler-tactical-permission-1.17.17.py").read_text(encoding="utf-8")
_cut = _source.index("# ---- harness end")
exec(compile(_source[:_cut], str(_here / "scheduler-tactical-permission-1.17.17.py"), "exec"), globals())  # noqa: S102 - the shared test harness
H = globals()
(must, sched, sv, Schedule, Run, User, Granted, handler, reset, SimpleNamespace, sys, NotFound, PermissionDenied, AUDITS) = (
    H[k] for k in ("must", "sched", "sv", "Schedule", "Run", "User", "Granted", "handler", "reset", "SimpleNamespace", "sys", "NotFound", "PermissionDenied", "AUDITS"))

T0 = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.timezone.utc)
Schedule.defaults.update(month_week=None, month_weekday=None, created_by_username="", confirmed_by_username="", creation_scope={}, latest_status=None, updated_at=T0,
                         paused_reason="", schedule_type="interval", interval_seconds=60, interval_anchor_at=T0)
Schedule.save = lambda self, update_fields=None: self in Schedule.objects.rows or Schedule.objects.rows.append(self)
Schedule.delete = lambda self: Schedule.objects.rows.remove(self)
Schedule.created_by_id = property(lambda self: getattr(self.created_by, "id", None))
sv.scheduler_creation_scope = SimpleNamespace(capture=lambda user: {})
boss = User("boss", Granted(30, can_do_server_maint=True))
plain = User("plain", Granted(31))
alice = User("alice", Granted(32))

ENABLED = {"checks": True}
PLUGINS = ["checks"]
REGISTRY = {"fault": False}
sys.modules["tec_tac.module_state"].load_state = lambda: {"schema": 1, "modules": {m: {} for m in ENABLED}}
sys.modules["tec_tac.module_state"].is_enabled = lambda module_id, state=None: ENABLED.get(module_id, True)


def _plugins():
    if REGISTRY["fault"]:
        raise RuntimeError("registry unreadable")
    return tuple(SimpleNamespace(plugin_id=i, legacy=False, plugin_type="extension", permission_groups=()) for i in PLUGINS)


sys.modules["tec_tac.registry"].get_plugins = _plugins


class Q:
    def __init__(self, **kw):
        self.alternatives = [kw]

    def __or__(self, other):
        merged = Q()
        merged.alternatives = self.alternatives + other.alternatives
        return merged


class QS:
    def __init__(self, rows):
        self.rows = list(rows)

    def select_related(self, *a):
        return self

    def select_for_update(self, **k):
        return self

    def annotate(self, **k):
        return list(self.rows)

    def filter(self, *qs, **kw):
        alternatives = [a for q in qs for a in q.alternatives] if qs else [kw]
        return QS(r for r in self.rows if any(all(getattr(r, k) == v for k, v in alt.items()) for alt in alternatives))

    def first(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


Schedule.objects.select_related = lambda *a: QS(Schedule.objects.rows)
Schedule.objects.select_for_update = lambda **k: QS(Schedule.objects.rows)
sv.Q = Q


def _runs_of(schedule):
    return SimpleNamespace(filter=lambda **k: SimpleNamespace(count=lambda: len([r for r in Run.objects.rows if r.schedule is schedule and r.status in k["status__in"]])),
                           all=list, first=lambda: None)


Schedule.runs = property(_runs_of)
sv.TecTacScheduleRun = SimpleNamespace(Status=Run.Status, objects=SimpleNamespace(filter=lambda **k: SimpleNamespace(order_by=lambda *a: SimpleNamespace(values=lambda *a: [None]))))
sv.get_object_or_404 = lambda qs, pk: next((r for r in Schedule.objects.rows if str(r.pk) == str(pk)), None) or (_ for _ in ()).throw(NotFound("no schedule"))
sv.serialize_run = lambda run: {"id": run.id}


class RemovedRow(SimpleNamespace):
    pass


MARKERS: list = []


class _Markers:
    @staticmethod
    def filter(**lookup):
        rows = [m for m in MARKERS if all(getattr(m, k) == v for k, v in lookup.items())]
        return SimpleNamespace(first=lambda: rows[0] if rows else None, delete=lambda: [MARKERS.remove(m) for m in rows])

    @staticmethod
    def update_or_create(defaults=None, **lookup):
        found = _Markers.filter(**lookup).first()
        if found is None:
            MARKERS.append(RemovedRow(**lookup, **(defaults or {})))
            return MARKERS[-1], True
        found.__dict__.update(defaults or {})
        return found, False


sys.modules["tec_tac.models"].TecTacRemovedSchedule = SimpleNamespace(objects=_Markers)
for action_module in ("checks", "gone", "tec-tac"):
    sched.register_scheduled_action(id=f"{action_module}.probe", module_id=action_module, label="probe", handler=handler, target_types=("none",), permission=None)

SCOPE = {"deny": set()}  # names of schedules the manager's target scope does not cover
sv._can_access_target_scope = lambda user, targets, **kw: (targets or {}).get("name") not in SCOPE["deny"]
AUDIT_FAIL = {"on": False}
_audit_record = sys.modules["tec_tac.audit"].record


def _record(**kw):
    if AUDIT_FAIL["on"] and kw.get("strict"):
        raise RuntimeError("audit store down")
    return _audit_record(**kw)


sys.modules["tec_tac.audit"].record = _record


def make(mid, key, *, enabled=True, owner="module", name=None):
    return Schedule.objects.create(name=key, module_id=mid, action_id=f"{mid}.probe", owner_type=owner, owner_module=mid if owner == "module" else "",
                                   owner_key=key if owner == "module" else "", enabled=enabled, targets={"type": "none", "name": name or key}, created_at=T0)


def fresh():
    reset()
    del MARKERS[:], AUDITS[:]
    ENABLED.clear()
    ENABLED["checks"] = True
    PLUGINS[:] = ["checks"]
    REGISTRY["fault"] = False
    SCOPE["deny"] = set()
    AUDIT_FAIL["on"] = False


def req(user=boss, **body):
    return SimpleNamespace(user=user, data=body, query_params={})


def call(view, method, request, **kw):
    try:
        return getattr(view(), method)(request, **kw)
    except (PermissionDenied, NotFound) as exc:
        return SimpleNamespace(status_code=403 if isinstance(exc, PermissionDenied) else 404, data={"detail": str(exc)})


def single(mode, schedule, user=boss):
    if mode == "disable":
        return call(sv.SchedulerOrphanedDisableView, "post", req(user), schedule_id=str(schedule.pk))
    return call(sv.SchedulerOrphanedRemoveView, "delete", req(user), schedule_id=str(schedule.pk))


def bulk(mode, module_id, user=boss, **body):
    if mode == "disable":
        return call(sv.SchedulerOrphanedModuleDisableView, "post", req(user, **body), module_id=module_id)
    return call(sv.SchedulerOrphanedModuleRemoveView, "delete", req(user, **body), module_id=module_id)


def orphan_rows():
    return [a for a in AUDITS if (a.get("metadata") or {}).get("orphaned") is True]


# (1) uninstalled: the rows show as orphaned and the manager reads them grouped by module
fresh()
g1, g2, u1 = make("gone", "k1"), make("gone", "k2", enabled=False), make("gone", "", owner="user", name="u1")
ok = make("checks", "c1")
listing = sv.SchedulerListView().get(SimpleNamespace(user=boss, query_params={}))
rows = {r["name"]: r for r in listing.data["schedules"]}
must({"k1", "k2", ""} <= set(rows) and "c1" in rows, list(rows))
must(all(rows[n]["orphaned"] and rows[n]["owner_module_installed"] is False and rows[n]["orphan_label"] == "Owner module not installed" for n in ("k1", "k2", "")), rows)
must(rows["c1"]["orphaned"] is False and rows["c1"]["owner_module_installed"] is True and rows["c1"]["orphan_label"] is None, "an installed module's schedule is not an orphan")
must(g1.paused_reason == "paused: owner module not installed" and rows["k1"]["paused"] is True and rows["k1"]["next_run_at"] is None, "paused by Core, never run")
must(g2.paused_reason == "" and g2.enabled is False, "a person-disabled orphan stays off, nothing written")
overview = call(sv.SchedulerOrphanedListView, "get", req()).data
must(overview["count"] == 1 and overview["modules"][0]["module_id"] == "gone" and overview["modules"][0]["count"] == 3 and overview["modules"][0]["enabled_count"] == 2, overview)
must(overview["registry_unreadable"] is False and overview["out_of_scope"] == 0, overview)
print("       an uninstalled module's schedules are listed as orphaned with the label; GET scheduler/orphaned/ groups them")

# (2) every route needs the Scheduler manager right
fresh()
g1 = make("gone", "k1")
for reply in (call(sv.SchedulerOrphanedListView, "get", req(plain)), single("disable", g1, plain), single("remove", g1, plain), bulk("disable", "gone", plain, confirm=True), bulk("remove", "gone", plain, confirm=True)):
    must(reply.status_code == 403, reply.data)
must(g1.enabled is True and not orphan_rows() and Schedule.objects.rows == [g1], "nothing changed")
print("       a non-manager gets 403 from all five routes; nothing changes")

# (3) a module that is installed (or a registry that cannot be read) is 409 owner_module_installed, nothing offered
fresh()
c1 = make("checks", "c1")
for reply in (single("disable", c1), single("remove", c1), bulk("disable", "checks", confirm=True), bulk("remove", "checks", confirm=True)):
    must(reply.status_code == 409 and reply.data["code"] == "owner_module_installed", reply.data)
g1 = make("gone", "k1")
REGISTRY["fault"] = True
for reply in (single("disable", g1), single("remove", g1), bulk("remove", "gone", confirm=True)):
    must(reply.status_code == 409 and reply.data["code"] == "owner_module_installed", ("an unreadable registry offers nothing destructive", reply.data))
overview = call(sv.SchedulerOrphanedListView, "get", req()).data
must(overview["modules"] == [] and overview["registry_unreadable"] is True, overview)
must(Schedule.objects.rows == [c1, g1] and not MARKERS and not orphan_rows(), "nothing changed")
print("       an installed module, or an unreadable registry, answers 409 owner_module_installed; nothing destructive is offered")

# (4) single Disable and Remove, audited with ids; Remove of a module-owned schedule is remembered, of a user's schedule is not
fresh()
g1, g2, u1 = make("gone", "k1"), make("gone", "k2"), make("gone", "", owner="user", name="u1")
reply = single("disable", g1)
must(reply.status_code == 200 and g1.enabled is False and reply.data["count"] == 1, reply.data)
row = orphan_rows()[-1]
must(row["action"] == "disable" and row["strict"] is True and row["object_id"] == str(g1.pk), row)
must(row["metadata"]["owner_module"] == "gone" and row["metadata"]["owner_key"] == "k1" and row["metadata"]["count"] == 1, row["metadata"])
must(not MARKERS, "Disable is not a removal")
reply = single("remove", g2)
must(reply.status_code == 200 and g2 not in Schedule.objects.rows, reply.data)
row = orphan_rows()[-1]
must(row["action"] == "delete" and row["strict"] is True and row["object_id"] == str(g2.pk) and row["before"]["name"] == "k2", row)
must(len(MARKERS) == 1 and (MARKERS[0].owner_module, MARKERS[0].owner_key, MARKERS[0].removed_by_username) == ("gone", "k2", "boss"), MARKERS)
reply = single("remove", u1)
must(reply.status_code == 200 and u1 not in Schedule.objects.rows and len(MARKERS) == 1, "a user's schedule has no owner key: no marker")
print("       single Disable and Remove: strict audit row with module, key and id; only a module-owned Remove is remembered")

# (5) a queued or running run is 409 active_runs, with no force
fresh()
g1 = make("gone", "k1")
Run.objects.create(schedule=g1, status="running")
for reply in (single("disable", g1), single("remove", g1)):
    must(reply.status_code == 409 and reply.data["code"] == "active_runs" and reply.data["active_runs"] == 1, reply.data)
sv_req = req()
sv_req.query_params = {"force": "true"}
must(call(sv.SchedulerOrphanedRemoveView, "delete", sv_req, schedule_id=str(g1.pk)).status_code == 409, "force is not an option")
must(g1 in Schedule.objects.rows and g1.enabled is True and not orphan_rows() and not MARKERS, "nothing changed")
Run.objects.rows[:] = []
Run.objects.create(schedule=g1, status="queued")
g2 = make("gone", "k2")
reply = bulk("disable", "gone", confirm=True)
must(reply.status_code == 409 and reply.data["active_runs"] == 1 and g2.enabled is True and g1.enabled is True, ("one busy schedule stops the whole bulk call", reply.data))
print("       a queued or running run: 409 active_runs for one schedule and for a bulk call, nothing changes, no force")

# (6) all-of-module Disable and Remove: confirm is required; one strict row with the count; out-of-scope rows are skipped and counted
fresh()
g1, g2, g3 = make("gone", "k1"), make("gone", "k2", enabled=False), make("gone", "k3")
other = make("other", "o1")
for reply in (bulk("disable", "gone"), bulk("remove", "gone"), bulk("disable", "gone", confirm="yes"), bulk("remove", "gone", confirm=1)):
    must(reply.status_code == 400 and reply.data["code"] == "confirmation_required", reply.data)
must(g1.enabled and g3.enabled and len(Schedule.objects.rows) == 4 and not orphan_rows(), "no confirm, no change")
SCOPE["deny"] = {"k3"}
reply = bulk("disable", "gone", confirm=True)
must(reply.status_code == 200 and reply.data["count"] == 1 and reply.data["skipped_out_of_scope"] == 1, reply.data)
must(g1.enabled is False and g3.enabled is True, "the out-of-scope row was skipped")
row = orphan_rows()[-1]
must(row["action"] == "disable" and row["object_type"] == "scheduler_module" and row["object_id"] == "gone" and row["strict"] is True, row)
must(row["metadata"]["count"] == 1 and row["metadata"]["skipped_out_of_scope"] == 1 and row["metadata"]["schedule_ids"] == [str(g1.pk)], row["metadata"])
SCOPE["deny"] = set()
reply = bulk("remove", "gone", confirm=True)
must(reply.status_code == 200 and reply.data["count"] == 3 and Schedule.objects.rows == [other], reply.data)
must(sorted(m.owner_key for m in MARKERS) == ["k1", "k2", "k3"], "every module-owned removal is remembered")
row = orphan_rows()[-1]
must(row["action"] == "delete" and row["metadata"]["count"] == 3, row["metadata"])
must(bulk("remove", "gone", confirm=True).status_code == 404, "nothing left to remove")
print("       all-of-module: confirm true required; one audit row with count and ids; an out-of-scope row is skipped and counted; every removal remembered")

# (7) an audit failure changes nothing
fresh()
g1 = make("gone", "k1")
AUDIT_FAIL["on"] = True
for reply in (single("disable", g1), single("remove", g1), bulk("remove", "gone", confirm=True)):
    must(reply.status_code == 503 and reply.data["code"] == "audit_unavailable", reply.data)
must(g1 in Schedule.objects.rows and g1.enabled is True and not MARKERS, "the strict audit row comes first: nothing was changed")
print("       a strict audit row that cannot be written: 503 and nothing changes")

# (8) the marker: reconcile_schedule without a person creates nothing; removed_owned_schedule says why; a person's own save brings it back
fresh()
sched._verified_person = lambda request: request.user
sched._check_person_may_schedule = lambda *a, **k: None
sched._system_action_creation = lambda *a, **k: None
sched._canonicalize_targets_for_person = lambda person, targets: targets
sched._owner_differs = lambda existing, person: False
sched._person_covers_targets = lambda *a, **k: True
creation_scope = sys.modules["tec_tac.scheduler_creation_scope"]
creation_scope.capture = lambda person: {}
sched.scheduler_creation_scope = creation_scope
PLUGINS.append("gone")  # the module is installed, registers its action and reconciles
KW = dict(owner_module="gone", owner_key="profile:1", action_id="gone.probe", schedule_type="interval", interval_seconds=3600, interval_anchor_at=T0, targets={"type": "none"})
first = sched.reconcile_schedule(**KW)
must(first is not None and first.owner_key == "profile:1", "created as before")
PLUGINS.remove("gone")  # uninstalled
reply = single("remove", first)
must(reply.status_code == 200 and not Schedule.objects.rows, reply.data)
PLUGINS.append("gone")  # installed again: the module reconciles on start
must(sched.removed_owned_schedule("gone", "profile:1")["removed_by_administrator"] is True, "the module can read why")
info = sched.removed_owned_schedule("gone", "profile:1")
must(info["removed_by_username"] == "boss" and info["removed_at"], info)
must(sched.reconcile_schedule(**KW) is None and not Schedule.objects.rows, "reconcile without a request creates nothing and returns None")
must(sched.reconcile_schedule(**KW) is None and not Schedule.objects.rows, "and again, on every start")
must(sched.reconcile_schedule(**{**KW, "enabled": False}) is None, "enabled=False answers None, as it always did when none exists")
must(sched.removed_owned_schedule("gone", "profile:2") is None, "another key is not removed")
second = sched.reconcile_schedule(**{**KW, "owner_key": "profile:2"})
must(second is not None, "an unremoved key still reconciles")
person = SimpleNamespace(user=alice)
back = sched.reconcile_schedule(**KW, confirmed_by_request=person)
must(back is not None and back.owner_key == "profile:1" and back.created_by is alice, "a person's own save recreates it")
must(sched.removed_owned_schedule("gone", "profile:1") is None and not MARKERS, "and clears the marker")
# the module itself removing or disabling clears a marker too
sched._removed_marker_model().objects.update_or_create(owner_module="gone", owner_key="x", defaults={"removed_by_username": "boss"})
must(sched.disable_owned_schedule(owner_module="gone", owner_key="x") is None and sched.removed_owned_schedule("gone", "x") is None, "disable_owned_schedule clears the marker")
sched._removed_marker_model().objects.update_or_create(owner_module="gone", owner_key="y", defaults={"removed_by_username": "boss"})
must(sched.remove_owned_schedule(owner_module="gone", owner_key="y") is False and sched.removed_owned_schedule("gone", "y") is None, "remove_owned_schedule clears the marker")
print("       Remove is remembered: reconcile_schedule without a request creates nothing (None), removed_owned_schedule answers, a person's save recreates it")

# (9) only disabled, then installed again: the schedule returns exactly as it was
fresh()
PLUGINS.append("gone")
keep = make("gone", "k1")
off = make("gone", "k2", enabled=False)
PLUGINS.remove("gone")
sv.SchedulerListView().get(SimpleNamespace(user=boss, query_params={}))
must(keep.paused_reason == "paused: owner module not installed", "paused while the module is gone")
single("disable", keep)
before = {s.pk: (s.enabled, s.updated_at) for s in Schedule.objects.rows}
PLUGINS.append("gone")
sched.sync_module_schedule_state()
must(keep.paused_reason == "" and off.paused_reason == "" and {s.pk: (s.enabled, s.updated_at) for s in Schedule.objects.rows} == before, "reinstalled: the reason is cleared, enabled and updated_at as they were")
rows = [a for a in AUDITS if a.get("object_type") == "scheduler_module" and a["action"] == "enable"]
must(len(rows) == 1 and rows[0]["metadata"]["count"] == 1 and rows[0]["object_id"] == "gone", ("one resume row for the one schedule Core had paused", rows))
print("       a schedule that was only disabled returns unchanged when the module is installed again")

# (10) text checks: routes, no force, the five routes exist
urls = (APP / "urls.py").read_text(encoding="utf-8")
for route in ('"scheduler/orphaned/"', '"scheduler/orphaned/<uuid:schedule_id>/disable/"', '"scheduler/orphaned/<uuid:schedule_id>/"',
              '"scheduler/orphaned/modules/<str:module_id>/disable/"', '"scheduler/orphaned/modules/<str:module_id>/"'):
    must(route in urls, route)
must("0042_clear_monthly_fields_non_monthly" in (APP / "migrations" / "0043_removed_schedule_marker.py").read_text(encoding="utf-8"), "the migration follows 0042")
must("TecTacRemovedSchedule" in (APP / "models.py").read_text(encoding="utf-8"), "the model exists")
print("[TEST] PASS scheduler orphaned 1.17.97")
