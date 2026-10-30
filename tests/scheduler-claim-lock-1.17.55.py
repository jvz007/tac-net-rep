#!/usr/bin/env python3
"""1.17.55 regression: the Scheduler run claim and the schedule delete view must not lock the nullable side of a join.

PostgreSQL refuses ``SELECT ... FOR UPDATE`` over a LEFT OUTER JOIN ("FOR UPDATE cannot be applied to the nullable side of an
outer join"). ``select_related`` on a nullable foreign key makes that join, so every ``select_for_update()`` that is combined
with ``select_related`` or ``prefetch_related`` must pass ``of=("self",)``. SQLite and stubs never send FOR UPDATE, which is why
earlier tests could not see it.

Covered: (1) the real ``execute_schedule_run`` claim against a stub queryset (of=("self",), select_related kept, claimed once,
schedule readable); (2) an ast scan of framwork/tec_tac for the unsafe pattern; (3) the delete view's queryset call.
The PostgreSQL check is tests/scheduler-claim-postgres-1.17.55.py (a dev-server script).
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"[TEST] ok: {msg}")


# ---- (1) the real claim in tasks.py against stubs
class Status:
    QUEUED = "queued"; RUNNING = "running"; FAILED = "failed"; SKIPPED = "skipped"; SUCCEEDED = "succeeded"


calls = []


class Run:
    Status = Status
    DoesNotExist = type("DoesNotExist", (Exception,), {})

    def __init__(self):
        self.pk = "run-1"; self.status = Status.QUEUED
        self.schedule = SimpleNamespace(id="s1", action_id="x.y", module_id="x", owner_module="", target_mode="snapshot")
        self.action_id = ""; self.module_id = ""; self.target_mode_snapshot = ""
        self.parameters_snapshot = {}; self.retry_count_snapshot = 0
        self.started_at = None; self.finished_at = None; self.attempt = 0; self.error = ""; self.error_type = ""
        self.owner_module = ""; self.owner_type = "user"  # 1.17.97: the worker reads them for its module guard
        self.saved = 0

    def save(self, **kw):
        self.saved += 1


RUN = Run()


class QS:
    def select_for_update(self, *a, **kw):
        calls.append(("select_for_update", a, kw)); return self

    def select_related(self, *a):
        calls.append(("select_related", a)); return self

    def get(self, pk):
        return RUN


Run.objects = QS()


class Stop(Exception):
    pass


def stub(name, **attrs):
    m = types.ModuleType(name); m.__dict__.update(attrs); sys.modules[name] = m; return m


pkg = stub("tec_tac"); pkg.__path__ = [str(APP)]
stub("django"); stub("django.db", transaction=SimpleNamespace(atomic=lambda: nullcontext()))
stub("django.utils", timezone=SimpleNamespace(now=lambda: "now"))
stub("tacticalrmm")
stub("tacticalrmm.celery", app=SimpleNamespace(task=lambda *a, **k: (lambda f: SimpleNamespace(run=f, __wrapped__=f))))
stub("tec_tac.models", TecTacScheduleRun=Run)
stub("tec_tac.scheduler_run_context", issue_run_context=lambda *a, **k: (_ for _ in ()).throw(Stop()))
stub("tec_tac.capabilities", capability_status=None, CapabilityDisabled=type("A", (Exception,), {}),
     CapabilityUnavailable=type("B", (Exception,), {}), CapabilityVersionMismatch=type("C", (Exception,), {}),
     CapabilityUnhealthy=type("D", (Exception,), {}))
stub("tec_tac.scheduler", SchedulerError=Exception, SchedulerPermanentError=Exception, SchedulerTransientError=Exception,
     _runtime_authorization_error=None, effective_retry_delay_seconds=None, get_scheduled_action=lambda *a: None,
     is_one_off_key=lambda k: False, _audit_schedule_row=lambda *a, **k: None, scheduled_person_action=lambda *a, **k: False, manual_person_action=lambda *a, **k: False,
     run_blocked_reason=lambda *a, **k: "")

spec = importlib.util.spec_from_file_location("tec_tac.tasks_claim_probe", APP / "tasks.py")
tasks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tasks)
claim = tasks.execute_schedule_run.run
self_task = SimpleNamespace(request=SimpleNamespace(retries=0))

try:
    claim(self_task, "run-1")
except (Stop, AttributeError, TypeError) as exc:
    # Past the claim: the stub stops the run at the context step. Later steps are not what this test checks.
    print(f"[TEST] note: stopped after the claim with {type(exc).__name__}")
sfu = [c for c in calls if c[0] == "select_for_update"]
must(sfu and sfu[0][2].get("of") == ("self",), 'the claim locks only the run row: of=("self",)')
must(("select_related", ("schedule",)) in calls, "select_related('schedule') is kept (no second query)")
must(RUN.status == Status.RUNNING and RUN.attempt == 1 and RUN.saved == 1, "a queued run is claimed once")
must(RUN.schedule.id == "s1", "run.schedule is readable after the claim")
must(claim(self_task, "run-1") == "run already running", "a second delivery is refused")

# ---- (2) ast scan: select_for_update with a join helper must pass of=
def chain_calls(node):
    names = []
    while isinstance(node, (ast.Call, ast.Attribute)):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                names.append((f.attr, node)); node = f.value
            else:
                break
        else:
            node = node.value
    return names


bad = []
for path in sorted(APP.glob("*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = chain_calls(node)
        attrs = {n for n, _ in chain}
        if "select_for_update" in attrs and attrs & {"select_related", "prefetch_related"}:
            sfu_call = next(c for n, c in chain if n == "select_for_update")
            if not any(k.arg == "of" for k in sfu_call.keywords):
                bad.append(f"{path.name}:{sfu_call.lineno}")
must(not bad, f"no select_for_update() joined with select_related/prefetch_related lacks of= ({sorted(set(bad))})")

# ---- (3) the delete view's queryset
views = (APP / "scheduler_views.py").read_text(encoding="utf-8")
must('TecTacSchedule.objects.select_for_update(of=("self",)).select_related("created_by", "updated_by")' in views,
     "the schedule delete view locks only the schedule row")
print("[TEST] scheduler claim lock 1.17.55: PASS")
