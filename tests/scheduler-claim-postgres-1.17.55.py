#!/usr/bin/env python3
"""PostgreSQL integration regression for the Scheduler run claim and the schedule delete view (1.17.55).

Run this on the dev server with the normal Django settings and database available (like the other *-postgres.py tests).
PostgreSQL refuses SELECT ... FOR UPDATE over the nullable side of an outer join; SQLite and stubs do not send FOR UPDATE, so only
this script can catch that. Everything runs inside one transaction that is rolled back at the end.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

import django

django.setup()

from django.db import connection, transaction
from django.utils import timezone
from tec_tac import tasks
from tec_tac.models import TecTacSchedule, TecTacScheduleRun

if connection.vendor != "postgresql":
    raise SystemExit(f"[TEST] PostgreSQL required for this integration regression; got {connection.vendor!r}")

failures = []


def step(name, func):
    try:
        func()
        print(f"[TEST] PASS: {name}")
    except Exception as exc:  # noqa: BLE001 - report every step
        failures.append(name)
        print(f"[TEST] FAIL: {name}: {type(exc).__name__}: {exc}")


class Rollback(Exception):
    pass


def make_schedule(**kw):
    return TecTacSchedule.objects.create(
        name=f"claim-probe-{uuid.uuid4().hex[:8]}", module_id="claim-probe", action_id="claim-probe.run",
        schedule_type=TecTacSchedule.ScheduleType.ONCE, run_at=timezone.now(), enabled=False, **kw,
    )


def make_run(schedule=None):
    return TecTacScheduleRun.objects.create(
        schedule=schedule, module_id="claim-probe", action_id="claim-probe.run", scheduled_for=timezone.now(),
        manual=True, status=TecTacScheduleRun.Status.QUEUED,
    )


def claim_qs():
    return TecTacScheduleRun.objects.select_for_update(of=("self",)).select_related("schedule")


def delete_qs():
    return TecTacSchedule.objects.select_for_update(of=("self",)).select_related("created_by", "updated_by")


def sql_text(qs):
    return str(qs.query)


try:
    with transaction.atomic():
        schedule = make_schedule()
        run_scheduled = make_run(schedule)
        run_orphan = make_run(None)

        def compiled_sql():
            sql, _ = claim_qs().filter(pk=run_scheduled.pk).query.sql_with_params()
            assert "FOR UPDATE OF" in sql, sql
            assert 'OF "tec_tac_tectacschedulerun"' in sql or "OF tec_tac_tectacschedulerun" in sql, sql
            assert "OF \"tec_tac_tectacschedule\"" not in sql and "OF tec_tac_tectacschedule," not in sql, sql
            sql2, _ = delete_qs().filter(pk=schedule.pk).query.sql_with_params()
            assert "FOR UPDATE OF" in sql2, sql2

        def claim_scheduled():
            assert claim_qs().get(pk=run_scheduled.pk).schedule.pk == schedule.pk

        def claim_orphan():
            assert claim_qs().get(pk=run_orphan.pk).schedule is None

        def delete_view_queryset():
            assert delete_qs().get(pk=schedule.pk).created_by is None

        def execute_probe():
            probe = SimpleNamespace(handler=lambda context: {"ok": True})
            original = tasks.get_scheduled_action
            tasks.get_scheduled_action = lambda action_id: probe
            try:
                out = tasks.execute_schedule_run.run(SimpleNamespace(request=SimpleNamespace(retries=0)), str(run_scheduled.pk))
            finally:
                tasks.get_scheduled_action = original
            run_scheduled.refresh_from_db()
            assert run_scheduled.status == TecTacScheduleRun.Status.SUCCEEDED, (out, run_scheduled.status, run_scheduled.error)
            again = tasks.execute_schedule_run.run(SimpleNamespace(request=SimpleNamespace(retries=0)), str(run_scheduled.pk))
            assert again == "run already succeeded", again

        step("compiled SQL locks only the run (and only the schedule in the delete view)", compiled_sql)
        step("claim queryset runs with a scheduled run", claim_scheduled)
        step("claim queryset runs with a schedule-less run (schedule NULL)", claim_orphan)
        step("delete-view queryset runs with created_by NULL", delete_view_queryset)
        step("execute_schedule_run claims, runs a probe action and refuses a second delivery", execute_probe)
        raise Rollback
except Rollback:
    pass

if failures:
    raise SystemExit(f"[TEST] FAIL: {len(failures)} step(s): {failures}")
print("[TEST] scheduler claim postgres 1.17.55: PASS")
