"""Install several licensed modules in one server-side run (Core 1.18.20, requests R1b to R1d).

The run installs what ``module_install_plan`` plans, one module at a time, through the two calls the single online install already uses:
``module_repository.stage_repository_package`` (strict start audit row, licence grant, SHA-256, publisher signature, identity check) and
``module_manager_v2.queue_v2_install`` (trust, licence, dependency, compatibility, replacement and disabled-install rules, then the helper job).
This file repeats none of those rules. It never removes, uninstalls, enables or disables a module and it never confirms a replacement or a
licence override: a module that needs one fails with Core's own sentence.

Why short ticks and a file: the module helper restarts Tactical's Celery and reloads uwsgi during an install, so neither a request thread nor
one long task can wait for a job. Each tick (``advance_run``) reads the run file under a lock, moves it one step and ends. The Celery task
queues the next tick three seconds later. If the chain dies, the progress route queues a tick again; a run with no heartbeat for 15 minutes
and no active job is closed as interrupted, so a lost worker never blocks new runs.

The pure part takes an ``env`` of collaborators, so it runs without Django. ``live_env()`` wires the real ones with lazy imports.
"""
from __future__ import annotations

import contextlib
import logging
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from . import module_install_plan

logger = logging.getLogger(__name__)

MAX_RUNS_KEPT = 20
STALE_TICK_SECONDS = 30
INTERRUPT_SECONDS = 900
JOB_MISSING_TICKS = 20
TICK_DELAY_SECONDS = 3
ACTIVE_JOB_STATES = ("queued", "dispatched", "running")
FAILED_JOB_STATES = ("failed", "dispatch_failed")
FINAL_STATUSES = ("completed", "stopped", "interrupted")
FORBIDDEN_FIELDS = ("licence_override_reason", "license_override_reason", "disable_replaced")

TEXT = {
    "stopped": "The run was stopped before this module started.",
    "interrupted": "The run was interrupted before this module started.",
    "dependency_failed": "A module it needs did not install",
    "version_changed": "The licence plan now offers a different version of this module. Plan again.",
    "allowed_unavailable": "Core could not read the licence plan, so this module was not installed.",
    "download_interrupted": "The download was interrupted. Install it again.",
    "job_unreadable": "The install job record could not be read. Check the job history.",
    "job_failed": "The install job failed.",
    "unexpected": "Core could not install this module. The Core log has the details.",
    "no_repository": "Core has no enabled licensing repository with this release. Sync the repository, then plan again.",
}


class AuditNotSaved(RuntimeError):
    """The strict start row could not be written, so no run was created."""


def _iso(stamp) -> str | None:
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if stamp else None


def _cut(value: Any, limit: int = 400) -> str:
    return " ".join(str(value or "").split())[:limit]


def is_final(run: dict) -> bool:
    return run.get("status") in FINAL_STATUSES


def refused_fields(data) -> list[str]:
    """The body fields a batch run never accepts (a licence override or a confirmed replacement disable are per-person confirmations)."""
    return [name for name in FORBIDDEN_FIELDS if hasattr(data, "get") and name in data]


# ------------------------------------------------------------------------------------------------------------------ run record


def _module_record(item: dict, *, planned: bool, state: str, code: str | None = None, reason: str | None = None) -> dict:
    return {"id": item["id"], "name": item.get("name") or item["id"], "version": item.get("version"), "action": item.get("action") or "install",
            "state": state, "code": code, "reason": reason, "planned": planned, "dependencies": sorted((item.get("dependencies") or {}).keys()),
            "job_id": None, "upload_id": None, "started_at": None, "ended_at": None, "job_missing": 0}


def new_run(env, plan: dict, selection: list[str], username: str) -> dict:
    modules = []
    for blocked in plan.get("blocked") or []:
        modules.append(_module_record({"id": blocked["id"]}, planned=False, state="skipped", code=blocked.get("code"), reason=_cut(blocked.get("message"))))
    for item in plan.get("order") or []:
        modules.append(_module_record(item, planned=True, state="pending"))
    now = env.now()
    return {"run_id": str(uuid.uuid4()), "status": "running", "started_by": username, "started_at": now, "finished_at": None, "heartbeat": now,
            "stop_requested": False, "end_audited": False, "requested": list(selection), "modules": modules}


def public_run(env, run: dict) -> dict:
    """The progress body. Core's words only: no log tail, hash, URL, publisher or key id."""
    counts = {state: 0 for state in ("pending", "downloading", "installing", "succeeded", "failed", "skipped")}
    modules = []
    for m in run["modules"]:
        counts[m["state"]] = counts.get(m["state"], 0) + 1
        job = env.job_status(m["job_id"]) if m.get("job_id") and m["state"] == "installing" else None
        modules.append({"id": m["id"], "name": m["name"], "version": m["version"], "action": m["action"], "state": m["state"],
                        "reason": {"code": m["code"], "message": m["reason"]} if m.get("code") or m.get("reason") else None, "job_id": m["job_id"],
                        "job_status": (job or {}).get("status"), "job_stage": (job or {}).get("stage"),
                        "started_at": _iso(m["started_at"]), "ended_at": _iso(m["ended_at"])})
    return {"ok": True, "run_id": run["run_id"], "status": run["status"], "started_by": run["started_by"], "started_at": _iso(run["started_at"]),
            "finished_at": _iso(run["finished_at"]), "stop_requested": bool(run["stop_requested"]), "counts": {**counts, "total": len(run["modules"])},
            "modules": modules}


def _find_active(env):
    for run_id in env.ids():
        run = env.load(run_id)
        if run is not None and not is_final(run):
            return run
    return None


def _prune(env) -> None:
    runs = [r for r in (env.load(i) for i in env.ids()) if r is not None]
    runs.sort(key=lambda r: r["started_at"], reverse=True)
    for old in runs[MAX_RUNS_KEPT:]:
        if is_final(old):
            env.forget(old["run_id"])


@contextlib.contextmanager
def _locked(env, run_id, wait=0.0):
    """Yield True when the run lock was taken within ``wait`` seconds, else False."""
    deadline = time.monotonic() + wait
    while True:
        with env.lock(run_id) as got:
            if got or time.monotonic() >= deadline:
                yield got
                return
        time.sleep(0.05)


def _lock_held(env, run_id) -> bool:
    """True when a tick holds the run lock right now (a download in flight): its holder queues the next tick, so nothing is added."""
    with env.lock(run_id) as got:
        return not got


# ------------------------------------------------------------------------------------------------------------------ audit rows


def _outcome(env, run, m) -> None:
    env.audit(run, "outcome", f"Module {m['id']} {m['state']}", {"module": m["id"], "version": m["version"], "state": m["state"], "job_id": m["job_id"],
                                                                "code": m["code"], "reason": m["reason"]})


def _conclude(env, run, m, state, code=None, reason=None) -> None:
    m.update(state=state, code=code, reason=_cut(reason) if reason else None, ended_at=env.now())
    env.save(run)
    _outcome(env, run, m)


def _finish(env, run, status) -> None:
    if is_final(run):
        return
    run["status"], run["finished_at"] = status, env.now()
    already = run.get("end_audited")
    run["end_audited"] = True  # at most once: the flag is saved before the row is written
    env.save(run)
    if not already:
        counts = {}
        for m in run["modules"]:
            counts[m["state"]] = counts.get(m["state"], 0) + 1
        env.audit(run, "end", f"Module install run {status}", {"status": status, "counts": counts, "started_by": run["started_by"]})


def _skip_pending(env, run, code, text) -> None:
    for m in run["modules"]:
        if m["state"] == "pending":
            _conclude(env, run, m, "skipped", code, text)


# ------------------------------------------------------------------------------------------------------------------ the tick


def _cascade(env, run) -> None:
    """Skip every pending module whose hard dependency (planned in this run) failed or was skipped."""
    changed = True
    while changed:
        changed = False
        broken = {m["id"] for m in run["modules"] if m["planned"] and m["state"] in ("failed", "skipped")}
        for m in run["modules"]:
            if m["state"] == "pending" and (set(m["dependencies"]) & broken):
                needed = min(set(m["dependencies"]) & broken)
                _conclude(env, run, m, "skipped", "dependency_failed", f"{TEXT['dependency_failed']} ({needed}).")
                changed = True


def _settle_installing(env, run) -> bool:
    """Reconcile a module whose job is running or finished. True while a job is still in flight."""
    flying = False
    for m in run["modules"]:
        if m["state"] != "installing":
            continue
        job = env.job_status(m["job_id"])
        status = (job or {}).get("status")
        if job is None:
            m["job_missing"] = m.get("job_missing", 0) + 1
            if m["job_missing"] >= JOB_MISSING_TICKS:
                _conclude(env, run, m, "failed", "job_unreadable", TEXT["job_unreadable"])
            else:
                flying = True
        elif status == "succeeded":
            _conclude(env, run, m, "succeeded")
        elif status in FAILED_JOB_STATES:
            _conclude(env, run, m, "failed", "job_failed", job.get("error") or TEXT["job_failed"])
        else:
            m["job_missing"] = 0
            flying = True
    return flying


def _recheck(allowed_body: dict, m: dict):
    """(code, sentence) when the module must not be staged now, else None."""
    if allowed_body.get("state") != "ok":
        return "allowed_unavailable", TEXT["allowed_unavailable"]
    row = next((r for r in allowed_body.get("modules") or [] if r.get("id") == m["id"]), None)
    if row is None or not row.get("selected"):
        return "not_selected", module_install_plan.TEXT["not_selected"]
    release = row.get("release")
    if not release:
        return "no_release", module_install_plan.TEXT["no_release"]
    if str(release.get("version") or "") != str(m["version"]):
        return "version_changed", TEXT["version_changed"]
    return None


def advance_run(env, run_id: str) -> bool:
    """One idempotent tick. True when the run is final (or gone), False when another tick is needed (or the lock was busy)."""
    return _advance(env, run_id) is True


def _advance(env, run_id: str):
    """True when final or gone, False when another tick is needed, None when the run lock was busy (the holder queues its own next tick)."""
    with _locked(env, run_id) as got:
        if not got:
            return None
        run = env.load(run_id)
        if run is None or is_final(run):
            return True
        run["heartbeat"] = env.now()
        for m in run["modules"]:
            if m["state"] == "downloading":  # an earlier tick died between staging and queueing
                _conclude(env, run, m, "failed", "download_interrupted", TEXT["download_interrupted"])
        flying = _settle_installing(env, run)
        _cascade(env, run)
        if flying:
            env.save(run)
            return False
        allowed_body = None
        while True:
            _cascade(env, run)
            if run["stop_requested"]:
                _skip_pending(env, run, "stopped", TEXT["stopped"])
                _finish(env, run, "stopped")
                return True
            nxt = next((m for m in run["modules"] if m["state"] == "pending"), None)
            if nxt is None:
                _finish(env, run, "completed")
                return True
            if allowed_body is None:
                allowed_body = env.allowed()
            why = _recheck(allowed_body, nxt)
            if why:
                _conclude(env, run, nxt, "skipped", *why)
                continue
            repository_id = env.repo_for(nxt["id"], nxt["version"])
            if not repository_id:
                _conclude(env, run, nxt, "skipped", "not_in_catalogue_cache", TEXT["no_repository"])
                continue
            nxt.update(state="downloading", started_at=env.now())
            env.save(run)
            upload_id = None
            try:
                staged = env.stage(repository_id, nxt["id"], nxt["version"])
                upload_id = staged["upload_id"]
                job = env.queue(upload_id, run["started_by"])
            except env.known_errors as exc:
                _discard(env, upload_id)
                _conclude(env, run, nxt, "failed", "install_refused", str(exc) or TEXT["unexpected"])
                continue
            except Exception:
                logger.exception("Module install run %s: %s failed unexpectedly", run_id, nxt["id"])
                _discard(env, upload_id)
                _conclude(env, run, nxt, "failed", "unexpected", TEXT["unexpected"])
                continue
            nxt.update(state="installing", job_id=job.get("id"), upload_id=upload_id)
            env.save(run)
            return False


def _discard(env, upload_id) -> None:
    if upload_id:
        try:
            env.discard(upload_id)
        except Exception:
            logger.warning("A staged package of a module install run could not be discarded.", exc_info=True)


def close_if_stale(env, run_id: str) -> None:
    """Close a run whose chain died: no heartbeat for 15 minutes and no active job. Never touches a job that is still running."""
    with _locked(env, run_id) as got:
        if not got:
            return
        run = env.load(run_id)
        if run is None or is_final(run):
            return
        if _settle_installing(env, run):
            env.save(run)
            return
        if env.now() - run["heartbeat"] < INTERRUPT_SECONDS:
            env.save(run)
            return
        for m in run["modules"]:
            if m["state"] == "downloading":
                _conclude(env, run, m, "failed", "download_interrupted", TEXT["download_interrupted"])
        _skip_pending(env, run, "interrupted", TEXT["interrupted"])
        _finish(env, run, "interrupted")


def advance_and_requeue(env, run_id: str) -> None:
    """The Celery task body: one tick, then the next one three seconds later unless the run is final. Never raises.

    A tick that finds the run lock busy ends without queuing: the holder queues the next tick itself, so a long download cannot multiply chains."""
    try:
        final = _advance(env, run_id)
    except Exception:
        logger.exception("Module install run %s: a tick failed", run_id)
        final = False
    if final is False:
        env.enqueue_tick(run_id, TICK_DELAY_SECONDS)


# ------------------------------------------------------------------------------------------------------------------ routes' logic


def start_run(env, selection: list[str], username: str, http_for_state, request=None) -> tuple[int, dict]:
    """(http status, body) for POST install/."""
    active = _find_active(env)
    if active is not None:
        close_if_stale(env, active["run_id"])
        active = _find_active(env)
    if active is not None:
        return 409, _in_progress(active)
    plan = env.plan(selection)
    if plan.get("state") != "ok":
        return http_for_state(plan.get("state")), plan
    if not plan.get("order"):
        return 400, {**plan, "ok": False, "state": "nothing_to_install", "message": "None of the selected modules can be installed."}
    with env.start_lock() as got:
        if not got:
            return 409, {"ok": False, "state": "run_in_progress", "message": "A module install run is already starting.", "run_id": None}
        active = _find_active(env)
        if active is not None:
            return 409, _in_progress(active)
        run = new_run(env, plan, selection, username)
        try:
            env.audit(run, "start", "Module install run started", {
                "requested": list(selection), "order": [m["id"] for m in run["modules"] if m["planned"]],
                "skipped": [{"id": m["id"], "code": m["code"]} for m in run["modules"] if not m["planned"]]}, strict=True, request=request)
        except AuditNotSaved:
            return 503, {"ok": False, "state": "audit_not_saved", "message": "Core could not write the audit row, so nothing was started."}
        env.save(run)
        _prune(env)
    env.enqueue_tick(run["run_id"], 0)
    return 202, public_run(env, run)


def _in_progress(run: dict) -> dict:
    return {"ok": False, "state": "run_in_progress", "message": "A module install run is already going. Wait for it or stop it.", "run_id": run["run_id"]}


def progress(env, run_id: str) -> tuple[int, dict]:
    run = env.load(run_id)
    if run is None:
        return 404, {"ok": False, "state": "not_found", "message": "This install run was not found."}
    if not is_final(run):
        close_if_stale(env, run_id)
        run = env.load(run_id) or run
        if not is_final(run) and env.now() - run["heartbeat"] > STALE_TICK_SECONDS and not _lock_held(env, run_id):
            env.enqueue_tick(run_id, 0)
    return 200, public_run(env, run)


def request_stop(env, run_id: str, audit_stop) -> tuple[int, dict]:
    """Stop never touches a job in flight: the current module finishes, then nothing else starts."""
    with _locked(env, run_id, wait=2.0) as got:
        if not got:
            return 503, {"ok": False, "state": "busy", "message": "The run is busy. Try again in a moment."}
        run = env.load(run_id)
        if run is None:
            return 404, {"ok": False, "state": "not_found", "message": "This install run was not found."}
        if is_final(run):
            return 409, {"ok": False, "state": "already_finished", "message": "This install run has finished.", "run_id": run_id}
        run["stop_requested"] = True
        if any(m["state"] in ("installing", "downloading") for m in run["modules"]):
            run["status"] = "stopping"
        env.save(run)
        audit_stop(run)
        body = public_run(env, run)
    env.enqueue_tick(run_id, 0)
    return 200, body


# ------------------------------------------------------------------------------------------------------------------ real wiring


class FileStore:
    """Run files under the module manager state folder: one JSON file and one lock file per run. Unix only (fcntl)."""

    def __init__(self, root=None):
        from pathlib import Path

        self.root = Path(root) if root else Path("/var/lib/tec-tac/module-manager/install-runs")

    def _path(self, run_id):
        uuid.UUID(str(run_id))
        return self.root / f"{run_id}.json"

    def ids(self):
        return sorted(p.stem for p in self.root.glob("*.json")) if self.root.is_dir() else []

    def load(self, run_id):
        import json

        try:
            return json.loads(self._path(run_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def save(self, run):
        from .safe_files import atomic_json

        atomic_json(self._path(run["run_id"]), run, mode=0o660)

    def forget(self, run_id):
        for suffix in (".json", ".lock"):
            with contextlib.suppress(OSError):
                (self.root / f"{run_id}{suffix}").unlink()

    @contextlib.contextmanager
    def _flock(self, name, blocking):
        import fcntl
        import os

        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / name, os.O_RDWR | os.O_CREAT, 0o660)
        got = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                got = True
            except OSError:
                got = False
            yield got
        finally:
            if got:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def lock(self, run_id):
        uuid.UUID(str(run_id))
        return self._flock(f"{run_id}.lock", False)

    def start_lock(self):
        return self._flock(".start.lock", False)


def live_env() -> SimpleNamespace:
    """The real collaborators. Imports are lazy so the pure part tests without Django."""
    from . import (
        audit,
        licensing_catalogue_source,
        module_manager,
        module_manager_v2,
        module_repository,
    )

    store = FileStore()

    def repo_for(module_id, version):
        repos = [r for r in module_repository.list_repositories() if r.get("kind") == "licensing" and r.get("enabled", True)]
        development = module_repository.is_development_server() if repos else False
        for repo in repos:
            for item in module_repository._cached_modules(repo, development=development):
                if item.get("id") == module_id and item.get("version") == version and not item.get("download_unavailable"):
                    return repo["id"]
        return None

    def job_status(job_id):
        try:
            job = module_manager.get_job(job_id)
        except module_manager.ModuleManagerError:
            return None
        return {"status": job.get("status"), "stage": job.get("stage"), "error": job.get("error")}

    def write_audit(run, kind, message, metadata, strict=False, request=None):
        """The start row names the person (their request); every later row is Core's service actor."""
        try:
            person = getattr(request, "user", None) if request is not None else None
            actor = person or audit.service_audit_actor(module_id="core", service="module-install-run", identity="core.module-install-run")
            audit.record(actor=actor, module_id="core", action="run", object_type="module_install_run", object_id=run["run_id"], message=message,
                         metadata={"kind": kind, "started_by": run["started_by"], **metadata}, request=request, strict=strict)
        except Exception as exc:
            if strict:
                raise AuditNotSaved() from exc
            logger.warning("An audit row of a module install run could not be written.")

    def enqueue_tick(run_id, countdown):
        """One bounded broker attempt, never raises (the same way module_updates.queue_detection does)."""
        try:
            from .tasks import advance_module_install_run

            options = {"socket_timeout": 2, "socket_connect_timeout": 2}
            with advance_module_install_run.app.connection_for_write(transport_options=options, connect_timeout=2) as broker:
                advance_module_install_run.apply_async(args=[run_id], countdown=countdown, connection=broker, retry=False, expires=3600, ignore_result=True)
            return True
        except Exception:
            logger.warning("A module install tick was not queued; the progress route queues it again.", exc_info=True)
            return False

    return SimpleNamespace(
        now=time.time, load=store.load, save=store.save, ids=store.ids, forget=store.forget, lock=store.lock, start_lock=store.start_lock,
        plan=module_install_plan.plan_online_install, allowed=licensing_catalogue_source.read_allowed_modules, repo_for=repo_for,
        stage=lambda repository_id, module_id, version: module_repository.stage_repository_package(repository_id, module_id, version, request=None),
        queue=lambda upload_id, requested_by: module_manager_v2.queue_v2_install(upload_id, requested_by=requested_by),
        discard=module_manager_v2.discard_v2_stage, job_status=job_status, audit=write_audit, enqueue_tick=enqueue_tick,
        known_errors=(module_repository.ModuleRepositoryError, module_manager.ModuleManagerError),
    )
