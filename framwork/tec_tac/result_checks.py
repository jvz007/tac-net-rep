"""Result checks: follow a bulk run after the person closes the tab (Core 1.18.44; capability ``core.result_checks`` 1.0.0).

Why. A bulk script run on 40 endpoints finishes minutes after the person left the page. A module that started such a run asks Core to follow
it. Core asks the module's own reader once a minute, as the person who started the check, which endpoints have a result. When nothing is
running any more, or the deadline passes, Core sends that person one notice ("Run script: 38 done, 1 failed, 1 offline") that links to
``/results/<id>``. The page shows one row per endpoint: state and exit code. Core never stores output text.

The three parts.
* ``register_reader(id, module_id, reader)`` from a module's ``AppConfig.ready()``. Memory only, like event jobs. ``reader(job_ref,
  endpoint_ids, user)`` returns ``{endpoint_id: {"state": done|failed|offline|running, "exit_code": int|None, "hostname": text}}``. It runs
  as the person (no trusted global read): it sees only what that person may see. It must be idempotent and read-only.
* ``start(user, *, reader_id, label, endpoint_ids, job_ref, deadline_seconds)`` returns the check id. Only the module that owns the reader
  may call it (the frame walk of ``caller_identity``, rule 1.10, AD-26). Core, an unverified caller and another module are refused with
  ``ResultCheckRefused`` (a plain sentence that names no module).
* The Scheduler tick calls ``queue_due_checks`` (it never runs a reader or any module code, ``scheduler_completion.py`` rule). That sends
  at most 20 Celery messages; the task ``tec_tac.run_result_check`` calls ``run_check``, which calls the reader once, for at most 500 endpoints.

Fail closed. A reader that raises, answers badly, or whose module is gone or disabled leaves the items running; the check is tried again
next minute and still closes at its deadline with ``no_result``. A check holds at most 1000 endpoints and lives at most 24 hours; a
closed check is deleted 30 days later, items with it.
"""
from __future__ import annotations

import copy
import json
import logging
import re
import threading
import time
from datetime import timedelta
from collections.abc import Callable
from typing import NamedTuple

from django.db import transaction
from django.utils import timezone

from . import caller_identity

logger = logging.getLogger("tec_tac.result_checks")

CAPABILITY_ID = "core.result_checks"
CAPABILITY_VERSION = "1.0.0"

OPEN, CLOSED = "open", "closed"
RUNNING, DONE, FAILED, OFFLINE, NO_RESULT = "running", "done", "failed", "offline", "no_result"
READER_STATES = frozenset({RUNNING, DONE, FAILED, OFFLINE})
SUMMARY_KEYS = (DONE, FAILED, OFFLINE, RUNNING, NO_RESULT)

LABEL_MAX = 80
ENDPOINTS_MAX = 1000
ENDPOINT_ID_MAX = 200
HOSTNAME_MAX = 255
READ_BATCH = 500
JOB_REF_MAX_BYTES = 2048
DEADLINE_RANGE = (60, 86400)
MAX_OPEN_PER_USER = 20
FIRST_CHECK_SECONDS = 60
INTERVAL_SECONDS = 60
QUEUE_LEASE_SECONDS = 300
RUN_LEASE_SECONDS = 150  # longer than the task's hard limit
TASK_SOFT_LIMIT, TASK_HARD_LIMIT = 100, 120
QUEUE_LIMIT = 20
RETENTION_DAYS = 30
PRUNE_LIMIT = 200
BROKER_TIMEOUT_SECONDS = 2
MESSAGE_MAX = 1000
EXIT_CODE_RANGE = (-2147483648, 2147483647)
REFUSAL_AUDIT_SECONDS = 300
WARN_SECONDS = 600

CLOSED_ACTION = "custom:result-check-closed"
REFUSED_ACTION = "custom:result-check-refused"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")

REFUSED_TEXT = {
    "caller": "Core could not tell which module is asking, so it did not start the result check.",
    "not_owner": "This result reader belongs to another module, so the result check was not started.",
    "unknown_reader": "Core does not know this result reader, so the result check was not started.",
    "user": "This person cannot receive result checks, so none was started.",
    "too_many_open": f"You already have {MAX_OPEN_PER_USER} result checks open. Wait for one to finish, then try again.",
}
AUDITED_REFUSALS = frozenset({"caller", "not_owner", "unknown_reader"})


class ResultCheckRegistrationError(ValueError):
    """A reader was refused at registration. A module wraps the call, logs and goes on, so it always starts."""


class ResultCheckInvalid(ValueError):
    """An argument of ``start`` is outside its limit. The text says which one."""


class ResultCheckRefused(Exception):
    """``start`` was refused. ``code`` is a reason code; the text is a plain sentence that names no module."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(REFUSED_TEXT.get(code, "The result check was not started."))


class ReaderDefinition(NamedTuple):
    id: str
    module_id: str
    reader: Callable


_LOCK = threading.Lock()
_READERS: dict[str, ReaderDefinition] = {}
_SEEN: dict = {}  # (kind, key) -> monotonic time of the last audit row or warning


def _throttled(kind: str, key, seconds: float) -> bool:
    """True when this (kind, key) was already reported within ``seconds``. Bounded: the map never holds more than 500 keys."""
    now = time.monotonic()
    with _LOCK:
        last = _SEEN.get((kind, key))
        if last is not None and now - last < seconds:
            return True
        if len(_SEEN) >= 500:
            _SEEN.clear()
        _SEEN[(kind, key)] = now
    return False


# ------------------------------------------------------------------------------------------------ registration
def _module_enabled(module_id: str) -> bool:
    from . import module_state

    state = module_state.load_state()
    if isinstance(state, dict) and state.get("_corrupt"):
        raise RuntimeError("the module state is corrupt")
    return bool(module_state.is_enabled(module_id, state))


def _verify_owner(module_id: str, reader: Callable) -> None:
    """The same checks as event jobs: an installed, enabled, non-legacy extension, and a reader whose code lies in the module's own folder."""
    try:
        from . import registry

        plugin = next((p for p in registry.discover_plugins() if p.plugin_id == module_id), None)
    except Exception:
        logger.warning("Result reader registration: the installed modules could not be read.", exc_info=True)
        raise ResultCheckRegistrationError("Core could not read the installed modules to verify the owner.") from None
    if plugin is None or plugin.plugin_type != "extension" or getattr(plugin, "legacy", False):
        raise ResultCheckRegistrationError("module_id is not an installed extension module.")
    try:
        enabled = _module_enabled(module_id)
    except Exception:
        raise ResultCheckRegistrationError("Core could not read whether the module is enabled.") from None
    if not enabled:
        raise ResultCheckRegistrationError("module_id is not enabled.")
    code = getattr(getattr(reader, "__func__", reader), "__code__", None)
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        raise ResultCheckRegistrationError("reader must be a function or method defined in the module's own code, not a partial, a built-in or generated code.")
    if not caller_identity._under(caller_identity._norm(filename), caller_identity._norm(plugin.root)):
        raise ResultCheckRegistrationError("reader's code must lie inside the module's own folder: a module cannot point a result check at code that is not its own.")


def register_reader(*, id, module_id, reader):
    """Register one result reader and return its id. Call it from ``AppConfig.ready()``; it touches memory only.

    ``id`` is ``'<module_id>.<name>'``. Registering the identical definition again returns without error; a different one is refused with
    ``ResultCheckRegistrationError`` (a ValueError). A module wraps the call, logs and goes on, so Tactical always starts."""
    if not isinstance(id, str) or not isinstance(module_id, str) or not module_id or not _ID_RE.fullmatch(id) or len(id) > 160:
        raise ResultCheckRegistrationError("id must be '<module_id>.<name>' with letters, digits, '-', '_' and '.' only.")
    if not id.startswith(module_id + "."):
        raise ResultCheckRegistrationError("id must start with the module id and a dot.")
    if not callable(reader):
        raise ResultCheckRegistrationError("reader must be callable.")
    definition = ReaderDefinition(id, module_id, reader)
    with _LOCK:
        previous = _READERS.get(id)
    if previous is not None:
        if previous == definition:
            return id
        raise ResultCheckRegistrationError(f"result reader {id!r} is already registered with a different definition.")
    _verify_owner(module_id, reader)  # reads the registry; kept outside the lock
    with _LOCK:
        previous = _READERS.get(id)
        if previous is not None and previous != definition:
            raise ResultCheckRegistrationError(f"result reader {id!r} is already registered with a different definition.")
        _READERS[id] = definition
    return id


# ------------------------------------------------------------------------------------------------ small helpers
def _interactive(queryset):
    """Active, not an installer or agent account, not blocked from the dashboard (the people who may receive a notice)."""
    return queryset.filter(is_active=True, is_installer_user=False, agent__isnull=True, block_dashboard_login=False)


def _user_model():
    from django.contrib.auth import get_user_model

    return get_user_model()


def _user_looks_allowed(user) -> bool:
    return bool(
        getattr(user, "pk", None) is not None and getattr(user, "is_active", False) and not getattr(user, "is_installer_user", False)
        and getattr(user, "agent", None) is None and not getattr(user, "block_dashboard_login", False)
    )


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def summarise(states) -> dict:
    out = {"total": 0, **{key: 0 for key in SUMMARY_KEYS}}
    for state in states:
        out["total"] += 1
        if state in out:
            out[state] += 1
    return out


def closing_message(label: str, counts: dict) -> str:
    """The one sentence of the closing notice: '<label>: N done, M failed, K offline[, L no result]'. At most 1000 characters."""
    tail = f": {counts[DONE]} done, {counts[FAILED]} failed, {counts[OFFLINE]} offline" + (f", {counts[NO_RESULT]} no result" if counts[NO_RESULT] else "")
    label = str(label or "")
    room = MESSAGE_MAX - len(tail)
    return (label[:max(room, 0)] + tail)[:MESSAGE_MAX]


def status_message(status: str, label: str, counts: dict) -> str:
    """The sentence the read route shows: the closing text once closed, a 'still checking' sentence while open."""
    if status == CLOSED:
        return closing_message(label, counts)
    return f"Still checking: {counts['total'] - counts[RUNNING]} of {counts['total']} endpoints have a result so far."


# ------------------------------------------------------------------------------------------------ start
def _audit_refusal(module_id: str, code: str) -> None:
    """At most one best-effort Core audit row per module and reason per 5 minutes. Reason code only. Never raises."""
    if code not in AUDITED_REFUSALS or _throttled("audit", (module_id, code), REFUSAL_AUDIT_SECONDS):
        return
    try:
        from . import audit

        audit.record(
            actor=audit.service_audit_actor(module_id="core", service="result-checks", identity="start"),
            module_id="core", action=REFUSED_ACTION, object_type="result_check", object_id=code,
            message="A result check was refused.", metadata={"requested_by": "result-checks", "reason": code},
        )
    except Exception:
        logger.warning("The audit row of a refused result check could not be written.", exc_info=True)


def _refuse(module_id: str, code: str):
    _audit_refusal(module_id, code)
    raise ResultCheckRefused(code)


def _clean_label(label) -> str:
    if not isinstance(label, str):
        raise ResultCheckInvalid("label must be text.")
    text = label.strip()
    if not 1 <= len(text) <= LABEL_MAX or not text.isprintable():
        raise ResultCheckInvalid(f"label must be 1 to {LABEL_MAX} printable characters.")
    return text


def _clean_endpoints(endpoint_ids) -> list:
    if not isinstance(endpoint_ids, (list, tuple)) or not 1 <= len(endpoint_ids) <= ENDPOINTS_MAX:
        raise ResultCheckInvalid(f"endpoint_ids must be a list of 1 to {ENDPOINTS_MAX} ids.")
    out = []
    for item in endpoint_ids:
        if not isinstance(item, str) or not 1 <= len(item) <= ENDPOINT_ID_MAX or not item.isprintable():
            raise ResultCheckInvalid(f"each endpoint id must be 1 to {ENDPOINT_ID_MAX} printable characters.")
        out.append(item)
    if len(set(out)) != len(out):
        raise ResultCheckInvalid("endpoint_ids must not repeat an id.")
    return out


def _clean_job_ref(job_ref) -> dict:
    if not isinstance(job_ref, dict):
        raise ResultCheckInvalid("job_ref must be a JSON object.")
    try:
        size = len(json.dumps(job_ref, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    except (TypeError, ValueError):
        raise ResultCheckInvalid("job_ref must be JSON.") from None
    if size > JOB_REF_MAX_BYTES:
        raise ResultCheckInvalid("job_ref must be at most 2 KiB.")
    return json.loads(json.dumps(job_ref))


def start(user, *, reader_id, label, endpoint_ids, job_ref, deadline_seconds) -> str:
    """Start one result check for ``user`` and return its id (see the module docstring).

    Only the module that owns ``reader_id`` may call it, from its own code. Raises ``ResultCheckRefused`` (caller, reader, person or the
    cap of 20 open checks) or ``ResultCheckInvalid`` (an argument outside its limit). Nothing is stored on a refusal."""
    identity = caller_identity.calling_module_for_core_provider(provider_file=__file__)  # the module whose own code called this function
    caller = identity.module_id if identity is not None else ""
    if identity is None:
        _refuse(caller, "caller")
    definition = _READERS.get(reader_id) if isinstance(reader_id, str) else None
    if definition is None:
        _refuse(caller, "unknown_reader")
    if definition.module_id != caller:
        _refuse(caller, "not_owner")
    if not _user_looks_allowed(user):
        raise ResultCheckRefused("user")
    text = _clean_label(label)
    ids = _clean_endpoints(endpoint_ids)
    ref = _clean_job_ref(job_ref)
    if not _int(deadline_seconds) or not DEADLINE_RANGE[0] <= deadline_seconds <= DEADLINE_RANGE[1]:
        raise ResultCheckInvalid(f"deadline_seconds must be a whole number from {DEADLINE_RANGE[0]} to {DEADLINE_RANGE[1]}.")
    from .models import TecTacResultCheck, TecTacResultCheckItem

    now = timezone.now()
    with transaction.atomic():
        # The row lock on the person makes two parallel starts take turns, so the cap cannot be passed.
        locked = _interactive(_user_model().objects.select_for_update()).filter(pk=user.pk).first()
        if locked is None:
            raise ResultCheckRefused("user")
        if TecTacResultCheck.objects.filter(user=locked, status=OPEN).count() >= MAX_OPEN_PER_USER:
            raise ResultCheckRefused("too_many_open")
        check = TecTacResultCheck.objects.create(
            user=locked, module_id=definition.module_id, reader_id=definition.id, label=text, job_ref=ref, status=OPEN,
            next_check_at=now + timedelta(seconds=FIRST_CHECK_SECONDS), deadline_at=now + timedelta(seconds=deadline_seconds),
        )
        TecTacResultCheckItem.objects.bulk_create([TecTacResultCheckItem(result_check_id=check.pk, endpoint_id=item, state=RUNNING) for item in ids], batch_size=500)
    return str(check.pk)


# ------------------------------------------------------------------------------------------------ the check itself
def _load_starter(user_id):
    return _interactive(_user_model().objects).filter(pk=user_id).first()


def _items_to_read(check_pk) -> list:
    """At most 500 running items, the ones checked longest ago first (never checked first), so a 1000-endpoint check rotates."""
    from .models import TecTacResultCheckItem

    running = TecTacResultCheckItem.objects.filter(result_check_id=check_pk, state=RUNNING)
    items = list(running.filter(checked_at__isnull=True).order_by("id")[:READ_BATCH])
    if len(items) < READ_BATCH:
        items += list(running.filter(checked_at__isnull=False).order_by("checked_at")[:READ_BATCH - len(items)])
    return items


def _ask_reader(row, starter, ids):
    """The reader's raw answer, or None when it could not be asked or raised. Never raises."""
    definition = _READERS.get(row.reader_id)
    try:
        if definition is None or definition.module_id != row.module_id or not _module_enabled(row.module_id):
            if not _throttled("warn", ("gone", row.reader_id), WARN_SECONDS):
                logger.warning("The result reader %s is not available; its checks stay running until their deadline.", row.reader_id)
            return None
        return definition.reader(copy.deepcopy(row.job_ref), list(ids), starter)
    except Exception:
        if not _throttled("warn", ("raised", row.reader_id), WARN_SECONDS):
            logger.warning("The result reader %s failed; the items stay running and are asked again.", row.reader_id, exc_info=True)
        return None


def _apply_answer(items, answer, now) -> None:
    """Strict: an entry that is not a dict with a known state, an int or None exit code and a text hostname leaves the item running."""
    from .models import TecTacResultCheckItem

    if not isinstance(answer, dict):
        return
    changed = []
    for item in items:
        entry = answer.get(item.endpoint_id)
        if not isinstance(entry, dict) or entry.get("state") not in READER_STATES:
            item.checked_at = now
            changed.append(item)
            continue
        code, host = entry.get("exit_code"), entry.get("hostname", "")
        if (code is not None and (not _int(code) or not EXIT_CODE_RANGE[0] <= code <= EXIT_CODE_RANGE[1])) or not isinstance(host, str):
            item.checked_at = now
            changed.append(item)
            continue
        host = "".join(ch for ch in host if ch.isprintable())[:HOSTNAME_MAX]
        item.state, item.exit_code, item.checked_at = entry["state"], code, now
        if host:
            item.hostname = host
        changed.append(item)
    if changed:
        TecTacResultCheckItem.objects.bulk_update(changed, ["state", "exit_code", "hostname", "checked_at"], batch_size=250)


def _audit_closed(row, counts, *, notified: bool, reason: str) -> None:
    try:
        from . import audit

        audit.record(
            actor=audit.service_audit_actor(module_id="core", service="result-checks", identity="close"),
            module_id="core", action=CLOSED_ACTION, object_type="result_check", object_id=str(row.pk),
            message="A result check closed.",
            metadata={"requested_by": "result-checks", "check_id": str(row.pk), "reader_id": row.reader_id, "reason": reason, "notified": notified,
                      **{key: counts[key] for key in ("total",) + SUMMARY_KEYS}},
        )
    except Exception:
        logger.warning("The audit row of a closed result check could not be written.", exc_info=True)


def _close(row, now, *, starter, reason: str) -> str:
    """Close the check once. The filtered update decides the winner, so only that call sends the notice and writes the audit row."""
    from .models import TecTacResultCheck, TecTacResultCheckItem

    with transaction.atomic():
        won = TecTacResultCheck.objects.filter(pk=row.pk, status=OPEN).update(status=CLOSED, closed_at=now, running_until=None, queued_until=None)
        if not won:
            return "skipped"
        TecTacResultCheckItem.objects.filter(result_check_id=row.pk, state=RUNNING).update(state=NO_RESULT, checked_at=now)
    counts = summarise(TecTacResultCheckItem.objects.filter(result_check_id=row.pk).values_list("state", flat=True))
    notified = False
    if starter is not None:
        try:
            from . import notices

            notices.publish_system_notice(
                [starter], client_id=f"result-check:{row.pk}", source="core", title="", message=closing_message(row.label, counts),
                level="success" if counts[DONE] == counts["total"] else "warning", action_label="See results", action_route=f"/results/{row.pk}",
            )
            TecTacResultCheck.objects.filter(pk=row.pk).update(notice_sent=True)
            notified = True
        except Exception:
            logger.warning("The closing notice of a result check could not be stored.", exc_info=True)
    _audit_closed(row, counts, notified=notified, reason=reason)
    return CLOSED


def run_check(check_id, now=None) -> str:
    """One pass over one check (the Celery task ``tec_tac.run_result_check`` calls this). Returns skipped, closed, open or error."""
    from .models import TecTacResultCheck, TecTacResultCheckItem

    now = now or timezone.now()
    lease = now + timedelta(seconds=RUN_LEASE_SECONDS)
    base = TecTacResultCheck.objects.filter(pk=check_id, status=OPEN)
    # An atomic filtered update is the claim: a duplicate delivery finds the lease live and runs nothing.
    if not (base.filter(running_until__isnull=True).update(running_until=lease) or base.filter(running_until__lt=now).update(running_until=lease)):
        return "skipped"
    try:
        row = TecTacResultCheck.objects.filter(pk=check_id).first()
        if row is None or row.status != OPEN:
            return "skipped"
        starter = _load_starter(row.user_id)
        if starter is None:
            return _close(row, now, starter=None, reason="starter")
        items = _items_to_read(row.pk)
        if items:
            _apply_answer(items, _ask_reader(row, starter, [item.endpoint_id for item in items]), now)
        nothing_running = not TecTacResultCheckItem.objects.filter(result_check_id=row.pk, state=RUNNING).exists()
        if nothing_running or now >= row.deadline_at:
            return _close(row, now, starter=starter, reason="finished" if nothing_running else "deadline")
        TecTacResultCheck.objects.filter(pk=row.pk).update(next_check_at=now + timedelta(seconds=INTERVAL_SECONDS), running_until=None, queued_until=None)
        return OPEN
    except Exception:
        logger.warning("A result check could not be run; it is tried again.", exc_info=True)
        try:
            TecTacResultCheck.objects.filter(pk=check_id, status=OPEN).update(next_check_at=now + timedelta(seconds=INTERVAL_SECONDS), running_until=None)
        except Exception:
            logger.warning("The lease of a result check could not be released; it lapses by itself.", exc_info=True)
        return "error"


# ------------------------------------------------------------------------------------------------ the tick step
def _send_task(check_id) -> None:
    """One bounded broker attempt, like event jobs. Raises when the broker does not take the message."""
    from .tasks import run_result_check

    options = {"socket_timeout": BROKER_TIMEOUT_SECONDS, "socket_connect_timeout": BROKER_TIMEOUT_SECONDS}
    with run_result_check.app.connection_for_write(transport_options=options, connect_timeout=BROKER_TIMEOUT_SECONDS) as broker:
        run_result_check.apply_async(
            args=[str(check_id)], connection=broker, retry=False, expires=QUEUE_LEASE_SECONDS, ignore_result=True,
            soft_time_limit=TASK_SOFT_LIMIT, time_limit=TASK_HARD_LIMIT,
        )


def delete_old_checks(now=None, limit: int = PRUNE_LIMIT) -> int:
    """Delete closed checks whose ``closed_at`` is more than 30 days old, at most ``limit`` a call. Items go with the check by cascade."""
    from .models import TecTacResultCheck

    now = now or timezone.now()
    ids = list(TecTacResultCheck.objects.filter(status=CLOSED, closed_at__lt=now - timedelta(days=RETENTION_DAYS)).values_list("pk", flat=True)[:limit])
    if ids:
        TecTacResultCheck.objects.filter(pk__in=ids).delete()
    return len(ids)


def queue_due_checks(now=None, limit: int = QUEUE_LIMIT) -> int:
    """The tick step: send a Celery message for at most ``limit`` due open checks, then trim old closed checks. Returns how many were queued.

    It never calls a reader or any module code and never raises. A check is claimed with an atomic filtered update on ``queued_until``
    (a lease of 5 minutes); a message the broker did not take clears the lease so the next tick tries again."""
    queued = 0
    try:
        from .models import TecTacResultCheck

        now = now or timezone.now()
        due = TecTacResultCheck.objects.filter(status=OPEN, next_check_at__lte=now)
        lease = now + timedelta(seconds=QUEUE_LEASE_SECONDS)
        candidates = [(pk, "isnull") for pk in due.filter(queued_until__isnull=True).order_by("next_check_at").values_list("pk", flat=True)[:limit]]
        if len(candidates) < limit:
            candidates += [(pk, "lapsed") for pk in due.filter(queued_until__lt=now).order_by("next_check_at").values_list("pk", flat=True)[:limit - len(candidates)]]
        for pk, kind in candidates:
            current = TecTacResultCheck.objects.filter(pk=pk, status=OPEN)
            claimed = current.filter(queued_until__isnull=True).update(queued_until=lease) if kind == "isnull" else current.filter(queued_until__lt=now).update(queued_until=lease)
            if not claimed:
                continue
            try:
                _send_task(pk)
                queued += 1
            except Exception:
                TecTacResultCheck.objects.filter(pk=pk, status=OPEN).update(queued_until=None)
                logger.warning("A result check message could not be sent; the next tick tries again.", exc_info=True)
                break  # the broker is down: do not wait for it once per check
    except Exception:
        logger.warning("The result check queue step failed; the next tick retries.", exc_info=True)
    try:
        delete_old_checks(now)
    except Exception:
        logger.warning("Old result checks could not be deleted; the next tick retries.", exc_info=True)
    return queued


# ------------------------------------------------------------------------------------------------ the capability
class _ResultChecksProvider:
    def register_reader(self, *, id, module_id, reader):
        return register_reader(id=id, module_id=module_id, reader=reader)

    def start(self, user, **kwargs):
        return start(user, **kwargs)  # the caller check still decides: the first frame outside this file is Core's, so it is refused


_PROVIDER = _ResultChecksProvider()


def result_checks_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["register_reader", "start"],
        "python": (
            "tec_tac.result_checks.register_reader(*, id, module_id, reader) -> id; "
            "tec_tac.result_checks.start(user, *, reader_id, label, endpoint_ids, job_ref, deadline_seconds) -> check id; "
            "reader(job_ref, endpoint_ids, user) -> {endpoint_id: {state, exit_code, hostname}}"
        ),
        "limits": {"endpoints": ENDPOINTS_MAX, "read_batch": READ_BATCH, "job_ref_bytes": JOB_REF_MAX_BYTES, "open_per_person": MAX_OPEN_PER_USER,
                   "deadline_seconds": list(DEADLINE_RANGE), "retention_days": RETENTION_DAYS},
        "caller": "start: the module that owns the reader only (the frame walk of AD-26); Core, an unverified caller and another module are refused with ResultCheckRefused",
        "fails": "closed: a reader that raises, answers badly or is gone leaves the items running; the check still closes at its deadline with no_result",
        "stores_output": False,
        "requires_framework": ">=1.18.44",
    }


def register_core_result_checks_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Follow a bulk run after the page is closed and tell the person once when the results are in (states and exit codes only).",
        operations=("register_reader", "start"),
        metadata=result_checks_contract_metadata(),
    )
