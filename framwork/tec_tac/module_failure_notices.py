"""Notices for failed module jobs (Core 1.17.14, Johan CQ36 and CQ41).

A module job runs as root, minutes after the browser that queued it has moved on. When it fails, nobody is looking. The
scheduler tick calls ``sweep_failed_jobs`` once a minute. It raises one notice per failed module job (enable, disable,
install, bundle install and batch install) for the people who can act on it, through
``tec_tac.notices.publish_system_notice``.

* One notice per job and recipient. The dedupe key is the notice's ``client_id``, ``module-job-failed:<job id>``, so the
  next tick never stores it again and never resets a notice the person has read.
* Recipients (CQ41, assumption (a), the smallest audience): every active effective superuser, plus the user named in the
  job's ``requested_by`` when that user is active.
* The text is plain English, printable ASCII, cut short, and holds no paths. A failed switch says whether the flags were put back, from
  ``rolled_back`` and ``rollback_error`` as the root helper recorded them.
* It looks only at jobs finished in the last seven days, and at most 200 of them per tick, newest first: the same bounds
  as the replacement audit sweep.
* It never raises. A failure is logged and the next tick tries again. Tactical is not affected.

The browser toast for a new notice is UI work. Core only stores the notice.

Priority 1 email (1.17.15, Johan CQ41; 1.17.25, AD-28 amendment): a failed module job is a system failure, so the Tec-Tac
administrators also get an email, once per job. ``send_p1_email`` is the one place that sends it. From 1.17.25 the email goes
through Tactical's own sender (``priority_mail``) and never through a Core SMTP client or Global Settings. Its rules:

* Recipients: the administrators only (active effective superusers, with their own address), never a free-form address. The
  requester gets the email only when that person is an administrator. One entry per address, at most 20 per job.
* The mail server's name gets the public-address check before Tactical connects (1.17.26, AD-30: with the administrator's
  ``priority_mail_private_relay`` setting on, Core's own call also accepts ordinary private-network addresses. A module never does). A refusal sends nothing, writes one count-only
  audit row, and marks the recipients as tried.
* An hourly cap (20 emails, counted from the marker rows of the last hour, read once per sweep and spent across jobs). Over the cap
  nothing is sent, nothing is marked, and a later tick sends within the seven-day window.
* One message per recipient, through ``CoreSettings.send_mail`` with ``test=True``. The first failed send stops the job's loop and
  marks the rest as tried, so a broken server is not retried every minute.
* Off when Tactical's email is not configured. Nothing is sent and no row is written, and recent failures are still sent once it is.
* Each job that reached the sender or the host check writes one count-only audit row (``custom:priority-mail``). It carries ``private_relay`` (true only when the relaxed rule accepted the host). It never carries an
  address, a host, a subject, a body, Tactical's text or a password.

The marker rows (``module-job-failed-email:<job id>``) are the dedupe key and the cap's count. Core reads no CoreSettings field
other than ``smtp_host`` (for the public-address check), and reads no password.
"""
from __future__ import annotations

import logging
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from . import module_replacement as _replacement
from . import priority_mail

logger = logging.getLogger("tec_tac.module_failure_notices")

CLIENT_ID_PREFIX = "module-job-failed:"
EMAIL_CLIENT_ID_PREFIX = "module-job-failed-email:"
EMAIL_WINDOW = timedelta(hours=1)
EMAIL_SERVER_MAX = 120
SOURCE = "core"
TITLE = "Module job failed"
ACTION_LABEL = "Open Modules"
ACTION_ROUTE = "/modules"
WINDOW_DAYS = _replacement.AUDIT_WINDOW_DAYS
MAX_JOBS_PER_TICK = _replacement.AUDIT_MAX_JOBS_PER_TICK
ERROR_MAX = 200
MESSAGE_MAX = 600
EMAIL_AUDIT_ACTION = "custom:priority-mail"
EMAIL_AUDIT_OBJECT = "module_job_email"

# What each job action did, in the words of the sentence "Module X could not be ...".
_VERBS = {"enable": "enabled", "disable": "disabled", "install": "installed", "bundle_install": "installed", "batch_install": "installed"}
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
_PATH_TOKEN_RE = re.compile(r"\S*[/\\]\S*")


def client_id_for(job_id: Any) -> str | None:
    """The dedupe key of a job's notice, or None when the job has no usable id."""
    text = str(job_id or "")
    return f"{CLIENT_ID_PREFIX}{text}" if _JOB_ID_RE.fullmatch(text) else None


def _error_text(value: Any) -> str:
    """The job's error as one short line of printable ASCII with every path-like word replaced."""
    cleaned = _replacement._plain(value, ERROR_MAX * 3)
    cleaned = _PATH_TOKEN_RE.sub("[path]", cleaned)
    return " ".join(cleaned.split())[:ERROR_MAX]


def _subject(job: Mapping[str, Any]) -> str:
    action = job.get("action")
    plugin = _PATH_TOKEN_RE.sub("[path]", _replacement._plain(job.get("plugin_id"), 80))
    if action == "batch_install":
        return "The batch install"
    if action == "bundle_install":
        return f"The bundle install of module {plugin}" if plugin else "The bundle install"
    return f"Module {plugin}" if plugin else "A module"


def _module_label(job: Mapping[str, Any]) -> str:
    """What the job is about, in words for a subject line: a module id, or the batch and bundle installs (1.17.15)."""
    action = job.get("action")
    plugin = _PATH_TOKEN_RE.sub("[path]", _replacement._plain(job.get("plugin_id"), 80))
    if action == "batch_install":
        return "batch install"
    if action == "bundle_install":
        return f"bundle {plugin}" if plugin else "bundle install"
    return plugin or "module job"


def notice_for_job(job: Mapping[str, Any]) -> dict | None:
    """The notice a failed module job owes, or None. Pure: no database, no clock, no files.

    Returns {client_id, level, title, message, action_label, action_route, requested_by, module}. ``module`` is the label
    the Priority 1 email uses (1.17.15)."""
    if not isinstance(job, Mapping) or job.get("status") != "failed" or job.get("action") not in _VERBS:
        return None
    client_id = client_id_for(job.get("id"))
    if client_id is None:
        return None
    action = str(job["action"])
    verb = _VERBS[action]
    if action == "install" and job.get("replace"):
        verb = "updated"
    text = f"{_subject(job)} could not be {verb}."
    if action in ("enable", "disable"):
        # A switch records what happened to the flags. The stage alone is never taken as proof.
        outcome, _ = _replacement._failed_outcome(job, _replacement._plain(job.get("stage"), 40))
        text += f" {outcome}"
    error = _error_text(job.get("error")) or "no error was recorded"
    text += f" Error: {error}"
    return {
        "client_id": client_id, "level": "error", "title": TITLE, "message": text[:MESSAGE_MAX],
        "action_label": ACTION_LABEL, "action_route": ACTION_ROUTE,
        "requested_by": str(job.get("requested_by") or ""), "module": _module_label(job),
    }


def email_client_id_for(notice: Mapping[str, Any]) -> str | None:
    """The dedupe key of a notice's Priority 1 email, ``module-job-failed-email:<job id>``, or None (1.17.15)."""
    client_id = str(notice.get("client_id") or "")
    if not client_id.startswith(CLIENT_ID_PREFIX):
        return None
    job_id = client_id[len(CLIENT_ID_PREFIX):]
    return f"{EMAIL_CLIENT_ID_PREFIX}{job_id}" if _JOB_ID_RE.fullmatch(job_id) else None


def _bounded_failed_jobs(jobs: Iterable[Any], now: datetime) -> list[Mapping[str, Any]]:
    """Failed jobs finished inside the window, newest first, at most ``MAX_JOBS_PER_TICK``."""
    horizon = now.timestamp() - WINDOW_DAYS * 86400
    found = []
    for job in jobs:
        if not isinstance(job, Mapping) or job.get("status") != "failed":
            continue
        when = _replacement._parse_when(job.get("finished_at"))
        if when is not None and when.timestamp() >= horizon:
            found.append((when, job))
    found.sort(key=lambda item: item[0], reverse=True)
    return [job for _, job in found[:MAX_JOBS_PER_TICK]]


def _default_recipients(requested_by: str) -> list:
    from . import notices

    return notices.system_notice_recipients([requested_by] if requested_by else [])


def _default_publish(recipients, notice: dict) -> int:
    from . import notices

    return notices.publish_system_notice(
        recipients, client_id=notice["client_id"], message=notice["message"], title=notice["title"], level=notice["level"],
        source=SOURCE, action_label=notice["action_label"], action_route=notice["action_route"],
    )


def _default_existing(client_ids: list[str]) -> set[tuple[str, Any]]:
    from .models import TecTacUserNotice

    return set(TecTacUserNotice.objects.filter(client_id__in=client_ids).values_list("client_id", "user_id"))


def _default_recent(since: datetime) -> int:
    """How many Priority 1 email marker rows were written since ``since``: one row per recipient tried (the cap's count)."""
    from .models import TecTacUserNotice

    return TecTacUserNotice.objects.filter(client_id__startswith=EMAIL_CLIENT_ID_PREFIX, created_at__gte=since).count()


def _default_audit(job_id: str, metadata: dict) -> None:
    from . import audit

    actor = audit.service_audit_actor(module_id="core", service="priority-mail")
    audit.record(
        actor=actor, module_id="core", action=EMAIL_AUDIT_ACTION, object_type=EMAIL_AUDIT_OBJECT, object_id=job_id,
        message="Priority 1 email for a failed module job.", metadata=metadata, strict=False,
    )


def _server_name() -> str:
    """The name the email gives for this server: the first Django ALLOWED_HOSTS entry, else the machine's host name."""
    try:
        from django.conf import settings as django_settings

        for host in django_settings.ALLOWED_HOSTS:
            name = str(host).strip().lstrip(".")
            if name and name != "*":
                return _replacement._plain(name, EMAIL_SERVER_MAX) or "this server"
    except Exception:
        logger.debug("No Django host name for the Priority 1 email; using the machine name.")
    try:
        return _replacement._plain(socket.gethostname(), EMAIL_SERVER_MAX) or "this server"
    except OSError:
        return "this server"


def _default_mark_sent(user: Any, client_id: str) -> None:
    """Record that the email was tried for this user. The row is read already, so it raises no toast."""
    from django.utils import timezone

    from .models import TecTacUserNotice

    TecTacUserNotice.objects.get_or_create(user=user, client_id=client_id, defaults={
        "source": SOURCE, "level": "info", "title": "Email notice sent",
        "message": "An email about a failed module job was sent to you.", "read_at": timezone.now(),
    })


def _email_text(value: Any, limit: int) -> str:
    """Printable ASCII on one line, cut to ``limit``: no carriage return, no line feed, no control character."""
    return " ".join(_replacement._plain(value, limit * 2).split())[:limit]


def _email_subject_and_body(notice: Mapping[str, Any], server: str) -> tuple[str, str]:
    """The subject and body of one Priority 1 email. Plain English; the body repeats the notice text, which holds no paths."""
    module = _email_text(notice.get("module") or "module job", 80)
    subject = _email_text(f"[Tec-Tac] Priority 1: module job failed for {module} on {server}", 200)
    body = (
        f"A module job did not finish on {server}.\n\n"
        f"{_email_text(notice.get('message'), MESSAGE_MAX)}\n\n"
        f"Server: {server}\n"
        f"Module: {module}\n\n"
        "Open Modules in Tec-Tac to see the job log.\n\n"
        "Tec-Tac by Tech Flow Dynamics - techxflow.co.za\n"
    )
    return subject, body


def _email_audience(users: Iterable[Any]) -> list:
    """The administrators who may get the email: one entry per address (case-insensitive), at most MAX_RECIPIENTS. A person with
    no address keeps a place and is refused when the email is tried."""
    seen: set[str] = set()
    audience: list = []
    for user in users:
        address = str(getattr(user, "email", "") or "").strip().lower()
        if address:
            if address in seen:
                continue
            seen.add(address)
        audience.append(user)
        if len(audience) >= priority_mail.MAX_RECIPIENTS:
            break
    return audience


def _email_budget(now: datetime, configured: Callable[[], bool] | None, recent: Callable[[datetime], int] | None) -> int | None:
    """How many emails may still be tried this hour, or None when Tactical's email is not configured. Read once per sweep."""
    if not (configured or priority_mail.is_configured)():
        logger.debug("Priority 1 email skipped: Tactical's email is not configured.")
        return None
    used = int((recent or _default_recent)(now - EMAIL_WINDOW) or 0)
    return max(0, priority_mail.HOURLY_CAP - used)


def _mark(user: Any, client_id: str, mark: Callable[[Any, str], None] | None) -> None:
    try:
        (mark or _default_mark_sent)(user, client_id)
    except Exception:
        logger.exception("Could not record the Priority 1 email %s.", client_id)


def _write_email_audit(notice: Mapping[str, Any], counts: Mapping[str, int], code: str, audit: Callable[[str, dict], None] | None,
                       private_relay: bool = False) -> None:
    """One count-only row for the job. Best effort: a failed write is logged and the sweep goes on."""
    job_id = str(notice.get("client_id") or "")[len(CLIENT_ID_PREFIX):]
    if code == "send_failed":
        outcome = "failed"
    elif counts["recipients"] and counts["sent"] == counts["recipients"]:
        outcome = "sent"
    else:
        outcome = "refused"
    metadata = {
        "recipients": counts["recipients"], "sent": counts["sent"], "refused": counts["refused"],
        "outcome": outcome, "code": code, "requested_by": "scheduler", "private_relay": bool(private_relay),
    }
    try:
        (audit or _default_audit)(job_id, metadata)
    except Exception:
        logger.exception("Could not write the Priority 1 email audit row.")


def send_p1_email(notice: Mapping[str, Any], recipients: Iterable[Any], *, state: dict | None = None,
                  host: Callable[[], str] | None = None, send: Callable[[str, str, str], bool] | None = None,
                  configured: Callable[[], bool] | None = None, recent: Callable[[datetime], int] | None = None,
                  audit: Callable[[str, dict], None] | None = None, have: Callable[[list[str]], set] | None = None,
                  mark: Callable[[Any, str], None] | None = None, server: str | None = None,
                  now: datetime | None = None) -> int:
    """Email one Priority 1 notice to each administrator who has not had it yet. Returns how many emails were sent. Never raises.

    ``recipients`` is the administrators' audience (the sweep builds it with ``_email_audience``). ``state`` is what one sweep may
    spend, {"budget": emails left this hour, "deferred": recipients held back by the cap}; None is a direct call, which reads the
    budget itself. One try per recipient and job: the try is marked with a row whose client id is ``module-job-failed-email:<job id>``,
    so the next tick never sends it again. A recipient with no address, or an address that is refused, is not marked and not sent.
    The host check runs once per job, and only when there is something to send. A refused host or a failed send marks the rest of
    the job's recipients as tried and sends nothing more."""
    try:
        client_id = email_client_id_for(notice)
        audience = _email_audience(recipients or [])
        if client_id is None or not audience:
            return 0
        own = state is None
        if own:
            budget = _email_budget(now or datetime.now(timezone.utc), configured, recent)
            if budget is None:
                return 0
            state = {"budget": budget, "deferred": 0}
        done = (have or _default_existing)([client_id])
        pending = [user for user in audience if (client_id, getattr(user, "pk", user)) not in done]
        if not pending:
            return 0
        subject, body = _email_subject_and_body(notice, server or _server_name())
        counts = {"recipients": 0, "sent": 0, "refused": 0}
        code = "none"
        stopped = False
        host_checked = False
        host_code: str | None = None
        private_relay = False
        # AD-30: the private relay is for Core's own call only. An injected host or send seam is never Core's own call.
        core_seams = host is None and send is None
        for user in pending:
            address = priority_mail.clean_address(getattr(user, "email", ""))
            if address is None:
                counts["recipients"] += 1
                counts["refused"] += 1
                continue
            if stopped:
                counts["recipients"] += 1
                counts["refused"] += 1
                _mark(user, client_id, mark)
                state["budget"] -= 1
                continue
            if state["budget"] <= 0:
                state["deferred"] += 1
                continue
            if not host_checked:
                host_checked = True
                host_code, private_relay = priority_mail.host_check((host or priority_mail.smtp_host)(), core_seams=core_seams)
            counts["recipients"] += 1
            state["budget"] -= 1
            if host_code:
                counts["refused"] += 1
                code, stopped = host_code, True
                _mark(user, client_id, mark)
                continue
            try:
                ok = bool((send or priority_mail.send_one)(address, subject, body))
            except Exception:
                logger.warning("Priority 1 email failed to send (exception).")
                ok = False
            _mark(user, client_id, mark)
            if ok:
                counts["sent"] += 1
            else:
                counts["refused"] += 1
                code, stopped = "send_failed", True
        if host_checked:
            _write_email_audit(notice, counts, code, audit, private_relay)
        if own and state["deferred"]:
            logger.warning("Priority 1 email cap reached: %d email(s) held for a later tick.", state["deferred"])
        return counts["sent"]
    except Exception:
        logger.exception("Priority 1 email failed; Tactical is not affected.")
        return 0


def sweep_failed_jobs(*, now: datetime | None = None, jobs: Iterable[Any] | None = None,
                      recipients_for: Callable[[str], list] | None = None,
                      publish: Callable[[list, dict], int] | None = None,
                      existing: Callable[[list[str]], set] | None = None,
                      configured: Callable[[], bool] | None = None,
                      host: Callable[[], str] | None = None,
                      send: Callable[[str, str, str], bool] | None = None,
                      recent: Callable[[datetime], int] | None = None,
                      audit: Callable[[str, dict], None] | None = None,
                      email_have: Callable[[list[str]], set] | None = None,
                      mark_sent: Callable[[Any, str], None] | None = None) -> int:
    """Raise one notice per failed module job that has none yet, and the Priority 1 email for it (1.17.15; 1.17.25 through Tactical's
    sender). Returns how many notices it stored. Never raises.

    The callables are the seams: the requester's recipients, the notice store, which notices already exist, then the email's
    configured flag, the mail server's name, the one-address sender (returns a bool), the rolling count of marker rows, the count-only
    audit row, which emails were already tried, and the marker. ``recipients_for("")`` is the administrators' audience. The defaults use
    ``tec_tac.notices``, ``priority_mail`` and the ``TecTacUserNotice`` table. The toast goes out first, and the email is a separate step
    that cannot stop it. A job whose recipients all hold its notice already costs one read and no write."""
    stored = 0
    notices = []
    try:
        if jobs is None:
            from . import module_manager_v2 as v2

            jobs = v2._iter_jobs()
        now = now or datetime.now(timezone.utc)
        for job in _bounded_failed_jobs(jobs, now):
            notice = notice_for_job(job)
            if notice is not None:
                notices.append(notice)
        if not notices:
            return 0
        have = (existing or _default_existing)([item["client_id"] for item in notices])
        recipients_for = recipients_for or _default_recipients
        publish = publish or _default_publish
        cache: dict[str, list] = {}
        for notice in notices:
            try:
                if notice["requested_by"] not in cache:
                    cache[notice["requested_by"]] = list(recipients_for(notice["requested_by"]))
                recipients = cache[notice["requested_by"]]
                missing = [user for user in recipients if (notice["client_id"], getattr(user, "pk", user)) not in have]
                if missing:
                    stored += int(publish(missing, notice) or 0)
            except Exception:
                logger.exception("Could not raise the failure notice %s.", notice["client_id"])
    except Exception:
        logger.exception("Module failure notice sweep failed; Tactical is not affected.")
        return stored
    # 1.17.25 (AD-28 amendment): the Priority 1 email, to the administrators only, through Tactical's own sender. After the toast.
    try:
        budget = _email_budget(now, configured, recent)
        if budget is not None:
            audience = _email_audience((recipients_for or _default_recipients)(""))
            state = {"budget": budget, "deferred": 0}
            for notice in notices:
                send_p1_email(notice, audience, state=state, host=host, send=send, audit=audit, have=email_have, mark=mark_sent, now=now)
            if state["deferred"]:
                logger.warning("Priority 1 email cap reached: %d email(s) held for a later tick (%d an hour).", state["deferred"], priority_mail.HOURLY_CAP)
    except Exception:
        logger.exception("Priority 1 email sweep failed; Tactical is not affected.")
    return stored
