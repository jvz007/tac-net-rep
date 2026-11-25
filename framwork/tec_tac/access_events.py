"""Core's access-change hook (Core-internal since Core 1.18.51; it is not a capability and no module may use it).

Core marks WHICH PEOPLE are affected when a role's permissions or its client and site scope change, or when a user's role, active flag,
superuser flag or dashboard block changes or the user is deleted. It never says what the change was. Core's own tunnel relay reads the marker
to re-check a live Console session within one 5-second tick instead of waiting for the 5-minute re-check.

Core 1.18.50 offered this to every module as core.access_events. The 1.18.50 review found that this gave every module a cross-user read
without a signed decision, so 1.18.51 registers no capability, publishes no contract row and exposes no Signal. Johan decided on 25 November 2026 that modules may listen only in a
declared form, built the first time a module needs it; until then this stays Core-only (reviews/questions/core.md).

What is here:

* ``_access_changed``: a private Django Signal. Core has no consumer of it today. It is sent with ``send_robust``, so a faulty receiver never
  stops the others and never stops Tactical's own save. It fires in the process that saved the change (a web worker or a Celery worker).
* ``changed_at(user_id)``: the time of the newest change for one person, or None. It reads the shared Django cache, so Core's tunnel relay
  (another process) learns of a change within one tick. It answers only when its first caller outside this file is Core's tunnel code
  (``probe_tunnel.access_changed_at``); any other caller gets None.
* ``notify_access_changed(user_ids, reason)``: used by the receivers below. It accepts only a call that comes from Django's own signal
  dispatcher (Core's model receivers).
* ``mark_changed(user_ids)``: used by ``probe_tunnel.update_site`` only, when an owner moves a probe to another site.

What is enforced, in plain words. Each writer and the reader judge their caller from the call stack, by the real path of the first frame
outside this file. A frame of an installed, enabled module is refused (the verified-identity helper of tec_tac.caller_identity), and so is
every frame that is not on the short list above: a library frame such as threading or a functools.partial run by Core's Scheduler is refused
too. A refusal changes nothing (a writer returns 0, the reader None) and logs one warning a minute. An unverifiable check refuses.
What is not enforced: hostile code that reaches private underscore names, forges a file name, calls Django's own model signals itself or
writes the shared cache key directly. That is a signed-module-review matter, the same limit as docs/caller-identity.md.

Not covered, by design: changes that fire no Django signal (queryset.update, raw SQL) and a deleted site or client. Those wait for the
5-minute re-check, which stays as the backstop.

Nothing here reads, stores or logs what a person may or may not do. A marker is a person's id and a time.
"""
from __future__ import annotations

import logging
import os
import sys
import time

from django.dispatch import Signal

logger = logging.getLogger("tec_tac.access_events")

SCOPE = "core-internal"  # not a capability: nothing is registered, nothing is exported

REASONS = ("role_permissions", "role_scope", "user_changed", "user_removed")
MARKER_PREFIX = "tec-tac:access:chg:"
MARKER_SECONDS = 6 * 3600  # above the tunnel hard cap (4 hours): a session can never outlive the marker that would end it
MAX_USER_IDS = 5000
USER_FIELDS = frozenset({"role", "role_id", "is_active", "is_superuser", "block_dashboard_login"})
ROLE_CACHE_PREFIX = "role_"  # Tactical's own prefix (tacticalrmm.constants.ROLE_CACHE_PREFIX); read from there when it imports
WARN_SECONDS = 60  # a refused caller is logged once a minute at most, so a loop cannot flood the log

_access_changed = Signal()  # private: no public Signal name; a future Core consumer connects here


# ------------------------------------------------------------------------------------------------ the caller check
_THIS_FILE = os.path.normcase(os.path.realpath(__file__))
_TUNNEL_FILE = os.path.normcase(os.path.realpath(os.path.join(os.path.dirname(__file__), "probe_tunnel.py")))
_LAST_WARN = [0.0]
_TEST_ALLOWED: set[str] = set()  # test seam only (see _allow_caller_for_tests); empty in a running Core

# the one first caller each function accepts: ("dispatcher" = Django's signal dispatcher, "tunnel" = probe_tunnel.py) and its function name
_ALLOWED = {
    "notify_access_changed": ("dispatcher", None),
    "mark_changed": ("tunnel", "update_site"),
    "changed_at": ("tunnel", "access_changed_at"),
}


def _real(path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _dispatcher_file() -> str | None:
    module = sys.modules.get("django.dispatch.dispatcher")
    path = getattr(module, "__file__", None)
    return _real(path) if path else None


def _allow_caller_for_tests(path) -> None:
    """Test seam: name a file whose frames count as an allowed Core caller. Nothing in Core calls this."""
    _TEST_ALLOWED.add(_real(path))


def clear_callers_for_tests() -> None:
    _TEST_ALLOWED.clear()
    _LAST_WARN[0] = 0.0


def _refusal_reason() -> str:
    """Whether a verified module made the call (the identity helper reads the module list from disk, so it runs only for a log line)."""
    from .caller_identity import calling_module_for_core_provider

    # frame 1 of the helper is this function, which sits in this file: every frame of this file is skipped, so the caller is judged
    return "a module called it" if calling_module_for_core_provider(provider_file=__file__) is not None else "not a Core caller"


def _refuse(name: str, why) -> None:
    """One warning a minute at most (a reader is only logged at debug, it runs every tick). ``why`` is text or a function that gives it."""
    if name == "changed_at":
        logger.debug("access_events.%s refused a caller.", name)
        return
    now = time.time()
    if now - _LAST_WARN[0] < WARN_SECONDS:
        return
    _LAST_WARN[0] = now
    try:
        why = why() if callable(why) else why
    except Exception:
        logger.debug("The refused caller could not be described.", exc_info=True)
        why = "the caller could not be verified"
    logger.warning("access_events.%s refused a caller (%s); nothing was changed.", name, why)


def _caller_allowed(name: str) -> bool:
    """True only when the first frame outside this file is on the short Core list for ``name`` and is not a module's code. Any fault refuses."""
    try:
        getter = getattr(sys, "_getframe", None)
        if getter is None:
            _refuse(name, "the call stack cannot be read")
            return False
        frame = getter(1)
        while frame is not None and _real(frame.f_code.co_filename) == _THIS_FILE:
            frame = frame.f_back
        if frame is None:
            _refuse(name, "no caller frame")
            return False
        path, function = _real(frame.f_code.co_filename), frame.f_code.co_name
        kind, wanted = _ALLOWED[name]
        known = _dispatcher_file() if kind == "dispatcher" else _TUNNEL_FILE
        if path in _TEST_ALLOWED or (known is not None and path == known and (wanted is None or function == wanted)):
            return True  # a Core file: never a module's code, so the module lookup (a disk scan) is not needed on the hot path
        _refuse(name, _refusal_reason)  # refused; the reason (a module lookup) is worked out only when a log line is due
        return False
    except Exception:
        logger.debug("The caller check could not be completed; refusing.", exc_info=True)
        _refuse(name, "the check could not be completed")
        return False


# ------------------------------------------------------------------------------------------------ the marker
def _cache():
    from django.core.cache import cache

    return cache


def marker_key(user_id: int) -> str:
    return f"{MARKER_PREFIX}{int(user_id)}"


def _clean_ids(user_ids) -> list[int]:
    """Positive ints only (a bool is not an id), without repeats, in order, at most MAX_USER_IDS."""
    try:
        items = list(user_ids)
    except TypeError:
        return []
    seen: dict[int, None] = {}
    for item in items:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            continue
        seen[item] = None
        if len(seen) >= MAX_USER_IDS:
            break
    return list(seen)


def changed_at(user_id) -> float | None:
    """The time (seconds since the epoch) of the newest access change for one person, or None. Cache only; a cache fault answers None.
    Core-internal: answers only when the first caller outside this file is Core's tunnel code; any other caller gets None."""
    if not _caller_allowed("changed_at"):
        return None
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        return None
    try:
        value = _cache().get(marker_key(user_id))
    except Exception:
        logger.debug("An access marker could not be read.", exc_info=True)
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _in_transaction() -> bool:
    try:
        from django.db import transaction

        return bool(transaction.get_connection().in_atomic_block)
    except Exception:
        logger.debug("The transaction state could not be read; delivering at once.", exc_info=True)
        return False


def _deliver(ids: list[int], reason: str) -> None:
    cache, now = _cache(), time.time()
    for user_id in ids:
        try:
            cache.set(marker_key(user_id), now, MARKER_SECONDS)
        except Exception:
            logger.warning("An access marker could not be written; the 5-minute re-check is the backstop.", exc_info=True)
            break
    try:
        responses = _access_changed.send_robust(sender="core", user_ids=frozenset(ids), reason=reason)
    except Exception:
        logger.warning("The access change signal could not be sent.", exc_info=True)
        return
    for receiver, outcome in responses or ():
        if isinstance(outcome, Exception):
            logger.warning("A receiver of the access change signal failed (%s); the others were still told.", getattr(receiver, "__name__", "receiver"))


def notify_access_changed(user_ids, reason: str) -> int:
    """Mark and announce the people whose access changed. Returns how many ids were taken (0 when none, or the reason is not listed).
    Inside a transaction the work runs when it commits, so a re-check never reads state that is not yet saved. Never raises.
    Core-internal: a call from anywhere but Django's own signal dispatcher (Core's model receivers) is refused and returns 0."""
    try:
        if not _caller_allowed("notify_access_changed"):
            return 0
        if reason not in REASONS:
            return 0
        ids = _clean_ids(user_ids)
        if not ids:
            return 0
        if _in_transaction():
            from django.db import transaction

            transaction.on_commit(lambda: _deliver(ids, reason))
        else:
            _deliver(ids, reason)
        return len(ids)
    except Exception:
        logger.warning("An access change could not be announced; the 5-minute re-check is the backstop.", exc_info=True)
        return 0


def mark_changed(user_ids) -> int:
    """Core's own use only (the tunnel relay, when an owner moves a probe to another site): write the markers, send no signal. A site move is
    not a change of a person's access, so no module is told. Returns how many markers were written; never raises. Core-internal: a call
    from anywhere but probe_tunnel.update_site is refused and returns 0."""
    if not _caller_allowed("mark_changed"):
        return 0
    ids = _clean_ids(user_ids)
    written, now = 0, time.time()
    for user_id in ids:
        try:
            _cache().set(marker_key(user_id), now, MARKER_SECONDS)
            written += 1
        except Exception:
            logger.warning("An access marker could not be written; the 5-minute re-check is the backstop.", exc_info=True)
            break
    return written


# ------------------------------------------------------------------------------------------------ the receivers (Tactical's models)
def _safe(func):
    """A receiver of a Django signal never raises into Tactical's save or delete."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            logger.warning("An access-change receiver failed (%s); Tactical's own change is not affected.", func.__name__, exc_info=True)
            return None
    wrapper.__name__ = func.__name__
    return wrapper


def _role_cache_prefix() -> str:
    try:
        from tacticalrmm.constants import ROLE_CACHE_PREFIX as prefix

        return str(prefix)
    except Exception:
        logger.debug("Tactical's role cache prefix could not be read; using the known one.", exc_info=True)
        return ROLE_CACHE_PREFIX


def _users_of_role(role_id) -> list[int]:
    from accounts.models import User

    return list(User.objects.filter(role_id=role_id).values_list("pk", flat=True))


def _forget_role(*names) -> None:
    """Tactical caches a role for 600 seconds under role_<name> and clears it when the role is saved, but its editor sets the client and
    site lists after that save: clear it again, so a re-check cannot read the old role."""
    cache, prefix = _cache(), _role_cache_prefix()
    for name in names:
        if name:
            cache.delete(f"{prefix}{name}")


@_safe
def _on_role_saved(sender, instance, created=False, **kwargs):
    if created:
        return
    notify_access_changed(_users_of_role(instance.pk), "role_permissions")


@_safe
def _on_role_deleting(sender, instance, **kwargs):
    # pre_delete: the delete empties each user's role, so the people are collected first
    notify_access_changed(_users_of_role(instance.pk), "role_permissions")


def _scope_receiver(accessor: str):
    """m2m_changed receiver for Role.can_view_clients (accessor role_clients) or Role.can_view_sites (role_sites), forward and reverse."""
    @_safe
    def receiver(sender, instance, action, reverse=False, pk_set=None, **kwargs):
        from accounts.models import Role

        if action not in ("post_add", "post_remove", "post_clear", "pre_clear"):
            return
        if not reverse:  # instance is the Role
            if action == "pre_clear":
                return
            _forget_role(getattr(instance, "name", None))
            notify_access_changed(_users_of_role(instance.pk), "role_scope")
            return
        # reverse: instance is a Client or a Site and pk_set holds role ids; a clear carries none, so read them before it happens
        if action == "pre_clear":
            role_ids = list(getattr(instance, accessor).values_list("pk", flat=True))
        elif action == "post_clear":
            return
        else:
            role_ids = list(pk_set or ())
        if not role_ids:
            return
        _forget_role(*Role.objects.filter(pk__in=role_ids).values_list("name", flat=True))
        people: list[int] = []
        for role_id in role_ids:
            people.extend(_users_of_role(role_id))
        notify_access_changed(people, "role_scope")
    receiver.__name__ = f"_on_{accessor}_changed"
    return receiver


@_safe
def _on_extension_permission_changed(sender, instance, created=False, **kwargs):
    if created:
        return
    notify_access_changed(_users_of_role(instance.role_id), "role_permissions")


@_safe
def _on_user_saved(sender, instance, created=False, update_fields=None, **kwargs):
    if created:
        return
    if update_fields is not None and not (set(update_fields) & USER_FIELDS):
        return  # a last_login or preference save changes nothing a re-check reads
    notify_access_changed([instance.pk], "user_changed")


@_safe
def _on_user_deleted(sender, instance, **kwargs):
    notify_access_changed([instance.pk], "user_removed")


def connect_receivers() -> bool:
    """Connect the receivers to Tactical's models, once (a fixed dispatch_uid makes a second call change nothing). Called from
    AppConfig.ready() in its own guarded block. Imports Tactical's models here, never at import time."""
    from accounts.models import Role, User
    from django.db.models.signals import m2m_changed, post_delete, post_save, pre_delete

    from .models import ExtensionRolePermission

    uid = "tec-tac-access-events"
    post_save.connect(_on_role_saved, sender=Role, weak=False, dispatch_uid=f"{uid}-role-save")
    pre_delete.connect(_on_role_deleting, sender=Role, weak=False, dispatch_uid=f"{uid}-role-delete")
    for field, accessor in ((Role.can_view_clients, "role_clients"), (Role.can_view_sites, "role_sites")):
        m2m_changed.connect(_scope_receiver(accessor), sender=field.through, weak=False, dispatch_uid=f"{uid}-{accessor}")
    post_save.connect(_on_extension_permission_changed, sender=ExtensionRolePermission, weak=False, dispatch_uid=f"{uid}-perm-save")
    post_delete.connect(_on_extension_permission_changed, sender=ExtensionRolePermission, weak=False, dispatch_uid=f"{uid}-perm-delete")
    post_save.connect(_on_user_saved, sender=User, weak=False, dispatch_uid=f"{uid}-user-save")
    post_delete.connect(_on_user_deleted, sender=User, weak=False, dispatch_uid=f"{uid}-user-delete")
    return True
