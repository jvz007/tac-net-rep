"""Core's access-change hook (core.access_events 1.0.0, Core 1.18.50).

Core tells the rest of the system WHICH PEOPLE are affected when a role's permissions or its client and site scope change, or when a user's
role, active flag, superuser flag or dashboard block changes or the user is deleted. It never says what the change was.

Three public things:

* ``access_changed``: a Django Signal. It is sent with ``user_ids`` (a frozenset of ints) and ``reason`` (one of REASONS). It is sent with
  ``send_robust``, so a faulty receiver never stops the others and never stops Tactical's own save. It fires in the process that saved the
  change (a web worker or a Celery worker), not in the ASGI process that holds a tunnel socket.
* ``changed_at(user_id)``: the time of the newest change for one person, or None. It is read from the shared Django cache, so any process
  can ask. This is how Core's tunnel relay (another process) learns of a change within one 5-second tick.
* ``notify_access_changed(user_ids, reason)``: Core's own call, used by the receivers below. It is not offered through the capability: a
  module cannot make Core re-check people.

Not covered, by design: changes that fire no Django signal (queryset.update, raw SQL) and a deleted site or client. Those wait for the
5-minute re-check, which stays as the backstop.

Nothing here reads, stores or logs what a person may or may not do. A marker is a person's id and a time.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from django.dispatch import Signal

logger = logging.getLogger("tec_tac.access_events")

CAPABILITY_ID = "core.access_events"
CAPABILITY_VERSION = "1.0.0"

REASONS = ("role_permissions", "role_scope", "user_changed", "user_removed")
MARKER_PREFIX = "tec-tac:access:chg:"
MARKER_SECONDS = 6 * 3600  # above the tunnel hard cap (4 hours): a session can never outlive the marker that would end it
MAX_USER_IDS = 5000
USER_FIELDS = frozenset({"role", "role_id", "is_active", "is_superuser", "block_dashboard_login"})
ROLE_CACHE_PREFIX = "role_"  # Tactical's own prefix (tacticalrmm.constants.ROLE_CACHE_PREFIX); read from there when it imports
OPERATIONS = ("access_changed", "changed_at")

access_changed = Signal()


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
    """The time (seconds since the epoch) of the newest access change for one person, or None. Cache only; a cache fault answers None."""
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
        responses = access_changed.send_robust(sender="core", user_ids=frozenset(ids), reason=reason)
    except Exception:
        logger.warning("The access_changed signal could not be sent.", exc_info=True)
        return
    for receiver, outcome in responses or ():
        if isinstance(outcome, Exception):
            logger.warning("A receiver of access_changed failed (%s); the others were still told.", getattr(receiver, "__name__", "receiver"))


def notify_access_changed(user_ids, reason: str) -> int:
    """Mark and announce the people whose access changed. Returns how many ids were taken (0 when none, or the reason is not listed).
    Inside a transaction the work runs when it commits, so a re-check never reads state that is not yet saved. Never raises."""
    try:
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
    not a change of a person's access, so no module is told. Returns how many markers were written; never raises."""
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


# ------------------------------------------------------------------------------------------------ the capability
class AccessEventsProvider:
    """The provider of core.access_events. ``access_changed`` is the Signal; ``changed_at`` reads one marker."""

    access_changed = access_changed

    def changed_at(self, *, user_id):
        return changed_at(user_id)


_PROVIDER = AccessEventsProvider()


def access_events_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": list(OPERATIONS),
        "signal": "tec_tac.access_events.access_changed: a Django Signal. Receivers get user_ids (a frozenset of ints) and reason (one of " + ", ".join(REASONS) + "). It says who, never what. Sent with send_robust, after the transaction commits, in the process that saved the change (a web or Celery worker).",
        "changed_at": "changed_at(user_id) -> float | None. The time of the newest change for that person, from the shared Django cache, readable from any process. None when there is none, or the cache cannot be read.",
        "fires_on": "A role's permissions saved or deleted; a role's client or site list changed (either side of the many-to-many); a Tec-Tac extension permission of a role saved or deleted; a user's role, active flag, superuser flag or dashboard block changed (a save that names other fields only does not fire); a user deleted.",
        "does_not_fire_on": "Changes that fire no Django signal (queryset.update, raw SQL) and a deleted site or client. The 5-minute re-check of a live tunnel session stays as the backstop for those.",
        "core_does_not": "Core does not say what changed, keep a history, or offer a way for a module to raise the signal. Core's tunnel relay uses it only to run its own re-check early.",
        "added_in": "1.0.0 (Core 1.18.50, framework >=1.18.50).",
    }


def register_core_access_events_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Which people are affected when a role's permissions or client and site scope, or a user's role or active state, change: a signal and a read of the newest change time.",
        operations=OPERATIONS,
        metadata=access_events_contract_metadata(),
    )
