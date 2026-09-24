"""Persistent per-user Tec-Tac notice history.

The browser toast remains the immediate delivery surface. This module stores a
bounded, deliberately small copy of user-visible notice content so the shell can
provide durable history without persisting arbitrary runtime metadata.
"""
from __future__ import annotations

import re
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import TecTacUserNotice

LEVELS = frozenset({"info", "success", "warning", "error"})
MAX_NOTICE_HISTORY = 500
NOTICE_RETENTION_DAYS = 30
MAX_LIST_LIMIT = 100
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


class NoticeError(ValueError):
    pass


def _text(value, *, field: str, maximum: int, required: bool = True) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise NoticeError(f"{field} is required.")
    if len(result) > maximum:
        raise NoticeError(f"{field} exceeds {maximum} characters.")
    return result


def _route(value) -> str:
    if value in (None, ""):
        return ""
    route = _text(value, field="action route", maximum=500)
    # Persistent actions are navigation only. Never store javascript:, external
    # URLs, protocol-relative URLs, or control characters as replayable actions.
    if not route.startswith("/") or route.startswith("//") or any(ord(ch) < 32 for ch in route):
        raise NoticeError("action route must be an internal Tec-Tac route beginning with '/'.")
    return route


def normalize_notice(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise NoticeError("notice payload must be an object.")
    level = str(payload.get("level") or "info").strip().lower()
    if level not in LEVELS:
        raise NoticeError(f"unsupported notice level: {level}")
    client_id = str(payload.get("client_id") or "").strip()
    if client_id and not _CLIENT_ID_RE.fullmatch(client_id):
        raise NoticeError("client_id contains unsupported characters.")
    route = _route(payload.get("action_route"))
    action_label = _text(payload.get("action_label"), field="action label", maximum=60, required=False)
    if action_label and not route:
        raise NoticeError("action label requires an action route.")
    return {
        "client_id": client_id,
        "source": _text(payload.get("source") or "core", field="source", maximum=100),
        "level": level,
        "title": _text(payload.get("title"), field="title", maximum=120, required=False),
        "message": _text(payload.get("message"), field="message", maximum=1000),
        "action_label": action_label,
        "action_route": route,
    }


def serialize_notice(row: TecTacUserNotice) -> dict:
    return {
        "id": str(row.id),
        "source": row.source,
        "level": row.level,
        "title": row.title or None,
        "message": row.message,
        "action": ({"label": row.action_label, "route": row.action_route} if row.action_route else None),
        "read": row.read_at is not None,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "read_at": row.read_at.isoformat() if row.read_at else None,
    }


def _prune_user(user_id) -> None:
    cutoff = timezone.now() - timedelta(days=NOTICE_RETENTION_DAYS)
    TecTacUserNotice.objects.filter(user_id=user_id, created_at__lt=cutoff).delete()
    overflow_ids = list(
        TecTacUserNotice.objects.filter(user_id=user_id)
        .order_by("-created_at")
        .values_list("id", flat=True)[MAX_NOTICE_HISTORY:]
    )
    if overflow_ids:
        TecTacUserNotice.objects.filter(user_id=user_id, id__in=overflow_ids).delete()


@transaction.atomic
def store_notice(user, payload: dict) -> tuple[TecTacUserNotice, bool]:
    values = normalize_notice(payload)
    client_id = values.pop("client_id")
    defaults = {**values, "read_at": None}
    if client_id:
        row, created = TecTacUserNotice.objects.update_or_create(
            user=user,
            client_id=client_id,
            defaults=defaults,
        )
    else:
        row = TecTacUserNotice.objects.create(user=user, client_id="", **defaults)
        created = True
    _prune_user(user.pk)
    return row, created


def list_notices(user, *, unread_only: bool = False, limit: int = 50) -> list[dict]:
    try:
        bounded = max(1, min(int(limit), MAX_LIST_LIMIT))
    except (TypeError, ValueError):
        bounded = 50
    query = TecTacUserNotice.objects.filter(user=user)
    if unread_only:
        query = query.filter(read_at__isnull=True)
    return [serialize_notice(row) for row in query.order_by("-created_at")[:bounded]]


def unread_count(user) -> int:
    return TecTacUserNotice.objects.filter(user=user, read_at__isnull=True).count()


def mark_read(user, notice_id) -> bool:
    return bool(
        TecTacUserNotice.objects.filter(user=user, id=notice_id, read_at__isnull=True)
        .update(read_at=timezone.now())
    )


def mark_all_read(user) -> int:
    return TecTacUserNotice.objects.filter(user=user, read_at__isnull=True).update(read_at=timezone.now())


def clear_read(user) -> int:
    deleted, _ = TecTacUserNotice.objects.filter(user=user, read_at__isnull=False).delete()
    return int(deleted)
