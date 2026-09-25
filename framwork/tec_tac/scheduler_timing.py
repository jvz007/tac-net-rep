"""Pure timing helpers for Tec-Tac scheduler recovery decisions.

Kept separate from Django/Celery imports so retry-window edge cases can be
regression-tested without bootstrapping Tactical.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def queued_stale_deadline(
    *,
    queued_at: datetime,
    queued_stale_minutes: int,
    attempt: int = 0,
    retry_delay_seconds: int = 0,
) -> datetime:
    """Return when a queued run may safely be declared stale.

    Initial dispatches use only the configured stale window. A run that has
    already attempted execution and was re-queued for retry first receives its
    full retry countdown, then the same stale-dispatch grace window.
    """
    queued_minutes = max(1, int(queued_stale_minutes or 1))
    retry_wait = max(0, int(retry_delay_seconds or 0)) if int(attempt or 0) > 0 else 0
    return _utc(queued_at) + timedelta(seconds=retry_wait, minutes=queued_minutes)
