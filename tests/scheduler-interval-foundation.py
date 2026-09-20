#!/usr/bin/env python3
"""Small dependency-free regression for Core interval occurrence arithmetic."""
from datetime import datetime, timedelta, timezone

MIN_INTERVAL_SECONDS = 60


def latest(anchor, seconds, now):
    if seconds < MIN_INTERVAL_SECONDS or now < anchor:
        return None
    return anchor + timedelta(seconds=int(((now - anchor).total_seconds()) // seconds) * seconds)


def next_one(anchor, seconds, now):
    if seconds < MIN_INTERVAL_SECONDS:
        return None
    if now <= anchor:
        return anchor
    elapsed = (now - anchor).total_seconds()
    steps = int(elapsed // seconds)
    candidate = anchor + timedelta(seconds=steps * seconds)
    return candidate if candidate >= now else candidate + timedelta(seconds=seconds)


anchor = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
assert latest(anchor, 300, anchor + timedelta(minutes=16, seconds=17)) == anchor + timedelta(minutes=15)
assert next_one(anchor, 300, anchor + timedelta(minutes=16, seconds=17)) == anchor + timedelta(minutes=20)
assert latest(anchor, 60, anchor + timedelta(minutes=3, seconds=59)) == anchor + timedelta(minutes=3)
assert next_one(anchor, 60, anchor + timedelta(minutes=3)) == anchor + timedelta(minutes=3)
assert latest(anchor, 59, anchor + timedelta(minutes=5)) is None
assert next_one(anchor, 59, anchor + timedelta(minutes=5)) is None
print("scheduler interval foundation: PASS")
