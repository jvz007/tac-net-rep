#!/usr/bin/python3
"""Root-console trust-policy management for Tec-Tac.

Lowering the package/update trust floor is intentionally a console operation.
This tool relies on normal sudo authentication, records a root-owned audit log,
and schedules automatic restoration of the previous policy via systemd.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

POLICY_ROOT = Path('/etc/tec-tac/policy')
POLICY_FILE = POLICY_ROOT / 'update-trust-policy.json'
PENDING_FILE = POLICY_ROOT / 'pending-trust-policy-revert.json'
AUDIT_DIR = Path('/var/log/tec-tac')
AUDIT_FILE = AUDIT_DIR / 'trust-policy-audit.jsonl'
LEVELS = ('unsigned', 'signed_development', 'signed_production', 'secure_signed')
LEVEL_RANK = {name: idx for idx, name in enumerate(LEVELS)}
DEFAULT_HOURS = 8
MAX_HOURS = 168


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat().replace('+00:00', 'Z')


def require_root() -> None:
    if os.geteuid() != 0 and os.environ.get('TEC_TAC_TEST_ALLOW_NONROOT') != '1':
        raise RuntimeError('tec-tac-trust-policy must be run as root (normally via sudo)')


def actor() -> str:
    return str(os.environ.get('SUDO_USER') or os.environ.get('USER') or 'root')[:150]


def read_policy() -> dict:
    try:
        payload = json.loads(POLICY_FILE.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise RuntimeError(f'trust policy file is missing: {POLICY_FILE}') from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f'trust policy file is unreadable: {exc}') from exc
    if not isinstance(payload, dict) or int(payload.get('schema', 0) or 0) != 1:
        raise RuntimeError('trust policy schema is invalid')
    level = str(payload.get('minimum_level') or '').strip().lower()
    if level not in LEVEL_RANK:
        raise RuntimeError('trust policy level is invalid')
    return payload


def write_policy(level: str, *, updated_by: str) -> dict:
    if level not in LEVEL_RANK:
        raise RuntimeError('invalid trust policy level')
    POLICY_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(POLICY_ROOT, 0, 0)
    os.chmod(POLICY_ROOT, 0o755)
    payload = {
        'schema': 1,
        'minimum_level': level,
        'updated_at': iso(),
        'updated_by': str(updated_by or actor())[:150],
    }
    tmp = POLICY_FILE.with_name(POLICY_FILE.name + '.tmp')
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o644)
    os.replace(tmp, POLICY_FILE)
    return payload


def append_audit(event: str, **detail) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(AUDIT_DIR, 0, 0)
    os.chmod(AUDIT_DIR, 0o750)
    row = {'at': iso(), 'event': event, 'actor': actor(), **detail}
    fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    try:
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'a', encoding='utf-8', closefd=False) as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(json.dumps(row, sort_keys=True) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_pending() -> dict | None:
    if not PENDING_FILE.is_file():
        return None
    try:
        payload = json.loads(PENDING_FILE.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def write_pending(payload: dict) -> None:
    tmp = PENDING_FILE.with_name(PENDING_FILE.name + '.tmp')
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PENDING_FILE)


def clear_pending() -> None:
    PENDING_FILE.unlink(missing_ok=True)


def parse_iso(value: str) -> datetime:
    text = str(value or '').strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RuntimeError('pending trust-policy revert expires_at is invalid') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def check_revert_due() -> dict:
    pending = read_pending()
    if not pending:
        return {'status': 'no_pending_revert'}
    change_id = str(pending.get('change_id') or '').strip()
    if not change_id:
        raise RuntimeError('pending trust-policy revert is missing change_id')
    expires_at = parse_iso(str(pending.get('expires_at') or ''))
    if now() < expires_at:
        return {
            'status': 'pending',
            'change_id': change_id,
            'expires_at': iso(expires_at),
            'temporary_level': pending.get('temporary_level'),
            'previous_level': pending.get('previous_level'),
        }
    return revert_due(change_id)


def confirm(current: str, target: str, hours: int, reason: str) -> None:
    if not sys.stdin.isatty():
        raise RuntimeError('interactive confirmation is required; run this command from a terminal')
    print(f'Current trust floor : {current}')
    print(f'Requested floor     : {target}')
    print(f'Automatic revert    : {hours} hour(s)')
    print(f'Reason              : {reason}')
    phrase = f'LOWER TO {target}'
    entered = input(f'Type "{phrase}" to continue: ').strip()
    if entered != phrase:
        raise RuntimeError('confirmation did not match; policy was not changed')


def set_level(target: str, *, reason: str, hours: int) -> dict:
    current_payload = read_policy()
    current = str(current_payload['minimum_level'])
    target = str(target or '').strip().lower()
    if target not in LEVEL_RANK:
        raise RuntimeError('invalid trust policy level')
    reason = str(reason or '').strip()
    if not reason:
        raise RuntimeError('--reason is required')
    if len(reason) > 500:
        raise RuntimeError('--reason must be 500 characters or fewer')
    if hours < 1 or hours > MAX_HOURS:
        raise RuntimeError(f'--hours must be between 1 and {MAX_HOURS}')

    lowering = LEVEL_RANK[target] < LEVEL_RANK[current]
    if lowering:
        confirm(current, target, hours, reason)

    existing_pending = read_pending()
    previous_level = current
    if lowering and existing_pending:
        pending_previous = str(existing_pending.get('previous_level') or '')
        if pending_previous in LEVEL_RANK and LEVEL_RANK[pending_previous] > LEVEL_RANK[previous_level]:
            previous_level = pending_previous

    updated = write_policy(target, updated_by=f'console:{actor()}')
    append_audit(
        'policy_changed_console', previous_level=current, requested_level=target,
        reason=reason, temporary=lowering, hours=hours if lowering else None,
    )

    if not lowering:
        clear_pending()
        return {**updated, 'status': 'applied', 'temporary': False}

    change_id = uuid.uuid4().hex
    expires = now() + timedelta(hours=hours)
    pending = {
        'schema': 1,
        'change_id': change_id,
        'previous_level': previous_level,
        'temporary_level': target,
        'created_at': iso(),
        'expires_at': iso(expires),
        'reason': reason,
        'actor': actor(),
    }
    write_pending(pending)
    append_audit('policy_revert_scheduled', change_id=change_id, requested_level=target, previous_level=previous_level, expires_at=iso(expires), hours=hours)
    return {**updated, 'status': 'applied', 'temporary': True, 'revert_at': iso(expires), 'revert_level': previous_level, 'change_id': change_id}


def revert_due(change_id: str) -> dict:
    pending = read_pending()
    if not pending or str(pending.get('change_id') or '') != str(change_id or ''):
        return {'status': 'superseded_or_missing'}
    previous = str(pending.get('previous_level') or '')
    temporary = str(pending.get('temporary_level') or '')
    if previous not in LEVEL_RANK or temporary not in LEVEL_RANK:
        raise RuntimeError('pending trust-policy revert is invalid')
    current = str(read_policy()['minimum_level'])
    # Never auto-revert by lowering a policy that an administrator has since
    # raised above the original level.
    if LEVEL_RANK[current] > LEVEL_RANK[previous]:
        append_audit('policy_auto_revert_skipped', change_id=change_id, current_level=current, previous_level=previous, reason='current policy is stronger than original policy')
        clear_pending()
        return {'status': 'skipped', 'current_level': current}
    restored = write_policy(previous, updated_by='system:auto-revert')
    clear_pending()
    append_audit('policy_auto_reverted', change_id=change_id, from_level=current, restored_level=previous)
    return {**restored, 'status': 'reverted', 'from_level': current}


def main() -> int:
    parser = argparse.ArgumentParser(prog='tec-tac-trust-policy', description='Manage the root-owned Tec-Tac package/update trust floor.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('get', help='Show the current root-owned trust policy.')
    p = sub.add_parser('set', help='Change the trust floor from a root console.')
    p.add_argument('level', choices=LEVELS)
    p.add_argument('--reason', required=True, help='Reason for the policy change (recorded in the root audit log).')
    p.add_argument('--hours', type=int, default=DEFAULT_HOURS, help=f'Hours before automatic revert when lowering (default {DEFAULT_HOURS}, max {MAX_HOURS}).')
    sub.add_parser('check-revert', help='Apply a pending temporary trust-policy revert when it is due.')
    p = sub.add_parser('_revert', help=argparse.SUPPRESS)
    p.add_argument('--change-id', required=True)
    args = parser.parse_args()
    require_root()
    if args.command == 'get':
        result = read_policy()
        pending = read_pending()
        if pending:
            result = {**result, 'pending_revert': pending}
    elif args.command == 'set':
        result = set_level(args.level, reason=args.reason, hours=args.hours)
    elif args.command == 'check-revert':
        result = check_revert_due()
    else:
        result = revert_due(args.change_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
