#!/usr/bin/python3
"""Root console management for Tec-Tac recovery signing trust.

Exports/imports the public recovery trust identity only. The private signing key
never leaves /etc/tec-tac/recovery-signing through this command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNING_ROOT = Path('/etc/tec-tac/recovery-signing')
TRUST_ROOT = Path('/etc/tec-tac/recovery-trust')
ID_FILE = SIGNING_ROOT / 'installation-id'
PUBLIC_FILE = SIGNING_ROOT / 'public.pem'
AUDIT_FILE = Path('/var/log/tec-tac/recovery-audit.jsonl')
SAFE_ID = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')


def now():
    return datetime.now(timezone.utc).isoformat()


def require_root():
    if os.geteuid() != 0 and os.environ.get('TEC_TAC_TEST_ALLOW_NONROOT') != '1':
        raise RuntimeError('tec-tac-recovery-key must be run as root (normally via sudo)')


def _public_identity(key_id: str, pem: bytes, *, server_name=None, exported_at=None):
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError('recovery public key is not Ed25519')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        'schema': 1,
        'artifact_type': 'tec-tac-recovery-public-key',
        'installation_id': key_id,
        'key_id': key_id,
        'server_name': server_name or socket.gethostname(),
        'public_key_sha256': hashlib.sha256(raw).hexdigest(),
        'public_key_pem': pem.decode('ascii'),
        'exported_at': exported_at or now(),
    }


def local_identity():
    key_id = ID_FILE.read_text(encoding='utf-8').strip()
    if not SAFE_ID.fullmatch(key_id):
        raise RuntimeError('local recovery installation id is invalid')
    st = PUBLIC_FILE.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('local recovery public key file is unsafe')
    return _public_identity(key_id, PUBLIC_FILE.read_bytes())


def append_audit(event, **detail):
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(AUDIT_FILE.parent, 0o750)
    try: os.chown(AUDIT_FILE.parent, 0, 0)
    except PermissionError: pass
    row = {'at': now(), 'event': event, 'actor': os.environ.get('SUDO_USER') or os.environ.get('USER') or 'root', **detail}
    fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o640)
    try:
        os.fchmod(fd, 0o640)
        try: os.fchown(fd, 0, 0)
        except PermissionError: pass
        os.write(fd, (json.dumps(row, sort_keys=True) + '\n').encode('utf-8'))
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_status(_args):
    data = local_identity(); data.pop('public_key_pem', None)
    data['trusted_key_path'] = str(TRUST_ROOT / f"{data['key_id']}.pub")
    print(json.dumps(data, indent=2, sort_keys=True))


def cmd_export(args):
    data = local_identity()
    text = json.dumps(data, indent=2, sort_keys=True) + '\n'
    if args.path == '-':
        sys.stdout.write(text)
    else:
        target = Path(args.path).expanduser().resolve()
        target.write_text(text, encoding='utf-8')
        os.chmod(target, 0o644)
        print(target)
    append_audit('recovery_public_key_exported', key_id=data['key_id'], public_key_sha256=data['public_key_sha256'], path=args.path)


def cmd_import(args):
    source = Path(args.path).expanduser().resolve()
    payload = json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(payload, dict) or int(payload.get('schema') or 0) != 1 or payload.get('artifact_type') != 'tec-tac-recovery-public-key':
        raise RuntimeError('recovery public-key export format is invalid')
    key_id = str(payload.get('key_id') or payload.get('installation_id') or '').strip()
    if not SAFE_ID.fullmatch(key_id):
        raise RuntimeError('recovery key id is invalid')
    pem = str(payload.get('public_key_pem') or '').encode('ascii')
    identity = _public_identity(key_id, pem, server_name=payload.get('server_name'), exported_at=payload.get('exported_at'))
    expected = str(payload.get('public_key_sha256') or '').lower()
    if expected != identity['public_key_sha256']:
        raise RuntimeError('recovery public-key fingerprint does not match export metadata')
    TRUST_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(TRUST_ROOT, 0o755)
    try: os.chown(TRUST_ROOT, 0, 0)
    except PermissionError: pass
    target = TRUST_ROOT / f'{key_id}.pub'
    if target.exists():
        if target.is_symlink() or target.read_bytes() != pem:
            raise RuntimeError('recovery trust key id already exists with different key material')
        print(f'already trusted: {key_id} {expected}')
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
    try:
        os.write(fd, pem); os.fsync(fd); os.fchmod(fd, 0o644)
        try: os.fchown(fd, 0, 0)
        except PermissionError: pass
    finally:
        os.close(fd)
    append_audit('recovery_public_key_imported', key_id=key_id, public_key_sha256=expected, source=str(source), source_server=identity.get('server_name'))
    print(f'trusted: {key_id} {expected}')


def main():
    require_root()
    parser = argparse.ArgumentParser(prog='tec-tac-recovery-key')
    sub = parser.add_subparsers(dest='command', required=True)
    status = sub.add_parser('status'); status.set_defaults(func=cmd_status)
    export = sub.add_parser('export'); export.add_argument('path', help="Output JSON path or '-' for stdout"); export.set_defaults(func=cmd_export)
    imp = sub.add_parser('import'); imp.add_argument('path', help='Public-key export JSON file'); imp.set_defaults(func=cmd_import)
    args = parser.parse_args(); args.func(args)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)
