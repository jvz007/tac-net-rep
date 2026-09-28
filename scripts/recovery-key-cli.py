#!/usr/bin/python3 -I
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
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_CONFIG = Path('/opt/tec-tac/etc/tec-tac.conf')
CONFIG_POINTER = Path('/etc/tec-tac/config-path')
AUDIT_FILE = Path('/var/log/tec-tac/recovery-audit.jsonl')
SAFE_ID = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')


def _read_bounded_fd(fd: int, max_bytes: int = 1024 * 1024) -> bytes:
    chunks = []
    remaining = max_bytes + 1
    while remaining > 0:
        block = os.read(fd, min(65536, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    data = b''.join(chunks)
    if len(data) > max_bytes:
        raise RuntimeError('trusted recovery configuration file is unexpectedly large')
    return data


def _read_root_regular(path: Path, *, max_bytes: int = 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f'root-owned recovery file is unsafe or unreadable: {path}') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022):
            raise RuntimeError(f'recovery file must be root-owned regular and not group/world writable: {path}')
        return _read_bounded_fd(fd, max_bytes=max_bytes)
    finally:
        os.close(fd)




def _read_import_regular(path: Path, *, max_bytes: int = 256 * 1024) -> bytes:
    raw = path.expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(raw, flags)
    except OSError as exc:
        raise RuntimeError(f'recovery import source must be a readable regular file: {raw}') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f'recovery import source must be a regular file: {raw}')
        return _read_bounded_fd(fd, max_bytes=max_bytes)
    finally:
        os.close(fd)

def _installed_config_path(pointer: Path = CONFIG_POINTER, default: Path = DEFAULT_CONFIG) -> Path:
    try:
        raw = _read_root_regular(pointer, max_bytes=4096).decode('utf-8').strip()
    except RuntimeError:
        if not os.path.lexists(pointer):
            return default
        raise
    path = Path(raw)
    if not raw or '\n' in raw or '\r' in raw or not path.is_absolute():
        raise RuntimeError(f'Tec-Tac config-path pointer is invalid: {pointer}')
    return path


def _root_layout(pointer: Path = CONFIG_POINTER, default: Path = DEFAULT_CONFIG) -> dict[str, str]:
    config = _installed_config_path(pointer=pointer, default=default)
    if not os.path.lexists(config):
        return {}
    text = _read_root_regular(config).decode('utf-8')
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip()
    return values


def _absolute_layout_path(layout: dict[str, str], key: str, default: str) -> Path:
    path = Path(str(layout.get(key) or default))
    if not path.is_absolute():
        raise RuntimeError(f'{key} must be absolute in the root-owned Tec-Tac config')
    return path


def _trusted_root_dir(path: Path, *, create: bool = False, mode: int = 0o755) -> None:
    parent = path.parent
    try:
        parent_info = parent.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f'recovery trust directory parent is missing: {parent}') from exc
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or (parent_info.st_mode & 0o022)
    ):
        raise RuntimeError(
            f'recovery trust directory parent must be root-owned, real, and not group/world writable: {parent}'
        )
    if create and not os.path.lexists(path):
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
        try:
            os.chown(path, 0, 0)
        except PermissionError:
            pass
        os.chmod(path, mode)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f'recovery trust directory is missing: {path}') from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022):
        raise RuntimeError(f'recovery trust directory must be root-owned, real, and not group/world writable: {path}')


_LAYOUT = _root_layout()
_SIGNING_KEY = _absolute_layout_path(_LAYOUT, 'TEC_TAC_RECOVERY_SIGNING_KEY', '/etc/tec-tac/recovery-signing/private.pem')
SIGNING_ROOT = _SIGNING_KEY.parent
TRUST_ROOT = _absolute_layout_path(_LAYOUT, 'TEC_TAC_RECOVERY_TRUST_ROOT', '/etc/tec-tac/recovery-trust')
ID_FILE = SIGNING_ROOT / 'installation-id'
PUBLIC_FILE = SIGNING_ROOT / 'public.pem'


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
    key_id = _read_root_regular(ID_FILE, max_bytes=4096).decode('utf-8').strip()
    if not SAFE_ID.fullmatch(key_id):
        raise RuntimeError('local recovery installation id is invalid')
    pem = _read_root_regular(PUBLIC_FILE, max_bytes=64 * 1024)
    return _public_identity(key_id, pem)


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


def _atomic_write_public_export(path: Path, text: str) -> Path:
    raw = path.expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    parent = raw.parent.resolve(strict=True)
    target = parent / raw.name
    if os.path.lexists(target):
        info = os.lstat(target)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f'recovery export target must be a regular file: {target}')
    fd = -1
    tmp = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=f'.{target.name}.', suffix='.tmp', dir=str(parent))
        tmp = Path(tmp_name)
        payload = text.encode('utf-8')
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(fd)
        fd = -1
        os.replace(tmp, target)
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return target
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def cmd_export(args):
    data = local_identity()
    text = json.dumps(data, indent=2, sort_keys=True) + '\n'
    if args.path == '-':
        sys.stdout.write(text)
    else:
        target = _atomic_write_public_export(Path(args.path), text)
        print(target)
    append_audit('recovery_public_key_exported', key_id=data['key_id'], public_key_sha256=data['public_key_sha256'], path=args.path)


def cmd_import(args):
    source = Path(args.path).expanduser()
    if not source.is_absolute():
        source = Path.cwd() / source
    try:
        payload = json.loads(_read_import_regular(source).decode('utf-8'))
    except UnicodeDecodeError as exc:
        raise RuntimeError('recovery public-key export must be UTF-8 JSON') from exc
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
    _trusted_root_dir(TRUST_ROOT, create=True, mode=0o755)
    target = TRUST_ROOT / f'{key_id}.pub'
    if os.path.lexists(target):
        if _read_root_regular(target, max_bytes=64 * 1024) != pem:
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
    dir_fd = os.open(TRUST_ROOT, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
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
