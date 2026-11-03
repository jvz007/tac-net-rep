"""Core secret store (Core 1.17.100, hardened in 1.17.101; capability core.secrets 1.0.0; AD-57, Option A of reviews/requests/SECRET-STORE-DESIGN-19-10-2026.md).

A module keeps a private value here, such as a token or a private key. Core encrypts it before it reaches the database and decrypts it
only for the module that owns it, inside the Core process. Nobody else can read it: there is no HTTP route that returns a value, for
any role, and the browser never sees one.

The contract (Python only, ``tec_tac.secret_store``; a module checks ``core.secrets`` through ``tec_tac.capabilities`` first):

* ``put(name, value)``  create or replace one secret (text or bytes, 1 byte to 16 KiB). Returns ``"created"`` or ``"replaced"``.
* ``get(name)``         the value, as ``str`` or ``bytes`` as it was stored, or ``None`` when there is none. Owner only.
* ``delete(name)``      remove one secret. ``True`` when a row was removed.
* ``configured(name)``  ``True`` or ``False``. Never the value. Writes nothing.
* ``list_names()``      the names the calling module owns, sorted. No values.

Who owns a secret. The owner is the module whose code makes the call, which Core finds from the call stack (``core.caller_identity``,
AD-26). Nothing is passed in, so a module cannot name another module's namespace. Core itself, a library, a generated frame, a
disabled module and a legacy module are refused with 403 ``caller_not_allowed`` before any name or value is looked at, and one Core
audit row (action ``deny``) records the refusal. Since 1.17.101 no function in this file takes an owner as an argument: the five
public functions find the owner themselves and do their own table work, so nothing a module can import skips the caller check. (A Core
use of its own, such as backup destinations, will need its own caller rule in a later release; it is not part of the contract.)

How a value is kept. AES-256-GCM through the ``cryptography`` package, a new random 96-bit nonce for every write, and the owner id and
the name bound in as authenticated data. A row copied to another owner or another name therefore fails to decrypt. The stored column is
nonce + ciphertext + tag. Each row also carries the id of the master key that made it (``key_id``), so a later key rotation can find
the rows that need re-encrypting.

The master key. 32 random bytes in ``/etc/tec-tac/secrets/master.key``, root:tactical, mode 0640, made by ``install.sh`` only.
Core never creates, repairs or replaces it. A missing key, a link, a file of the wrong size, one not owned by root or one that others
can write or read is a loud fault: the call raises ``master_key_unavailable`` (503), one error line is logged with the reason (never
any key byte), and nothing is read or written. There is no silent new key. A row whose ``key_id`` is not the current key's is
``secret_unreadable`` (503). Losing the key makes every secret unreadable: the owning module asks for the value again.

Audit. Every put (action add or modify) and delete writes one strict Core audit row, BEFORE the change and in the same transaction, so
a change that cannot be audited is not made (503 ``audit_failed``). The row names the owner and the name, the size, the value type and
the key id. It never holds the value. A refused caller and a row that cannot be decrypted write one row each (not strict). A
successful read writes no row, because a licence key is read on every download and would flood the log; the row keeps a read count and
a last-read time instead. Since 1.17.101 that update runs at most once a minute per secret, as ``F("read_count") + 1`` in its own
savepoint, and a failure of it never fails the read or touches the caller's transaction. A refused caller and an unreadable secret write
at most one row per owner, name and reason every five minutes in each Core process (a later row says how many were left out).

No value ever appears in a log line, an exception message, an audit row, a job record or an HTTP answer. Option B (the master key from
systemd credentials) changes only ``_load_master_key``; the table and the contract stay.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import stat as stat_module
import threading
import time
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .caller_identity import calling_module_for_core_provider
from .event_jobs_policy import (
    ENABLED_CACHE_SECONDS as CALLER_CACHE_SECONDS,  # the event jobs snapshot time
)

logger = logging.getLogger("tec_tac.secret_store")

CAPABILITY_ID = "core.secrets"
CAPABILITY_VERSION = "1.0.0"
MASTER_KEY_PATH = Path("/etc/tec-tac/secrets/master.key")  # install.sh creates it; a test points this at a temporary file
MASTER_KEY_BYTES = 32
NONCE_BYTES = 12
MAX_VALUE_BYTES = 16 * 1024
MAX_NAMES_PER_OWNER = 100
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
AUDIT_OBJECT_TYPE = "core_secret"
KEY_GROUP_PATH = Path("/etc/tec-tac/secrets/key-group")  # 1.17.102: install.sh writes the group name it gave the key (the Tactical user's group)
_GROUP_NAME_PATTERN = re.compile(r"[a-z_][a-z0-9_.-]{0,63}")
READ_STATS_SECONDS = 60  # a read updates its counters at most this often
AUDIT_REPEAT_SECONDS = 300  # one deny or decrypt-failed row per owner, name and reason in this time (per Core process)
_AUDIT_REPEAT_MAX = 512  # entries kept for that per row type; when full and none has expired, further rows are left out, never flooded
_AAD_PREFIX = b"tec-tac/core.secrets/v1\x00"
_TYPE_TEXT = b"t"
_TYPE_BYTES = b"b"


class SecretStoreError(Exception):
    """A refusal. ``code`` is the machine-readable reason; ``status_code`` is the HTTP mapping. The message never holds a value.

    Codes: invalid_name (400), invalid_value (400), secret_limit (400), caller_not_allowed (403), master_key_unavailable (503, the
    master key is missing or unsafe; ``reason`` says which, for the log and the help text), secret_unreadable (503, the row cannot
    be decrypted with the current key), audit_failed (503, the change was not made because its audit row could not be written),
    secret_conflict (409, since 1.17.101: two first writes of one name collided twice in a row; try again).
    """

    def __init__(self, code: str, message: str, status_code: int = 400, *, reason: str | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.reason = reason


# --- validation -------------------------------------------------------------------------------

def _clean_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise SecretStoreError(
            "invalid_name",
            "name must be 1 to 64 characters: a lower-case letter or digit, then lower-case letters, digits, '.', '_' or '-'.",
        )
    return name


def _encode_value(value: Any) -> bytes:
    """The plain bytes to encrypt: one type byte, then the value. Raises before anything is read or written."""
    if isinstance(value, str):
        try:
            kind, raw = _TYPE_TEXT, value.encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate
            raise SecretStoreError("invalid_value", "value must be valid text.") from None
    elif isinstance(value, (bytes, bytearray)):
        kind, raw = _TYPE_BYTES, bytes(value)
    else:
        raise SecretStoreError("invalid_value", "value must be text or bytes.")
    if not raw:
        raise SecretStoreError("invalid_value", "value may not be empty.")
    if len(raw) > MAX_VALUE_BYTES:
        raise SecretStoreError("invalid_value", f"value may not exceed {MAX_VALUE_BYTES // 1024} KiB.")
    return kind + raw


def _decode_value(plain: bytes) -> str | bytes:
    kind, raw = plain[:1], plain[1:]
    if kind == _TYPE_TEXT:
        return raw.decode("utf-8")
    if kind == _TYPE_BYTES:
        return raw
    raise ValueError("unknown value type")


# --- the master key ---------------------------------------------------------------------------

_fstat = os.fstat  # a test replaces these three to stand in for root ownership and the tactical group on a PC that has neither
_lstat = os.lstat  # lstat, not stat: a link in the folder's place is seen as a link (1.17.101)


def _key_group_id() -> int | None:
    """The numeric id of the group the key file must have, or ``None`` when it cannot be found (that is a fault, never a pass)."""
    try:
        import grp

        name = _key_group_name()
        return None if name is None else grp.getgrnam(name).gr_gid
    except (ImportError, KeyError, OSError):
        return None


def _key_group_name() -> str | None:
    """The group name install.sh recorded beside the key (1.17.102), or ``None``. The record must be a regular file (no link) owned by
    root, not writable by group or others, small, and hold one plain group name; anything else is ``None`` (a fault, never a default)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(KEY_GROUP_PATH), flags)
    except OSError:
        return None
    try:
        info = _fstat(fd)
        if not stat_module.S_ISREG(info.st_mode) or getattr(info, "st_uid", 0) != 0 or info.st_mode & 0o022 or info.st_size > 128:
            return None
        text = os.read(fd, 129).decode("ascii", "ignore").strip()
    except OSError:
        return None
    finally:
        os.close(fd)
    return text if _GROUP_NAME_PATTERN.fullmatch(text) else None


def _key_fault(reason: str, message: str) -> SecretStoreError:
    """The loud fault. One error line with the reason; no key byte is ever logged."""
    logger.error("Core secret store cannot use its master key (%s). Nothing was read or written. See Troubleshooting.", reason)
    return SecretStoreError("master_key_unavailable", message, 503, reason=reason)


def _load_master_key() -> bytes:
    """Read and check the master key. Fails closed with ``master_key_unavailable``; never creates or repairs a key.

    The folder must be a real folder (not a link) that belongs to root and is not writable by group or others. The file must be a regular
    file (no link), owned by root, in the tactical group (1.17.101), with no group write or execute and no access for others (0640 or
    tighter), and exactly 32 bytes. Read on every call: 32 bytes,
    and a key that was swapped is never served from a stale copy. Option B replaces this function only.
    """
    path = MASTER_KEY_PATH
    generic = "The secret store cannot use its master key. An administrator must check the key file; see Troubleshooting."
    try:
        folder = _lstat(path.parent)
    except FileNotFoundError:
        raise _key_fault("missing", generic) from None
    except OSError:
        raise _key_fault("unreadable", generic) from None
    if not stat_module.S_ISDIR(folder.st_mode) or getattr(folder, "st_uid", 0) != 0 or folder.st_mode & 0o022:
        raise _key_fault("folder_unsafe", generic)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        raise _key_fault("missing", generic) from None
    except OSError:  # a link (ELOOP), a permission refusal or any other failure to open
        raise _key_fault("unreadable", generic) from None
    try:
        info = _fstat(fd)
        if not stat_module.S_ISREG(info.st_mode):
            raise _key_fault("not_a_file", generic)
        if getattr(info, "st_uid", 0) != 0:
            raise _key_fault("wrong_owner", generic)
        wanted_group = _key_group_id()
        if wanted_group is None or getattr(info, "st_gid", None) != wanted_group:
            raise _key_fault("wrong_group", generic)
        if info.st_mode & 0o137:
            raise _key_fault("wrong_mode", generic)
        if info.st_size != MASTER_KEY_BYTES:
            raise _key_fault("wrong_size", generic)
        key = os.read(fd, MASTER_KEY_BYTES + 1)
    except SecretStoreError:
        raise
    except OSError:
        raise _key_fault("unreadable", generic) from None
    finally:
        os.close(fd)
    if len(key) != MASTER_KEY_BYTES:
        raise _key_fault("wrong_size", generic)
    if key == bytes(MASTER_KEY_BYTES):
        raise _key_fault("placeholder", generic)
    return key


def _key_id(key: bytes) -> str:
    """A short public name for the key: it shows which key made a row. It is a hash, never the key."""
    return "k1-" + hashlib.sha256(b"tec-tac/core.secrets/key-id\x00" + key).hexdigest()[:12]


class _Scope:
    """The module a call was verified for. Made only by ``_caller_scope`` (and the fixed ``_UNVERIFIED`` for a refusal's audit row).
    Helpers that need the module's id take this object, never a bare owner argument, and none of them touches the table."""

    __slots__ = ("module_id",)

    def __init__(self, verified: str):
        self.module_id = verified


_UNVERIFIED = _Scope("unverified")


def _aad(scope: _Scope, name: str) -> bytes:
    return _AAD_PREFIX + scope.module_id.encode("utf-8") + b"\x00" + name.encode("utf-8")


def _encrypt(key: bytes, scope: _Scope, name: str, plain: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plain, _aad(scope, name))


def _decrypt(key: bytes, scope: _Scope, name: str, blob: bytes) -> bytes:
    """The plain bytes, or ``ValueError`` (any failure: a short blob, a wrong key, a row moved to another owner or name, a changed byte)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = bytes(blob)
    if len(blob) < NONCE_BYTES + 16 + 1:
        raise ValueError("blob too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], _aad(scope, name))
    except InvalidTag:
        raise ValueError("authentication failed") from None


# --- the caller -------------------------------------------------------------------------------

def _caller_scope(cache_seconds: float = 0) -> _Scope | None:
    """The module whose code is calling the contract function, found by Core (AD-26). ``None`` means refuse.

    ``cache_seconds`` is the short module snapshot of event jobs (``get`` uses it: a licence key is read on every download). A module
    just disabled is still recognised for up to that long; a module just installed is refused until the snapshot expires."""
    identity = calling_module_for_core_provider(provider_file=__file__, cache_seconds=cache_seconds)
    return None if identity is None else _Scope(identity.module_id)


# --- audit ------------------------------------------------------------------------------------

def _actor(scope: _Scope):
    from .audit import AuditActor

    return AuditActor(kind="service", module_id="core", identity=f"secret-store:{scope.module_id}", service="secret-store")


def _audit(action: str, scope: _Scope, name: str, *, strict: bool, **metadata: Any) -> None:
    """One Core audit row. It names the owner and the name, never a value. A strict row that cannot be written raises ``audit_failed``,
    and the caller's transaction rolls the change back (the row is written first, so nothing was changed yet)."""
    from .audit import record

    try:
        record(
            actor=_actor(scope),
            module_id="core",
            action=action,
            object_type=AUDIT_OBJECT_TYPE,
            object_id=f"{scope.module_id}/{name}",
            message=f"Tec-Tac secret store: {action}.",
            before=None,
            after=None,
            metadata={"owner": scope.module_id, "name": name, **metadata},
            strict=strict,
        )
    except Exception as exc:
        if strict:
            raise SecretStoreError("audit_failed", "The change was not made because it could not be audited.", 503) from exc
        logger.warning("Core secret store could not write an audit row (%s).", type(exc).__name__)


_monotonic = time.monotonic  # a test replaces this to move the clock
_repeat_lock = threading.Lock()
_repeat_seen: dict = {}  # (owner, name, reason) -> [time of the last row, rows left out since]


def _repeat_gate(scope: _Scope, name: str, reason: str) -> int | None:
    """``None`` when a row for this owner, name and reason was already written less than ``AUDIT_REPEAT_SECONDS`` ago (leave it out).
    Otherwise the number of rows left out since the last one, and the time is noted. A full table with nothing expired leaves rows out
    rather than growing: a flood cannot make Core write more."""
    now = _monotonic()
    key = (scope.module_id, name, reason)
    with _repeat_lock:
        entry = _repeat_seen.get(key)
        if entry is not None:
            if now - entry[0] < AUDIT_REPEAT_SECONDS:
                entry[1] += 1
                return None
            left_out = entry[1]
        else:
            # 1.17.102: the cap is per row type (the reason), so unverified callers filling deny rows cannot silence decrypt-failed rows
            if sum(1 for k in _repeat_seen if k[2] == reason) >= _AUDIT_REPEAT_MAX:
                for old in [k for k, v in _repeat_seen.items() if k[2] == reason and now - v[0] >= AUDIT_REPEAT_SECONDS]:
                    del _repeat_seen[old]
                if sum(1 for k in _repeat_seen if k[2] == reason) >= _AUDIT_REPEAT_MAX:
                    return None
            left_out = 0
        _repeat_seen[key] = [now, 0]
    return left_out


def _audit_limited(action: str, scope: _Scope, name: str, reason: str, **metadata: Any) -> bool:
    """A non-strict row at most once per owner, name and reason every five minutes. ``True`` when it was written (or tried)."""
    left_out = _repeat_gate(scope, name, reason)
    if left_out is None:
        return False
    if left_out:
        metadata["left_out_since_last_row"] = left_out
    _audit(action, scope, name, strict=False, outcome=reason, **metadata)
    return True


def _deny(operation: str, name: Any) -> SecretStoreError:
    """The refusal for a caller Core cannot verify. One non-strict deny row (rate limited), then the error. Core is never a caller."""
    shown = name if isinstance(name, str) and NAME_PATTERN.fullmatch(name) else "(invalid)"
    _audit_limited("deny", _UNVERIFIED, shown, "caller_not_allowed", operation=operation)
    return SecretStoreError("caller_not_allowed", "Only a signed, enabled module may use the secret store, and only for its own secrets.", 403)


# --- storage ----------------------------------------------------------------------------------

def _atomic():
    try:
        from django.db import transaction
    except ModuleNotFoundError:
        # Lightweight contract tests import this module without Django.
        return nullcontext()
    return transaction.atomic()


def _integrity_error():
    try:
        from django.db import IntegrityError
    except ImportError:
        class _NeverRaised(Exception):
            pass

        return _NeverRaised
    return IntegrityError


def _table():
    from .models import TecTacSecret

    return TecTacSecret.objects


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _count_read(row) -> None:
    """Note one read on its row: at most once per ``READ_STATS_SECONDS``, as ``F("read_count") + 1`` inside its own savepoint, so a
    lost race only adds a count, a failure rolls back to the savepoint and never poisons the caller's transaction, and a busy secret
    does not contend on its row. Never raises. ``read_count`` therefore counts the minutes in which the secret was read, not every read."""
    try:
        now = _now()
        last = getattr(row, "last_read_at", None)
        try:
            if last is not None and (now - last).total_seconds() < READ_STATS_SECONDS:
                return
        except TypeError:  # a naive stored time: treat as due
            pass
        from django.db.models import F

        with _atomic():
            _table().filter(pk=row.pk).update(read_count=F("read_count") + 1, last_read_at=now)
    except Exception:  # noqa: BLE001 - the read statistics never fail a read, whatever the database says
        logger.warning("Core secret store could not update the read statistics of one secret.")


# --- the public functions (the Python contract): verify the caller, then do the work -----------
# Each does its own table work with the owner it found itself. No helper above takes an owner and touches the table.

def put(name: Any, value: Any) -> str:
    """Create or replace one secret owned by the calling module. Returns ``created`` or ``replaced``. Audited before the change.

    Two first writes of one name at the same moment: the loser hits the table's unique constraint and is retried once as a replace; a
    second collision is ``secret_conflict`` (409). The 100-name limit is a soft limit: two first writes of different names at the very
    same moment can leave a module one or two names over it, and the next first write is then refused."""
    scope = _caller_scope()
    if scope is None:
        raise _deny("put", name)
    owner = scope.module_id
    key_name = _clean_name(name)
    plain = _encode_value(value)
    key = _load_master_key()
    key_id = _key_id(key)
    blob = _encrypt(key, scope, key_name, plain)
    integrity_error = _integrity_error()
    for attempt in (1, 2):
        try:
            with _atomic():
                current = _table().select_for_update().filter(owner_module=owner, name=key_name).first()
                if current is None and _table().filter(owner_module=owner).count() >= MAX_NAMES_PER_OWNER:
                    raise SecretStoreError("secret_limit", f"A module may keep at most {MAX_NAMES_PER_OWNER} secrets.")
                action = "add" if current is None else "modify"
                _audit(action, scope, key_name, strict=True, size_bytes=len(plain) - 1, value_type="text" if plain[:1] == _TYPE_TEXT else "bytes", key_id=key_id)
                if current is None:
                    _table().create(owner_module=owner, name=key_name, ciphertext=blob, key_id=key_id)
                else:
                    _table().filter(pk=current.pk).update(ciphertext=blob, key_id=key_id, updated_at=_now())
            return "created" if current is None else "replaced"
        except integrity_error:  # the transaction (with its audit row) was rolled back; the row now exists, so try once as a replace
            if attempt == 2:
                break
    raise SecretStoreError("secret_conflict", "Two writes of this secret collided. Try again; see Troubleshooting.", 409)


def get(name: Any) -> str | bytes | None:
    """The calling module's own secret, or ``None`` when it has none. Server-side only. A read is counted (at most once a minute), not audited."""
    scope = _caller_scope(CALLER_CACHE_SECONDS)
    if scope is None:
        raise _deny("get", name)
    owner = scope.module_id
    key_name = _clean_name(name)
    key = _load_master_key()  # first: a missing or unsafe key is a fault even when the secret does not exist
    row = _table().filter(owner_module=owner, name=key_name).first()
    if row is None:
        return None
    current_id = _key_id(key)
    try:
        if row.key_id != current_id:
            raise ValueError("key id differs")
        value = _decode_value(_decrypt(key, scope, key_name, row.ciphertext))
    except ValueError:
        if _audit_limited("custom:decrypt-failed", scope, key_name, "secret_unreadable", row_key_id=str(row.key_id)[:32], key_id=current_id):
            logger.error("Core secret store could not decrypt one secret (owner %s, name %s). The row or the master key changed.", owner, key_name)
        raise SecretStoreError("secret_unreadable", "This secret cannot be read with the current master key. Enter it again; see Troubleshooting.", 503) from None
    _count_read(row)
    return value


def delete(name: Any) -> bool:
    """Remove the calling module's own secret. ``True`` when a row was removed. Audited before the change."""
    scope = _caller_scope()
    if scope is None:
        raise _deny("delete", name)
    owner = scope.module_id
    key_name = _clean_name(name)
    with _atomic():
        current = _table().select_for_update().filter(owner_module=owner, name=key_name).first()
        if current is None:
            return False  # nothing to delete: no row, no audit
        _audit("delete", scope, key_name, strict=True, key_id=str(current.key_id)[:32])
        _table().filter(pk=current.pk).delete()
    return True


def configured(name: Any) -> bool:
    """``True`` when the calling module has a secret of that name. Never the value; it does not need the master key."""
    scope = _caller_scope()
    if scope is None:
        raise _deny("configured", name)
    key_name = _clean_name(name)
    return _table().filter(owner_module=scope.module_id, name=key_name).first() is not None


def list_names() -> list[str]:
    """The names the calling module owns, sorted. No values."""
    scope = _caller_scope()
    if scope is None:
        raise _deny("list_names", None)
    return [row.name for row in _table().filter(owner_module=scope.module_id).order_by("name")]


# --- capability registration ------------------------------------------------------------------

class _CoreSecretsProvider:
    put = staticmethod(put)
    get = staticmethod(get)
    delete = staticmethod(delete)
    configured = staticmethod(configured)
    list_names = staticmethod(list_names)


_PROVIDER = _CoreSecretsProvider()


def secrets_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.secret_store",
        "operations": ["put", "get", "delete", "configured", "list_names"],
        "limits": {"value_bytes": MAX_VALUE_BYTES, "names_per_module": MAX_NAMES_PER_OWNER, "name": "[a-z0-9][a-z0-9._-]{0,63}"},
        "caller": (
            "verified (AD-26): the owner is the module whose code calls; nothing is passed in. Core, a library, a generated frame, a "
            "disabled or legacy module give 403 caller_not_allowed before any read or write, with one deny audit row."
        ),
        "access": "owner only, server-side only. No HTTP route returns a value, for any role. The browser never sees one.",
        "storage": "AES-256-GCM, a random nonce per write, the owner id and the name as authenticated data; key id per row.",
        "master_key": "/etc/tec-tac/secrets/master.key, 32 random bytes, root:tactical 0640, created by install.sh only. Missing or unsafe: 503 master_key_unavailable, nothing read or written, no new key.",
        "audit": (
            "one strict Core audit row before each put (add or modify) and delete (object_type core_secret, object_id <owner>/<name>, "
            "metadata owner, name, size, key id; never the value); a deny row for a refused caller; a custom:decrypt-failed row for "
            "an unreadable secret (each at most once per owner, name and reason every five minutes per process). A successful read writes no row; the row keeps a read count and a last-read time, updated at most once a minute."
        ),
        "requires_framework": ">=1.17.100",
        "notes": "1.17.101: hardening only; the five operations and their results are unchanged. New error code secret_conflict (409).",
    }


def register_core_secrets_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Encrypted storage for a module's own private values. Read by the owning module's server-side code only.",
        operations=("put", "get", "delete", "configured", "list_names"),
        metadata=secrets_contract_metadata(),
    )
