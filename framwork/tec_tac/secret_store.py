"""Core secret store (Core 1.17.100; capability core.secrets 1.0.0; AD-57, Option A of reviews/requests/SECRET-STORE-DESIGN-19-10-2026.md).

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
audit row (action ``deny``) records the refusal. Core's own later uses (backup destinations) will use the private functions with the
owner ``core``; they are not part of the contract.

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
a last-read time instead (a failed update of those never fails the read).

No value ever appears in a log line, an exception message, an audit row, a job record or an HTTP answer. Option B (the master key from
systemd credentials) changes only ``_load_master_key``; the table and the contract stay.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import stat as stat_module
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .caller_identity import calling_module_for_core_provider

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
_AAD_PREFIX = b"tec-tac/core.secrets/v1\x00"
_TYPE_TEXT = b"t"
_TYPE_BYTES = b"b"


class SecretStoreError(Exception):
    """A refusal. ``code`` is the machine-readable reason; ``status_code`` is the HTTP mapping. The message never holds a value.

    Codes: invalid_name (400), invalid_value (400), secret_limit (400), caller_not_allowed (403), master_key_unavailable (503, the
    master key is missing or unsafe; ``reason`` says which, for the log and the help text), secret_unreadable (503, the row cannot
    be decrypted with the current key), audit_failed (503, the change was not made because its audit row could not be written).
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

_fstat = os.fstat  # a test replaces these two to stand in for root ownership on a PC that has no root
_stat = os.stat


def _key_fault(reason: str, message: str) -> SecretStoreError:
    """The loud fault. One error line with the reason; no key byte is ever logged."""
    logger.error("Core secret store cannot use its master key (%s). Nothing was read or written. See Troubleshooting.", reason)
    return SecretStoreError("master_key_unavailable", message, 503, reason=reason)


def _load_master_key() -> bytes:
    """Read and check the master key. Fails closed with ``master_key_unavailable``; never creates or repairs a key.

    The folder must belong to root and not be writable by group or others. The file must be a regular file (no link), owned by root,
    with no group write or execute and no access for others (0640 or tighter), and exactly 32 bytes. Read on every call: 32 bytes,
    and a key that was swapped is never served from a stale copy. Option B replaces this function only.
    """
    path = MASTER_KEY_PATH
    generic = "The secret store cannot use its master key. An administrator must check the key file; see Troubleshooting."
    try:
        folder = _stat(path.parent)
    except FileNotFoundError:
        raise _key_fault("missing", generic) from None
    except OSError:
        raise _key_fault("unreadable", generic) from None
    if getattr(folder, "st_uid", 0) != 0 or folder.st_mode & 0o022:
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


def _aad(owner: str, name: str) -> bytes:
    return _AAD_PREFIX + owner.encode("utf-8") + b"\x00" + name.encode("utf-8")


def _encrypt(key: bytes, owner: str, name: str, plain: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plain, _aad(owner, name))


def _decrypt(key: bytes, owner: str, name: str, blob: bytes) -> bytes:
    """The plain bytes, or ``ValueError`` (any failure: a short blob, a wrong key, a row moved to another owner or name, a changed byte)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = bytes(blob)
    if len(blob) < NONCE_BYTES + 16 + 1:
        raise ValueError("blob too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], _aad(owner, name))
    except InvalidTag:
        raise ValueError("authentication failed") from None


# --- the caller -------------------------------------------------------------------------------

def _caller_module() -> str | None:
    """The module whose code is calling the contract function, found by Core (AD-26). ``None`` means refuse."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    return None if identity is None else identity.module_id


# --- audit ------------------------------------------------------------------------------------

def _actor(owner: str):
    from .audit import AuditActor

    return AuditActor(kind="service", module_id="core", identity=f"secret-store:{owner}", service="secret-store")


def _audit(action: str, owner: str, name: str, *, strict: bool, **metadata: Any) -> None:
    """One Core audit row. It names the owner and the name, never a value. A strict row that cannot be written raises ``audit_failed``,
    and the caller's transaction rolls the change back (the row is written first, so nothing was changed yet)."""
    from .audit import record

    try:
        record(
            actor=_actor(owner),
            module_id="core",
            action=action,
            object_type=AUDIT_OBJECT_TYPE,
            object_id=f"{owner}/{name}",
            message=f"Tec-Tac secret store: {action}.",
            before=None,
            after=None,
            metadata={"owner": owner, "name": name, **metadata},
            strict=strict,
        )
    except Exception as exc:
        if strict:
            raise SecretStoreError("audit_failed", "The change was not made because it could not be audited.", 503) from exc
        logger.warning("Core secret store could not write an audit row (%s).", type(exc).__name__)


def _deny(operation: str, name: Any) -> SecretStoreError:
    """The refusal for a caller Core cannot verify. One non-strict deny row, then the error. Core is never a caller."""
    shown = name if isinstance(name, str) and NAME_PATTERN.fullmatch(name) else "(invalid)"
    _audit("deny", "unverified", shown, strict=False, operation=operation, outcome="caller_not_allowed")
    return SecretStoreError("caller_not_allowed", "Only a signed, enabled module may use the secret store, and only for its own secrets.", 403)


# --- storage ----------------------------------------------------------------------------------

def _atomic():
    try:
        from django.db import transaction
    except ModuleNotFoundError:
        # Lightweight contract tests import this module without Django.
        return nullcontext()
    return transaction.atomic()


def _table():
    from .models import TecTacSecret

    return TecTacSecret.objects


def _put(owner: str, name: str, value: Any) -> str:
    key_name = _clean_name(name)
    plain = _encode_value(value)
    key = _load_master_key()
    key_id = _key_id(key)
    blob = _encrypt(key, owner, key_name, plain)
    with _atomic():
        rows = _table().select_for_update().filter(owner_module=owner, name=key_name)
        current = rows.first()
        if current is None and _table().filter(owner_module=owner).count() >= MAX_NAMES_PER_OWNER:
            raise SecretStoreError("secret_limit", f"A module may keep at most {MAX_NAMES_PER_OWNER} secrets.")
        action = "add" if current is None else "modify"
        _audit(action, owner, key_name, strict=True, size_bytes=len(plain) - 1, value_type="text" if plain[:1] == _TYPE_TEXT else "bytes", key_id=key_id)
        if current is None:
            _table().create(owner_module=owner, name=key_name, ciphertext=blob, key_id=key_id)
        else:
            _table().filter(pk=current.pk).update(ciphertext=blob, key_id=key_id, updated_at=_now())
    return "created" if current is None else "replaced"


def _get(owner: str, name: str) -> str | bytes | None:
    key_name = _clean_name(name)
    key = _load_master_key()  # first: a missing or unsafe key is a fault even when the secret does not exist
    row = _table().filter(owner_module=owner, name=key_name).first()
    if row is None:
        return None
    current_id = _key_id(key)
    try:
        if row.key_id != current_id:
            raise ValueError("key id differs")
        value = _decode_value(_decrypt(key, owner, key_name, row.ciphertext))
    except ValueError:
        _audit("custom:decrypt-failed", owner, key_name, strict=False, outcome="secret_unreadable", row_key_id=str(row.key_id)[:32], key_id=current_id)
        logger.error("Core secret store could not decrypt one secret (owner %s, name %s). The row or the master key changed.", owner, key_name)
        raise SecretStoreError("secret_unreadable", "This secret cannot be read with the current master key. Enter it again; see Troubleshooting.", 503) from None
    try:
        _table().filter(pk=row.pk).update(read_count=int(row.read_count or 0) + 1, last_read_at=_now())
    except Exception:  # noqa: BLE001 - the read statistics never fail a read, whatever the database says
        logger.warning("Core secret store could not update the read statistics of one secret.")
    return value


def _delete(owner: str, name: str) -> bool:
    key_name = _clean_name(name)
    with _atomic():
        rows = _table().select_for_update().filter(owner_module=owner, name=key_name)
        current = rows.first()
        if current is None:
            return False  # nothing to delete: no row, no audit
        _audit("delete", owner, key_name, strict=True, key_id=str(current.key_id)[:32])
        _table().filter(pk=current.pk).delete()
    return True


def _configured(owner: str, name: str) -> bool:
    key_name = _clean_name(name)
    return _table().filter(owner_module=owner, name=key_name).first() is not None


def _list_names(owner: str) -> list[str]:
    return [row.name for row in _table().filter(owner_module=owner).order_by("name")]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- the public functions (the Python contract): verify the caller, then do the work -----------

def put(name: Any, value: Any) -> str:
    """Create or replace one secret owned by the calling module. Returns ``created`` or ``replaced``. Audited before the change."""
    owner = _caller_module()
    if owner is None:
        raise _deny("put", name)
    return _put(owner, name, value)


def get(name: Any) -> str | bytes | None:
    """The calling module's own secret, or ``None`` when it has none. Server-side only. A read is counted, not audited."""
    owner = _caller_module()
    if owner is None:
        raise _deny("get", name)
    return _get(owner, name)


def delete(name: Any) -> bool:
    """Remove the calling module's own secret. ``True`` when a row was removed. Audited before the change."""
    owner = _caller_module()
    if owner is None:
        raise _deny("delete", name)
    return _delete(owner, name)


def configured(name: Any) -> bool:
    """``True`` when the calling module has a secret of that name. Never the value; it does not need the master key."""
    owner = _caller_module()
    if owner is None:
        raise _deny("configured", name)
    return _configured(owner, name)


def list_names() -> list[str]:
    """The names the calling module owns, sorted. No values."""
    owner = _caller_module()
    if owner is None:
        raise _deny("list_names", None)
    return _list_names(owner)


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
            "an unreadable secret. A successful read writes no row; the row keeps a read count and a last-read time."
        ),
        "requires_framework": ">=1.17.100",
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
