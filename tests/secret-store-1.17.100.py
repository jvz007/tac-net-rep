#!/usr/bin/env python3
"""1.17.100 (AD-57, C2 of the licensing compatibility diff): the Core secret store, plus the two held Lows of 1.17.99.

Part A, the store. The real tec_tac/secret_store.py and tec_tac/caller_identity.py run against a temporary extensions folder (the style
of tests/module-preferences-caller-1.17.37.py), the real `cryptography` package, a fake table and a fake audit writer. Covered: a round
trip of text and bytes; no plain text in the stored row, any log line, any audit row or any exception; a fresh random nonce per write;
AAD binding (a row copied to another owner or another name fails); the caller check (another module reads nothing of the owner's, Core,
a library, a generated frame, a disabled and a legacy module are refused with one deny row and nothing read or written); a missing,
short, long, group-writable, other-readable, wrong-owner, placeholder or linked key fails closed with master_key_unavailable and
creates nothing; a key id that is not the current key's is secret_unreadable with one decrypt-failed row; audit first (the row is
written before the change, and an audit that fails leaves the table untouched); name and value limits; no HTTP route or view reads a
value; the migration is one new table on top of the 1.17.99 leaf; the backup leaves the key out and a restore refuses it.

Part B, install.sh. The key block is cut from the real installer and run under real bash with the privileged commands stubbed: a fresh
install creates 32 bytes (0640); an existing key is never overwritten (same bytes after), and a key of the wrong size or a link stops
the install without a change.

Part C, held Low 1 (module_repository.py). A 401 or 403 from a repository that has credentials is "credentials rejected", not
"retired"; a repository with none keeps the 1.17.99 behaviour; 404 and 410 are retired for both; nothing is offered or staged.

Part D, held Low 2 (system-update-helper.py). A rollback or restore that ran an installer older than 1.17.99 gets the Licensing Server
address put back; a newer installer's own line is left alone; a config that cannot be written never fails the rollback.

Django is not installed on the development PC, so models, views and the migration are checked with ast and fakes.
"""
from __future__ import annotations

import ast
import importlib
import json
import logging
import os
import re
import shutil
import stat as stat_module
import subprocess
import sys
import tempfile
import types
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))
SCHEDULER_FILE = str(APP / "scheduler.py")
SENTINEL = "SENTINEL-s3cr3t-VALUE-9f2c-do-not-leak"
SENTINEL_BYTES = SENTINEL.encode("utf-8")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


def read(path):
    return Path(path).read_text(encoding="utf-8")


# ================================================================================================ Part A: the store
TMP = Path(tempfile.mkdtemp(prefix="tectac-secrets-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
KEYDIR = TMP / "secrets"
for folder in (EXT, LIB, KEYDIR):
    folder.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}


def plugin(plugin_id, *, enabled=True, legacy=False):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=legacy, category="server")
    ENABLED[plugin_id] = enabled


plugin("licensing")
plugin("halopsa")
plugin("modoff", enabled=False)
plugin("oldmod", legacy=True)

pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=lambda: tuple(PLUGINS.values()))
pkg.module_state = mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: bool(ENABLED.get(module_id, False)))

# the fake table: every write is logged in ORDER with the audit rows, so "audit first" is checked against the order
ORDER: list = []
AUDIT: list = []
AUDIT_FAIL = [False]


class AuditWriteError(RuntimeError):
    pass


class AuditActor:
    def __init__(self, *, kind, module_id, identity, service=None, device_id=None):
        self.kind, self.module_id, self.identity, self.service, self.device_id = kind, module_id, identity, service, device_id


def fake_record(**kwargs):
    if AUDIT_FAIL[0]:
        if kwargs.get("strict"):
            raise AuditWriteError("audit store down")
        return {"recorded": False}
    ORDER.append(("audit", kwargs["action"], kwargs["object_id"]))
    AUDIT.append(kwargs)
    return {"recorded": True}


mod("tec_tac.audit", AuditActor=AuditActor, record=fake_record, AuditWriteError=AuditWriteError)
REGISTERED: list = []
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kwargs: REGISTERED.append(kwargs) or "registered")


class _Atomic:
    def __enter__(self):
        ORDER.append(("begin",))
        return self

    def __exit__(self, exc_type, *args):
        ORDER.append(("rollback" if exc_type else "commit",))
        return False


mod("django")
mod("django.db", transaction=SimpleNamespace(atomic=lambda: _Atomic()))


class Row(SimpleNamespace):
    pass


class Query:
    def __init__(self, table, rows):
        self.table, self.rows = table, rows

    def filter(self, **kwargs):
        return Query(self.table, [r for r in self.rows if all(getattr(r, k) == v for k, v in kwargs.items())])

    def select_for_update(self):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def count(self):
        return len(self.rows)

    def order_by(self, field):
        return Query(self.table, sorted(self.rows, key=lambda r: getattr(r, field)))

    def __iter__(self):
        return iter(list(self.rows))

    def update(self, **kwargs):
        for row in self.rows:
            for key, value in kwargs.items():
                setattr(row, key, value)
        ORDER.append(("update", len(self.rows), sorted(kwargs)))
        return len(self.rows)

    def delete(self):
        gone = {id(r) for r in self.rows}
        self.table.rows = [r for r in self.table.rows if id(r) not in gone]
        ORDER.append(("delete", len(gone)))
        return len(gone), {}


class Manager:
    def __init__(self):
        self.rows: list = []
        self.next_pk = 1

    def filter(self, **kwargs):
        return Query(self, self.rows).filter(**kwargs)

    def select_for_update(self):
        return Query(self, self.rows)

    def create(self, **kwargs):
        row = Row(pk=self.next_pk, read_count=0, last_read_at=None, **kwargs)
        self.next_pk += 1
        self.rows.append(row)
        ORDER.append(("create", kwargs["owner_module"], kwargs["name"]))
        return row


class TecTacSecret:
    objects = Manager()


mod("tec_tac.models", TecTacSecret=TecTacSecret)

LOGS: list = []


class Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage())


handler = Capture(level=logging.DEBUG)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.DEBUG)
logging.disable(logging.NOTSET)

ci = importlib.import_module("tec_tac.caller_identity")
ss = importlib.import_module("tec_tac.secret_store")
Err = ss.SecretStoreError
TABLE = TecTacSecret.objects

# a stand-in for root ownership and file modes on a PC that has no root: the real code asks these two functions
KEY_STATE = {"uid": 0, "mode": 0o640, "kind": "regular"}
FOLDER_STATE = {"uid": 0, "mode": 0o40750}
real_fstat, real_stat = os.fstat, os.stat
KEY_FILE = KEYDIR / "master.key"
ss.MASTER_KEY_PATH = KEY_FILE


def fake_fstat(fd):
    info = real_fstat(fd)
    mode = (stat_module.S_IFDIR if KEY_STATE["kind"] == "dir" else stat_module.S_IFREG) | KEY_STATE["mode"]
    return SimpleNamespace(st_mode=mode, st_uid=KEY_STATE["uid"], st_size=info.st_size)


def fake_stat(path, *args, **kwargs):
    if Path(path) == KEYDIR:
        return SimpleNamespace(st_uid=FOLDER_STATE["uid"], st_mode=FOLDER_STATE["mode"])
    return real_stat(path, *args, **kwargs)


ss._fstat, ss._stat = fake_fstat, fake_stat


def write_key(data=None):
    KEY_FILE.write_bytes(os.urandom(32) if data is None else data)


def reset(key=True):
    TABLE.rows.clear()
    TABLE.next_pk = 1
    ORDER.clear()
    AUDIT.clear()
    LOGS.clear()
    AUDIT_FAIL[0] = False
    KEY_STATE.update(uid=0, mode=0o640, kind="regular")
    FOLDER_STATE.update(uid=0, mode=0o40750)
    if KEY_FILE.is_symlink() or KEY_FILE.exists():
        KEY_FILE.unlink()
    if key:
        write_key()


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


CALL = "def call(fn, *args, **kwargs):\n    return fn(*args, **kwargs)\n"
LIC = compile_as(str(EXT / "licensing" / "service.py"), CALL)["call"]
HALO = compile_as(str(EXT / "halopsa" / "service.py"), CALL)["call"]
OFF = compile_as(str(EXT / "modoff" / "service.py"), CALL)["call"]
OLD = compile_as(str(EXT / "oldmod" / "service.py"), CALL)["call"]
CORE = compile_as(SCHEDULER_FILE, CALL)["call"]
LIBRARY = compile_as(str(LIB / "decorator.py"), CALL)["call"]
GENERATED = compile_as("<string>", CALL)["call"]


def refused(fn, *args, code, **kwargs):
    try:
        fn(*args, **kwargs)
    except Err as exc:
        must(exc.code == code, (code, exc.code))
        must(SENTINEL not in str(exc) and SENTINEL not in repr(exc), "a value is in an error")
        return exc
    raise AssertionError(f"expected {code}")


def everything_text():
    """Every place a value must never appear: the stored rows, every log line and every audit row."""
    rows = " ".join(repr(vars(r)) for r in TABLE.rows)
    return rows + " " + " ".join(LOGS) + " " + json.dumps(AUDIT, default=lambda o: repr(vars(o)) if hasattr(o, "__dict__") else str(o))


# --- 1. round trip, types, replace, delete
reset()
must(LIC(ss.put, "licence_key", SENTINEL) == "created")
must(LIC(ss.get, "licence_key") == SENTINEL and isinstance(LIC(ss.get, "licence_key"), str))
must(LIC(ss.put, "server_identity_key", SENTINEL_BYTES + b"\x00\xff") == "created")
must(LIC(ss.get, "server_identity_key") == SENTINEL_BYTES + b"\x00\xff")
must(LIC(ss.put, "licence_key", "second") == "replaced" and LIC(ss.get, "licence_key") == "second")
must(LIC(ss.configured, "licence_key") is True and LIC(ss.configured, "nope") is False)
must(LIC(ss.list_names) == ["licence_key", "server_identity_key"], LIC(ss.list_names))
must(LIC(ss.get, "missing") is None)
must(LIC(ss.delete, "licence_key") is True and LIC(ss.delete, "licence_key") is False and LIC(ss.get, "licence_key") is None)
unicode_value = "passé ☃ \U0001f511"
LIC(ss.put, "unicode", unicode_value)
must(LIC(ss.get, "unicode") == unicode_value)
LIC(ss.put, "sixteen", b"x" * 16384)
must(len(LIC(ss.get, "sixteen")) == 16384)
print("       round trip of text and bytes, replace, delete, configured and list_names")

# --- 2. no plain text anywhere
reset()
LIC(ss.put, "licence_key", SENTINEL)
LIC(ss.put, "raw", SENTINEL_BYTES)
LIC(ss.get, "licence_key")
LIC(ss.put, "licence_key", SENTINEL + "-2")
LIC(ss.delete, "raw")
refused(LIC, ss.put, "BAD NAME", SENTINEL, code="invalid_name")
refused(LIC, ss.put, "toolong", SENTINEL.encode() * 1000, code="invalid_value")
refused(CORE, ss.put, "licence_key", SENTINEL, code="caller_not_allowed")
text = everything_text()
must(SENTINEL not in text and SENTINEL_BYTES.hex() not in text, "the value is in a row, a log line or an audit row")
for row in TABLE.rows:
    must(isinstance(row.ciphertext, bytes) and SENTINEL_BYTES not in row.ciphertext and b"licence" not in row.ciphertext, "plain text in the row")
    must(set(vars(row)) >= {"owner_module", "name", "ciphertext", "key_id"} and SENTINEL not in repr(vars(row)))
# a failing key fault and a decrypt fault leak nothing either
KEY_FILE.write_bytes(b"short")
exc = refused(LIC, ss.get, "licence_key", code="master_key_unavailable")
must(exc.status_code == 503 and exc.reason == "wrong_size" and SENTINEL not in everything_text())
print("       no plain text in the stored row, any log line, any audit row or any exception")

# --- 3. a new nonce per write
reset()
LIC(ss.put, "a", SENTINEL)
first = bytes(TABLE.rows[0].ciphertext)
LIC(ss.put, "a", SENTINEL)
second = bytes(TABLE.rows[0].ciphertext)
must(first != second and first[:12] != second[:12], "the nonce was reused")
must(len(first) == 12 + 1 + len(SENTINEL) + 16, len(first))
print("       a fresh random nonce for every write (same value, different ciphertext)")

# --- 4. AAD binding
reset()
LIC(ss.put, "licence_key", SENTINEL)
row = TABLE.rows[0]
moved = Row(pk=99, owner_module="halopsa", name="licence_key", ciphertext=row.ciphertext, key_id=row.key_id, read_count=0, last_read_at=None)
TABLE.rows.append(moved)
refused(HALO, ss.get, "licence_key", code="secret_unreadable")
TABLE.rows.remove(moved)
renamed = Row(pk=98, owner_module="licensing", name="other_name", ciphertext=row.ciphertext, key_id=row.key_id, read_count=0, last_read_at=None)
TABLE.rows.append(renamed)
refused(LIC, ss.get, "other_name", code="secret_unreadable")
TABLE.rows.remove(renamed)
must(LIC(ss.get, "licence_key") == SENTINEL, "the original row still reads")
flipped = bytearray(row.ciphertext)
flipped[-1] ^= 1
row.ciphertext = bytes(flipped)
refused(LIC, ss.get, "licence_key", code="secret_unreadable")
decrypt_rows = [a for a in AUDIT if a["action"] == "custom:decrypt-failed"]
must(len(decrypt_rows) == 3 and all(a["strict"] is False for a in decrypt_rows), decrypt_rows)
must(SENTINEL not in everything_text())
print("       AAD binding: a row copied to another owner or name, or changed by a bit, fails with secret_unreadable and one audit row each")

# --- 5. the caller check
reset()
LIC(ss.put, "licence_key", SENTINEL)
must(HALO(ss.get, "licence_key") is None and HALO(ss.configured, "licence_key") is False and HALO(ss.list_names) == [], "another module saw the owner's secret")
must(HALO(ss.delete, "licence_key") is False and TABLE.rows and LIC(ss.get, "licence_key") == SENTINEL, "another module deleted the owner's secret")
HALO(ss.put, "licence_key", "halo's own")
must(LIC(ss.get, "licence_key") == SENTINEL and HALO(ss.get, "licence_key") == "halo's own", "owners are separate namespaces")
reset()
LIC(ss.put, "licence_key", SENTINEL)
rows_before = [vars(r).copy() for r in TABLE.rows]
for label, caller in (("core", CORE), ("library", LIBRARY), ("generated", GENERATED), ("disabled", OFF), ("legacy", OLD), ("test file", lambda fn, *a: fn(*a))):
    del ORDER[:]
    audit_before = len(AUDIT)
    for op, args in (("put", ("licence_key", "x")), ("get", ("licence_key",)), ("delete", ("licence_key",)), ("configured", ("licence_key",)), ("list_names", ())):
        refused(caller, getattr(ss, op), *args, code="caller_not_allowed")
    must([vars(r) for r in TABLE.rows] == rows_before, f"{label}: a row changed")
    must(not [o for o in ORDER if o[0] in {"create", "update", "delete"}], f"{label}: a write happened")
    denies = AUDIT[audit_before:]
    must(len(denies) == 5 and all(a["action"] == "deny" and a["strict"] is False and a["module_id"] == "core" for a in denies), (label, denies))
must(SENTINEL not in everything_text())
print("       caller check: another module reads, lists and deletes nothing of the owner's; Core, a library, a generated frame, a disabled module, a legacy module and the test file are refused with one deny row each and nothing read or written")

# --- 6. the master key fails closed
def expect_key_fault(reason, setup):
    reset(key=False)
    setup()
    for fn, args in ((ss.put, ("licence_key", SENTINEL)), (ss.get, ("licence_key",))):
        exc = refused(LIC, fn, *args, code="master_key_unavailable")
        must(exc.status_code == 503 and exc.reason == reason, (reason, exc.reason))
    must(not TABLE.rows and not AUDIT, "a row or an audit row was written without a usable key")
    must(not KEY_FILE.exists() or KEY_FILE.is_symlink() or reason != "missing", "Core created a key")
    must(any(reason in line for line in LOGS) and not any(SENTINEL in line for line in LOGS), LOGS)
    # reads of names need no key and write nothing
    must(LIC(ss.configured, "licence_key") is False and LIC(ss.list_names) == [])


expect_key_fault("missing", lambda: None)
must(not KEY_FILE.exists(), "Core made a key file")
expect_key_fault("wrong_size", lambda: write_key(b"\x01" * 31))
expect_key_fault("wrong_size", lambda: write_key(b"\x01" * 33))
expect_key_fault("wrong_size", lambda: write_key(b""))
expect_key_fault("placeholder", lambda: write_key(bytes(32)))
expect_key_fault("wrong_mode", lambda: (write_key(), KEY_STATE.update(mode=0o660)))
expect_key_fault("wrong_mode", lambda: (write_key(), KEY_STATE.update(mode=0o644)))
expect_key_fault("wrong_mode", lambda: (write_key(), KEY_STATE.update(mode=0o750)))
expect_key_fault("wrong_owner", lambda: (write_key(), KEY_STATE.update(uid=1000)))
expect_key_fault("not_a_file", lambda: (write_key(), KEY_STATE.update(kind="dir")))
expect_key_fault("folder_unsafe", lambda: (write_key(), FOLDER_STATE.update(mode=0o40770)))
expect_key_fault("folder_unsafe", lambda: (write_key(), FOLDER_STATE.update(mode=0o40757)))
expect_key_fault("folder_unsafe", lambda: (write_key(), FOLDER_STATE.update(uid=1000)))
# a link (POSIX only: O_NOFOLLOW)
reset(key=False)
real_target = TMP / "elsewhere.key"
real_target.write_bytes(os.urandom(32))
try:
    os.symlink(real_target, KEY_FILE)
    linked = True
except (OSError, NotImplementedError):
    linked = False
if linked and hasattr(os, "O_NOFOLLOW"):
    exc = refused(LIC, ss.put, "licence_key", "x", code="master_key_unavailable")
    must(exc.reason == "unreadable", exc.reason)
    KEY_FILE.unlink()
    print("       a linked key file is refused (O_NOFOLLOW)")
else:
    print("       a linked key file: not run on this PC (no symlink or O_NOFOLLOW); source checked below")
# a folder that is gone
reset(key=False)
shutil.rmtree(KEYDIR)
exc = refused(LIC, ss.get, "x", code="master_key_unavailable")
must(exc.reason == "missing", exc.reason)
KEYDIR.mkdir()
# a good key works again with no restart, and a swapped key is never served from a stale copy
reset()
LIC(ss.put, "licence_key", SENTINEL)
write_key()  # a different key in the same place
refused(LIC, ss.get, "licence_key", code="secret_unreadable")
print("       a missing, short, long, empty, placeholder, group-writable, other-readable, wrong-owner or folder-unsafe key is master_key_unavailable (503); nothing read, written or audited; Core makes no key; a swapped key is secret_unreadable")

# --- 7. key id per row
reset()
LIC(ss.put, "licence_key", SENTINEL)
must(re.fullmatch(r"k1-[0-9a-f]{12}", TABLE.rows[0].key_id), TABLE.rows[0].key_id)
TABLE.rows[0].key_id = "k1-000000000000"
refused(LIC, ss.get, "licence_key", code="secret_unreadable")
must(AUDIT[-1]["action"] == "custom:decrypt-failed" and AUDIT[-1]["metadata"]["row_key_id"] == "k1-000000000000", AUDIT[-1])
print("       the key id is stored per row; a row of another key id is secret_unreadable with one decrypt-failed row")

# --- 8. audit first, audit fails closed, audit rows carry no value
reset()
LIC(ss.put, "licence_key", SENTINEL)
must(ORDER.index(("audit", "add", "licensing/licence_key")) < ORDER.index(("create", "licensing", "licence_key")), ORDER)
LIC(ss.put, "licence_key", SENTINEL + "2")
must(ORDER.index(("audit", "modify", "licensing/licence_key")) < next(i for i, o in enumerate(ORDER) if o[0] == "update" and "ciphertext" in o[2]), ORDER)
LIC(ss.delete, "licence_key")
must(ORDER.index(("audit", "delete", "licensing/licence_key")) < ORDER.index(("delete", 1)), ORDER)
actions = [(a["action"], a["object_type"], a["object_id"], a["strict"], a["module_id"]) for a in AUDIT]
must(actions == [("add", "core_secret", "licensing/licence_key", True, "core"), ("modify", "core_secret", "licensing/licence_key", True, "core"),
                 ("delete", "core_secret", "licensing/licence_key", True, "core")], actions)
for a in AUDIT:
    must(a["metadata"]["owner"] == "licensing" and a["metadata"]["name"] == "licence_key" and a["actor"].identity == "secret-store:licensing", a)
    must(a["before"] is None and a["after"] is None and SENTINEL not in json.dumps(a["metadata"]))
must(AUDIT[0]["metadata"]["size_bytes"] == len(SENTINEL) and AUDIT[0]["metadata"]["value_type"] == "text" and AUDIT[0]["metadata"]["key_id"].startswith("k1-"), AUDIT[0]["metadata"])
# deleting a name that is not there writes no row
before = len(AUDIT)
must(LIC(ss.delete, "never") is False and len(AUDIT) == before)
# an audit that cannot be written: nothing changes
reset()
LIC(ss.put, "licence_key", SENTINEL)
snapshot = [vars(r).copy() for r in TABLE.rows]
AUDIT_FAIL[0] = True
for fn, args in ((ss.put, ("licence_key", "new")), (ss.put, ("fresh", "new")), (ss.delete, ("licence_key",))):
    exc = refused(LIC, fn, *args, code="audit_failed")
    must(exc.status_code == 503)
must([vars(r) for r in TABLE.rows] == snapshot, "a change was made although its audit row failed")
AUDIT_FAIL[0] = False
must(LIC(ss.get, "licence_key") == SENTINEL)
# the successful read writes no audit row, and counts
n = len(AUDIT)
for _ in range(3):
    LIC(ss.get, "licence_key")
must(len(AUDIT) == n and TABLE.rows[0].read_count == 4 and TABLE.rows[0].last_read_at is not None, (len(AUDIT), n, TABLE.rows[0].read_count))
print("       audit first and in the same transaction (add, modify, delete); no value in a row; an audit that fails changes nothing (503 audit_failed); a read writes no row and is counted")

# --- 9. limits
reset()
for bad in ("", "A", "-x", ".x", "x" * 65, "has space", "ünï", "a/b", "a\x00b", None, 5, b"bytes"):
    refused(LIC, ss.put, bad, "v", code="invalid_name")
    refused(LIC, ss.get, bad, code="invalid_name")
for good in ("a", "0", "a" * 64, "a.b_c-d"):
    LIC(ss.put, good, "v")
for bad in ("", b"", b"x" * 16385, "é" * 8193, 5, None, ["x"], {"a": 1}, "\ud800"):
    refused(LIC, ss.put, "valid", bad, code="invalid_value")
reset()
for index in range(100):
    LIC(ss.put, f"n{index:03d}", "v")
refused(LIC, ss.put, "n100", "v", code="secret_limit")
must(LIC(ss.put, "n005", "again") == "replaced", "a replace is not a new name")
print("       name and value limits: 64 characters of [a-z0-9._-], 1 byte to 16 KiB, text or bytes, 100 names")

# --- 10. capability and contract text
REGISTERED.clear()
ss.register_core_secrets_capability()
cap = REGISTERED[0]
must(cap["id"] == "core.secrets" and cap["version"] == "1.0.0" and cap["module_id"] == "core", cap)
must(set(cap["operations"]) == {"put", "get", "delete", "configured", "list_names"} and cap["provider"].put is ss.put, cap)
must(cap["metadata"]["requires_framework"] == ">=1.17.100" and "AES-256-GCM" in cap["metadata"]["storage"], cap["metadata"])
APPS = read(APP / "apps.py")
must("core.secrets capability registration failed" in APPS and "register_core_secrets_capability()" in APPS, "registration missing in apps.py")
CONTRACTS = read(APP / "contracts.py")
for name in ("put", "get", "delete", "configured", "list_names"):
    must(re.search(r'"area": "secret-store",\s+"import_path": "tec_tac.secret_store",\s+"name": "' + name + '"', CONTRACTS), name)
must("Module secrets (core.secrets 1.0.0, Core 1.17.100, AD-57)" in CONTRACTS and "framework >=1.17.100" in CONTRACTS)
print("       the capability core.secrets 1.0.0, its registration and its five contract rows")

# --- 11. no HTTP route, view, serializer or other module reads a value; Core never writes a key
SRC = read(APP / "secret_store.py")
must(not re.search(r'open\([^)]*["\']w', SRC) and "write_bytes" not in SRC and "O_CREAT" not in SRC and "O_WRONLY" not in SRC and "O_RDWR" not in SRC,
     "secret_store.py can write a file")
must("O_NOFOLLOW" in SRC and "urandom" in SRC and SRC.count("os.urandom") == 1, "O_NOFOLLOW or the single nonce source is missing")
for path in sorted(APP.glob("*.py")):
    if path.name in {"secret_store.py", "apps.py", "contracts.py", "models.py"}:
        continue
    code = read(path)
    must("secret_store" not in code and "TecTacSecret" not in code and "core_secret" not in code, f"{path.name} touches the secret store")
for path in sorted((APP / "migrations").glob("*.py")):
    if path.name != "0044_core_secret.py":
        must("TecTacSecret" not in read(path), path.name)
URLS = read(APP / "urls.py")
must("secret" not in URLS.lower(), "a route mentions secrets")
must("class TecTacSecret" in read(APP / "models.py") and 'db_table = "core_secret"' in read(APP / "models.py"))
print("       no route, view or other file reads a value; secret_store.py has no way to write a file")

# --- 12. the migration: one new table on top of the 1.17.99 leaf
migrations = {}
for path in sorted((APP / "migrations").glob("[0-9]*.py")):
    tree = ast.parse(read(path))
    deps = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "dependencies" for t in node.targets):
            deps = [d.elts[1].value for d in node.value.elts if isinstance(d, ast.Tuple) and d.elts[0].value == "tec_tac"]
    migrations[path.stem] = deps
leaves = [name for name in migrations if not any(name in deps for deps in migrations.values())]
must(leaves == ["0044_core_secret"], leaves)
must(migrations["0044_core_secret"] == ["0043_removed_schedule_marker"], migrations["0044_core_secret"])
mtree = ast.parse(read(APP / "migrations" / "0044_core_secret.py"))
ops = [n for n in ast.walk(mtree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {
    "CreateModel", "AddConstraint", "AddField", "AlterField", "RemoveField", "RunPython", "RunSQL", "DeleteModel", "RenameField", "AlterModelTable"}]
must(sorted(n.func.attr for n in ops) == ["AddConstraint", "CreateModel"], [n.func.attr for n in ops])
mfields = {}
for node in ast.walk(mtree):
    if isinstance(node, ast.Tuple) and len(node.elts) == 2 and isinstance(node.elts[0], ast.Constant) and isinstance(node.elts[1], ast.Call):
        mfields[node.elts[0].value] = ast.unparse(node.elts[1])
model_tree = ast.parse(read(APP / "models.py"))
cls = next(n for n in model_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacSecret")
model_fields = {t.targets[0].id: ast.unparse(t.value).replace("models.", "") for t in cls.body if isinstance(t, ast.Assign) and isinstance(t.value, ast.Call)}
mig_fields = {k: v.replace("models.", "") for k, v in mfields.items() if k != "id"}
def _norm_field(text):
    call = ast.parse(text, mode="eval").body
    return (ast.unparse(call.func), sorted((k.arg, ast.unparse(k.value)) for k in call.keywords))


must({k: _norm_field(v) for k, v in model_fields.items()} == {k: _norm_field(v) for k, v in mig_fields.items()}, (model_fields, mig_fields))
must(set(model_fields) == {"owner_module", "name", "ciphertext", "key_id", "created_at", "updated_at", "last_read_at", "read_count"}, set(model_fields))
must("core_secret_owner_name_unique" in read(APP / "migrations" / "0044_core_secret.py") and "core_secret_owner_name_unique" in read(APP / "models.py"))
print("       migration 0044: one CreateModel and one AddConstraint on top of the 1.17.99 leaf (0043), the only leaf; the fields match the model; no existing table is touched")

# --- 13. the backup leaves the key out and a restore refuses it
BACKUP = read(ROOT / "scripts" / "server-backup-helper.py")
must(re.search(r'paths\["system_etc_root"\] / "recovery-trust",\s+#[^\n]*\n\s+#[^\n]*\n\s+paths\["system_etc_root"\] / "secrets",', BACKUP), "the backup does not exclude the secrets folder")
must('"etc/tec-tac/secrets"' in BACKUP and BACKUP.index('"etc/tec-tac/secrets"') < BACKUP.index("allowed=_tec_tac_restore_allowed_roots(config)"), "a restore does not refuse the secrets folder")
print("       the routine backup excludes /etc/tec-tac/secrets and a restore refuses a bundle that carries it")

# ================================================================================================ Part B: install.sh
INSTALL = read(ROOT / "install.sh")
begin, end = INSTALL.index("# BEGIN secret-store-master-key"), INSTALL.index("# END secret-store-master-key")
BLOCK = INSTALL[begin:end]
must(INSTALL.count("urandom") >= 1 and BLOCK.count("/dev/urandom") == 1, "the key must come from /dev/urandom, once")
must("mv -n" in BLOCK and "NEVER overwritten" in INSTALL[:begin][-1400:], "the no-overwrite rule is missing")
must(INSTALL.index("TACTICAL_GROUP=") < begin < INSTALL.index('cat > "${MODULE_CONFIG}"'), "the key block is out of order")
bash = shutil.which("bash")


def must_mode_640(secrets):
    """The installer asked for 0640 (checked from the stubbed chmod's log, which works on any PC), and where the file system keeps modes, got it."""
    log = (secrets.parent / "chmod.log").read_text(encoding="utf-8")
    must(f"chmod 0640 {secrets.as_posix()}/" in log, log)
    if os.name != "nt":
        key = secrets / "master.key"
        must(subprocess.run(["bash", "-c", f"stat -c %a '{key.as_posix()}'"], capture_output=True, text=True, check=False).stdout.strip() == "640", "mode is not 0640")


def run_block(setup, expect_ok):
    work = Path(tempfile.mkdtemp(prefix="tectac-installkey-"))
    secrets = work / "secrets"
    script = work / "block.sh"
    block = BLOCK.replace("/etc/tec-tac/secrets", secrets.as_posix())
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "log() { printf '[TEC-TAC] %s\\n' \"$*\"; }\n"
        "fail() { printf '[TEC-TAC] ERROR: %s\\n' \"$*\" >&2; exit 1; }\n"
        "TACTICAL_GROUP=tactical\n"
        "chown() { :; }\n"
        f"chmod() {{ echo \"chmod $*\" >> '{(work / 'chmod.log').as_posix()}'; command chmod \"$@\"; }}\n"
        "install() { local d=''; for a in \"$@\"; do d=\"$a\"; done; mkdir -p \"$d\"; }\n"
        + block + "\n",
        encoding="utf-8", newline="\n")
    setup(secrets)
    result = subprocess.run([bash, str(script)], capture_output=True, text=True, timeout=60, check=False)
    must((result.returncode == 0) == expect_ok, (result.returncode, result.stdout, result.stderr))
    return secrets, result


if bash:
    probe = subprocess.run([bash, "-c", "command -v mktemp stat head mv >/dev/null && echo ok"], capture_output=True, text=True, check=False)
    if probe.stdout.strip() != "ok":
        bash = None
if bash:
    # fresh: created, 32 bytes, mode 0640, not printed
    secrets, result = run_block(lambda s: None, True)
    key = secrets / "master.key"
    must(key.is_file() and key.stat().st_size == 32, "no key was created")
    must_mode_640(secrets)
    must(not [p for p in secrets.iterdir() if p.name != "master.key"], "a temporary file was left behind")
    must("created" in result.stdout and key.read_bytes().hex() not in result.stdout + result.stderr, "the key was printed")
    first_key = key.read_bytes()
    must(first_key != bytes(32), "an all-zero key")
    # second run on the same folder: never overwritten
    again = subprocess.run([bash, str(next((secrets.parent).glob("block.sh")))], capture_output=True, text=True, timeout=60, check=False)
    must(again.returncode == 0 and key.read_bytes() == first_key and "kept" in again.stdout, (again.returncode, again.stdout, again.stderr))
    # an existing key with the wrong mode: content kept, mode put right
    chosen = bytes(range(32))

    def existing(s):
        s.mkdir()
        (s / "master.key").write_bytes(chosen)
        os.chmod(s / "master.key", 0o666)

    secrets, result = run_block(existing, True)
    must((secrets / "master.key").read_bytes() == chosen, "an existing key was overwritten")
    must_mode_640(secrets)
    # an existing key of the wrong size: stops, nothing changed (no new key)
    for size in (0, 31, 33):
        def odd(s, size=size):
            s.mkdir()
            (s / "master.key").write_bytes(b"\x07" * size)

        secrets, result = run_block(odd, False)
        must((secrets / "master.key").read_bytes() == b"\x07" * size, "a key of the wrong size was replaced")
        must("NOT replaced" in result.stderr and "offline copy" in result.stderr, result.stderr)
    # a link: stops, the target is untouched
    def linked_key(s):
        s.mkdir()
        target = s.parent / "target.key"
        target.write_bytes(b"\x09" * 32)
        try:
            os.symlink(target, s / "master.key")
        except (OSError, NotImplementedError):
            raise unittest_skip()

    class unittest_skip(Exception):
        pass

    try:
        secrets, result = run_block(linked_key, False)
        must((secrets.parent / "target.key").read_bytes() == b"\x09" * 32 and "is a link" in result.stderr)
    except unittest_skip:
        print("       (symlink case not run on this PC)")
    # the folder is a file: stops
    def folder_is_file(s):
        s.write_bytes(b"x")

    secrets, result = run_block(folder_is_file, False)
    must("real folder" in result.stderr and secrets.read_bytes() == b"x")
    print("       install.sh under bash: a fresh install makes a 32-byte 0640 key (nothing printed); an existing key is never overwritten (kept, mode put right); a wrong-size key, a link or a file in the folder's place stops the install with no change")
else:
    must('[[ -L "${SECRET_MASTER_KEY}" ]]' in BLOCK and 'elif [[ -e "${SECRET_MASTER_KEY}" ]]' in BLOCK, "static guard missing")
    print("       install.sh: bash is not usable on this PC; only the static guards ran")

# ================================================================================================ Part C: held Low 1 (repository credentials)
REPO_PATH = APP / "module_repository.py"
REPO_TREE = ast.parse(read(REPO_PATH))


def extract(tree, names):
    picked = []
    for node in tree.body:
        is_def = isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
        is_assign = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
        if is_def or is_assign:
            picked.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in picked}
    must(not (set(names) - found), f"not found in source: {sorted(set(names) - found)}")
    return picked


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    return True


CACHE_DIR = Path(tempfile.mkdtemp(prefix="repository-credentials-")) / "cache"
CACHE_DIR.mkdir(parents=True)
REPOS: list = []
INSTALLED: list = []
FETCHES: list = []
FETCH_BEHAVIOUR: dict = {}
SHA = "ab" * 32
rns: dict = {
    "json": json, "re": re, "urllib": urllib, "Path": Path, "CACHE_ROOT": CACHE_DIR, "version_satisfies": version_satisfies,
    "ModuleStateError": ModuleStateError, "Counter": Counter, "datetime": datetime, "timezone": timezone,
    "_utcnow": lambda: datetime.now(timezone.utc).isoformat(),
}
names = {
    "MAX_INDEX_BYTES", "MAX_SKIPPED_RECORDS", "MAX_SKIPPED_TEXT", "MAX_SKIPPED_REASON", "MAX_INFORMATIONAL_TEXT",
    "SKIPPED_REASON_FOR_OTHERS", "_CONTROL_CHARACTERS", "ModuleRepositoryError", "RepositoryHttpError", "RETIRED_STATUSES",
    "_LEGACY_RETIRED_ERROR", "RETIRED_MESSAGE", "RETIRED_RELEASE_REASON", "CREDENTIALS_STATUSES", "CREDENTIALS_REJECTED_MESSAGE",
    "CREDENTIALS_RELEASE_REASON", "_has_credentials", "_legacy_error_status", "_cache_credentials_rejected", "_repo_raw",
    "_skipped_summary", "repository_status", "_cache_retired", "_cached_modules", "_candidate_compatibility", "online_catalog",
    "all_repository_status", "public_repository", "_AVAILABILITY_MESSAGES", "_availability", "sync_repository",
    "stage_repository_package", "_PathUpload",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), rns)  # noqa: S102 - test only
RErr, HttpErr = rns["ModuleRepositoryError"], rns["RepositoryHttpError"]


def fake_fetch(url, maximum, timeout=12, *, trust="custom"):
    FETCHES.append(url)
    behaviour = FETCH_BEHAVIOUR["next"]
    if isinstance(behaviour, BaseException):
        raise behaviour
    return behaviour


def raw_repo(rid):
    for item in REPOS:
        if item["id"] == rid:
            return dict(item)
    raise RErr(f"Repository {rid!r} was not found.")


rns["_fetch"] = fake_fetch
rns["_accepted_releases"] = lambda raw_modules, repo: ([dict(i) for i in raw_modules], [])
rns["_atomic_repo_json"] = lambda path, payload: Path(path).write_text(json.dumps(payload), encoding="utf-8")
rns["list_repositories"] = lambda: [rns["public_repository"](dict(r)) for r in REPOS]
rns["_repo"] = raw_repo
rns["installed_catalog_v2"] = lambda: [dict(i) for i in INSTALLED]
rns["_check_runtime_requirements"] = lambda requires: []
TOKEN = "tok-9d41-private-credential"


def repo(rid="techflow", token=None, priority=10, trust="official"):
    record = {"id": rid, "name": rid.title(), "url": f"https://{rid}.test/index.json", "trust": trust, "priority": priority, "enabled": True}
    if token:
        record["auth_token"] = token
    return record


def entry(module_id, version="0.4.0"):
    return {"id": module_id, "name": module_id.title(), "version": version, "download_url": f"https://x.test/{module_id}.zip",
            "sha256": SHA, "dependencies": {}, "optional_dependencies": {}, "requires": {}}


def write_cache(rid, modules=None, **extra):
    payload = {"schema": 1, "repository_id": rid, "status": "ok", "error": None, "modules": modules or [], "skipped": [],
               "skipped_count": 0, "synced_at": "2026-10-30T00:00:00+00:00"}
    payload.update(extra)
    (CACHE_DIR / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")


def read_cache(rid):
    return json.loads((CACHE_DIR / f"{rid}.json").read_text(encoding="utf-8"))


def rreset(repos):
    for item in CACHE_DIR.glob("*.json"):
        item.unlink()
    REPOS[:] = repos
    INSTALLED[:] = []
    FETCHES.clear()


def sync_fails(exc, rid="techflow"):
    FETCH_BEHAVIOUR["next"] = exc
    try:
        rns["sync_repository"](rid)
    except RErr:
        return
    raise AssertionError("the sync should have failed")


MSG = rns["CREDENTIALS_REJECTED_MESSAGE"]
must("retired" not in MSG.lower() and "no longer offers" not in MSG and "credentials" in MSG and "Settings → Modules" in MSG, MSG)
# C1. credentialed 401 and 403: credentials rejected, not retired, nothing offered
for code in (401, 403):
    rreset([repo(token=TOKEN)])
    write_cache("techflow", [entry("alpha")])
    sync_fails(HttpErr(f"Repository request returned HTTP {code}.", code))
    cache = read_cache("techflow")
    must(cache["credentials_rejected"] is True and cache["retired"] is False and cache["error_status"] == code, cache)
    sync = rns["repository_status"]("techflow")["sync"]
    must(sync["credentials_rejected"] is True and sync["retired"] is False, sync)
    cat = rns["online_catalog"]()
    must(cat["availability"]["state"] == "credentials_rejected" and cat["availability"]["message"] == MSG, cat["availability"])
    must(cat["availability"]["credentials_rejected_repositories"] == 1 and cat["availability"]["retired_repositories"] == 0, cat["availability"])
    must(cat["modules"] == [] and cat["count"] == 0, "something is still offered")
    must(TOKEN not in json.dumps(cat) and TOKEN not in json.dumps(read_cache("techflow")), "the credential leaked")
    releases = rns["_cached_modules"](rns["list_repositories"]()[0])
    must(releases and all(r["download_unavailable"] and r["download_unavailable_state"] == "credentials_rejected" for r in releases), releases)
    try:
        rns["stage_repository_package"]("techflow", "alpha")
    except RErr as exc:
        must(str(exc) == MSG, str(exc))
    else:
        raise AssertionError("a release of a repository that refused its credentials was staged")
    must(FETCHES == [] or all("index.json" in url for url in FETCHES), FETCHES)
    must(not [u for u in FETCHES if u.endswith(".zip")], "a package download was attempted")
print("       a repository with credentials that answers 401 or 403: credentials_rejected, the plain message, retired false, nothing offered or staged, no download, no credential in any answer")

# C2. the public default (no credentials) keeps the 1.17.99 behaviour
for code in (401, 403):
    rreset([repo()])
    write_cache("techflow", [entry("alpha")])
    sync_fails(HttpErr(f"Repository request returned HTTP {code}.", code))
    cache = read_cache("techflow")
    must(cache["retired"] is True and cache.get("credentials_rejected") is False, cache)
    cat = rns["online_catalog"]()
    must(cat["availability"]["state"] == "repository_retired" and cat["availability"]["message"] == rns["RETIRED_MESSAGE"], cat["availability"])
    must(cat["availability"]["credentials_rejected_repositories"] == 0 and cat["modules"] == [])
    try:
        rns["stage_repository_package"]("techflow", "alpha")
    except RErr as exc:
        must(str(exc) == rns["RETIRED_MESSAGE"], str(exc))
    else:
        raise AssertionError("a retired release was staged")
print("       a repository with no credentials (the public default): 401 and 403 are still retired, with the 1.17.99 message")

# C3. 404 and 410 are retired for a credentialed repository too; 5xx, timeouts and network errors change nothing
for code in (404, 410):
    rreset([repo(token=TOKEN)])
    write_cache("techflow", [entry("alpha")])
    sync_fails(HttpErr(f"Repository request returned HTTP {code}.", code))
    cache = read_cache("techflow")
    must(cache["retired"] is True and cache["credentials_rejected"] is False, cache)
    must(rns["online_catalog"]()["availability"]["state"] == "repository_retired")
for exc in (HttpErr("Repository request returned HTTP 500.", 500), HttpErr("Repository request returned HTTP 503.", 503),
            HttpErr("Repository request returned HTTP 429.", 429), TimeoutError("timed out"),
            RErr("Repository request failed due to a network or TLS error.")):
    rreset([repo(token=TOKEN)])
    write_cache("techflow", [entry("alpha")])
    sync_fails(exc)
    cache = read_cache("techflow")
    must("retired" not in cache and "credentials_rejected" not in cache, cache)
    cat = rns["online_catalog"]()
    must(cat["availability"]["state"] == "ready" and [m["id"] for m in cat["modules"]] == ["alpha"], cat["availability"])
print("       404 and 410 are retired for a credentialed repository; 5xx, 429, timeouts and network errors change nothing and the old list stays")

# C4. recovery, a transient fault after a refusal, a retired cache that now refuses, mixed repositories
rreset([repo(token=TOKEN)])
write_cache("techflow", [entry("alpha")])
sync_fails(HttpErr("Repository request returned HTTP 401.", 401))
sync_fails(HttpErr("Repository request returned HTTP 503.", 503))
must(read_cache("techflow")["credentials_rejected"] is True, "a transient failure cleared the refusal")
must(rns["online_catalog"]()["availability"]["state"] == "credentials_rejected")
FETCH_BEHAVIOUR["next"] = json.dumps({"schema": 1, "modules": [entry("alpha", "0.5.0")]}).encode("utf-8")
rns["sync_repository"]("techflow")
cache = read_cache("techflow")
must("credentials_rejected" not in cache and "retired" not in cache and cache["status"] == "ok", cache)
must(rns["online_catalog"]()["availability"]["state"] == "ready", "a good sync did not recover")
rreset([repo(token=TOKEN)])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 404.", retired=True, error_status=404)
sync_fails(HttpErr("Repository request returned HTTP 403.", 403))
cache = read_cache("techflow")
must(cache["retired"] is False and cache["credentials_rejected"] is True, cache)
rreset([repo("old", token=TOKEN, priority=5), repo("fresh", priority=20)])
write_cache("old", [entry("alpha")], status="error", error="x", credentials_rejected=True, error_status=401)
write_cache("fresh", [entry("beta")])
cat = rns["online_catalog"]()
must([m["id"] for m in cat["modules"]] == ["beta"] and cat["availability"]["state"] == "ready", cat["availability"])
rreset([repo("old", token=TOKEN, priority=5), repo("gone", priority=20)])
write_cache("old", [entry("alpha")], status="error", error="x", credentials_rejected=True, error_status=401)
write_cache("gone", [entry("beta")], status="error", error="x", retired=True, error_status=404)
cat = rns["online_catalog"]()
must(cat["availability"]["state"] == "credentials_rejected" and cat["availability"]["retired_repositories"] == 1 and cat["availability"]["credentials_rejected_repositories"] == 1, cat["availability"])
print("       recovery by a good sync; a 5xx after a refusal keeps it; a retired cache that now refuses becomes credentials_rejected; a healthy repository beside a refused one stays offered; one retired plus one refused says credentials_rejected")

# C5. a cache written by 1.17.98 (no flags, error text only)
for code, token, expected in ((401, TOKEN, "rejected"), (403, TOKEN, "rejected"), (401, None, "retired"), (403, None, "retired"),
                              (404, TOKEN, "retired"), (410, TOKEN, "retired")):
    rreset([repo(token=token)])
    write_cache("techflow", [entry("alpha")], status="error", error=f"Repository request returned HTTP {code}.")
    sync = rns["repository_status"]("techflow")["sync"]
    must(sync["credentials_rejected"] is (expected == "rejected") and sync["retired"] is (expected == "retired"), (code, token, sync))
    must(rns["online_catalog"]()["modules"] == [], "a 1.17.98 cache was offered")
rreset([repo(token=TOKEN)])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 503.")
sync = rns["repository_status"]("techflow")["sync"]
must(not sync["retired"] and not sync["credentials_rejected"] and [m["id"] for m in rns["online_catalog"]()["modules"]] == ["alpha"])
rreset([repo(token=TOKEN)])
(CACHE_DIR / "techflow.json").write_text("{not json", encoding="utf-8")
sync = rns["repository_status"]("techflow")["sync"]
must(sync["status"] == "error" and not sync["retired"] and not sync["credentials_rejected"], sync)
print("       a 1.17.98 cache is read from its error text: 401 and 403 with credentials are credentials_rejected, without them retired, 404 and 410 retired, 503 neither; a corrupt file neither")

# C6. whitespace credentials are none
must(rns["_has_credentials"]({"auth_token": "  "}) is False and rns["_has_credentials"]({"auth_token": 5}) is False and rns["_has_credentials"]({}) is False)
must(rns["_has_credentials"]({"auth_token": "x"}) is True)
print("       an empty, blank or non-text credential counts as none")

# ================================================================================================ Part D: held Low 2 (helper keeps the Licensing Server address)
HELPER_PATH = ROOT / "scripts" / "system-update-helper.py"
HELPER = read(HELPER_PATH)
HTREE = ast.parse(HELPER)
WORK = Path(tempfile.mkdtemp(prefix="tectac-helper-"))
CONF = WORK / "tec-tac.conf"
CONF_STATE = {"uid": 0, "mode": 0o100644, "link": False}


class FakeConfig(os.PathLike):
    """A config file whose owner and mode are scripted (this PC has no root). The bytes are a real file."""

    parent = WORK

    def __fspath__(self):
        return str(CONF)

    def is_symlink(self):
        return CONF_STATE["link"]

    def is_file(self):
        return CONF.is_file()

    def stat(self):
        return SimpleNamespace(st_uid=CONF_STATE["uid"], st_mode=CONF_STATE["mode"])

    def read_text(self, encoding="utf-8"):
        with open(CONF, encoding=encoding, newline="") as handle:
            return handle.read()


import tempfile as _tempfile

hns = {
    "CONFIG": FakeConfig(), "tempfile": _tempfile, "Path": Path,
    "os": SimpleNamespace(write=os.write, fchmod=lambda *a: None, fchown=lambda *a: None, fsync=os.fsync, close=os.close, replace=os.replace),
}
wanted = {"LICENSING_SERVER_URL_KEY", "read_config_line", "reapply_licensing_server_url", "_set_config_line"}
exec(compile(ast.Module(body=extract(HTREE, wanted), type_ignores=[]), str(HELPER_PATH), "exec"), hns)  # noqa: S102 - test only
reapply, read_line, KEY = hns["reapply_licensing_server_url"], hns["read_config_line"], hns["LICENSING_SERVER_URL_KEY"]
must(KEY == "TEC_TAC_LICENSING_SERVER_URL")


class Log:
    def __init__(self):
        self.text = ""

    def write(self, value):
        self.text += value

    def flush(self):
        pass


def set_conf(text, **state):
    CONF.write_bytes(text.encode("utf-8"))
    CONF_STATE.update({"uid": 0, "mode": 0o100644, "link": False})
    CONF_STATE.update(state)


OLD_INSTALLER_CONF = "# Tec-Tac installation layout. Managed by install.sh.\nTEC_TAC_ROOT=/opt/tec-tac\nTEC_TAC_API_URL=https://x\n"
CUSTOM = "https://lic.example.test/prefix"
# D1. the pre-rollback config has the key, the old installer's config does not: put back exactly
set_conf(OLD_INSTALLER_CONF + f"{KEY}={CUSTOM}\n")
before = read_line(KEY)
must(before == CUSTOM, before)
set_conf(OLD_INSTALLER_CONF)  # what an installer older than 1.17.99 writes
log = Log()
must(reapply(before, log) is True, "the key was not put back")
must(read_line(KEY) == CUSTOM and CONF.read_text(encoding="utf-8").count(f"{KEY}=") == 1, CONF.read_text(encoding="utf-8"))
must("put back" in log.text and CUSTOM not in log.text, log.text)
must("TEC_TAC_ROOT=/opt/tec-tac" in CONF.read_text(encoding="utf-8"), "the rest of the config changed")
# D2. a 1.17.99 or later installer kept its own line: untouched, even when it differs
set_conf(OLD_INSTALLER_CONF + f"{KEY}=https://kept.example.test\n")
before_text = CONF.read_text(encoding="utf-8")
must(reapply(CUSTOM, Log()) is False and CONF.read_text(encoding="utf-8") == before_text)
# D3. there was no key before: nothing is added
set_conf(OLD_INSTALLER_CONF)
must(read_line(KEY) is None and reapply(None, Log()) is False and KEY not in CONF.read_text(encoding="utf-8"))
# D4. an invalid value is still put back as data (Core ignores a bad one itself), and the last line wins
set_conf(OLD_INSTALLER_CONF + f"{KEY}=http://bad\n{KEY}=http://worse value\n")
must(read_line(KEY) == "http://worse value")
set_conf(OLD_INSTALLER_CONF)
must(reapply("http://worse value", Log()) is True and read_line(KEY) == "http://worse value")
# D5. a config that cannot be trusted or written never fails the rollback
for state in ({"uid": 1000}, {"mode": 0o100666}, {"link": True}):
    set_conf(OLD_INSTALLER_CONF, **state)
    log = Log()
    must(read_line(KEY) is None, state)
    result = reapply(CUSTOM, log)
    must(result is False and KEY not in CONF.read_text(encoding="utf-8"), state)
    must("could not be put back" in log.text and CUSTOM not in log.text, (state, log.text))
# D6. a value with a line break is refused as data, not written
set_conf(OLD_INSTALLER_CONF)
log = Log()
must(reapply("https://a\nEVIL=1", log) is False and "EVIL" not in CONF.read_text(encoding="utf-8") and "could not be put back" in log.text, log.text)
print("       the helper puts TEC_TAC_LICENSING_SERVER_URL back after an installer older than 1.17.99 dropped it (exactly, once, rest of the config untouched, value not logged); a newer installer's line is kept; no key before means none added; an untrusted config or a line break never fails the rollback")

# D7. both call sites read the line BEFORE the installer and put it back AFTER it, for the framework only
for marker in ("rc = run_install(component, staged, out, source_checkout=target)", "rollback_rc = run_install(component, staged, log, source_checkout=target)"):
    at = HELPER.index(marker)
    must("licensing_url_before = read_config_line(LICENSING_SERVER_URL_KEY)" in HELPER[at - 400:at], f"not read before {marker}")
    tail = HELPER[at:at + 600]
    must(tail.index("repin_framework_source(") < tail.index("reapply_licensing_server_url(licensing_url_before"), f"not put back after {marker}")
    must('if component == "framework"' in HELPER[at - 400:at] and "framework" in tail[:500], marker)
must(HELPER.count("reapply_licensing_server_url(licensing_url_before") == 2 and HELPER.count("run_install(component, staged,") == 3, "unexpected call count")
update_call = HELPER.index("rc = run_install(component, staged, log, source_checkout=target)")
must("reapply_licensing_server_url" not in HELPER[update_call - 300:update_call + 300], "a forward update must keep using the new installer's own line")
print("       the rollback and the restore both read the key before the installer and put it back after it; a forward update does not (its installer is the new one)")

# ================================================================================================ docs, release notes, contracts
FOOTER = "Tech Flow Dynamics · techxflow.co.za"
for name in ("secret-store.md", "module-repositories.md", "troubleshooting-diagnostics.md"):
    text = read(ROOT / "docs" / name).rstrip()
    must(text.endswith(FOOTER) and text.count(FOOTER) == 1, f"{name}: the footer must be last, once")
DOC = read(ROOT / "docs" / "secret-store.md")
TS = read(ROOT / "docs" / "troubleshooting-diagnostics.md")
REPOS_DOC = read(ROOT / "docs" / "module-repositories.md")
for code in ("master_key_unavailable", "secret_unreadable", "caller_not_allowed", "audit_failed", "invalid_name", "invalid_value", "secret_limit"):
    must(code in DOC and code in TS, f"{code} is not in the help and the troubleshooting text")
for reason in ("missing", "unreadable", "not_a_file", "wrong_owner", "wrong_mode", "wrong_size", "folder_unsafe", "placeholder"):
    must(f"`{reason}`" in DOC and f"`{reason}`" in TS, reason)
for text in (DOC, TS):
    must("sudo ls -l /etc/tec-tac/secrets/master.key" in text, "the key check command is missing")
must("custom:decrypt-failed" in DOC and "offline copy" in DOC and "not in a backup" in DOC.lower().replace("**", ""), "help text incomplete")
must("credentials_rejected" in REPOS_DOC and "credentials_rejected" in TS and "put back" in REPOS_DOC and "could not be put back" in TS, "the Low 1 or Low 2 text is missing")
must("refused the credentials set up for it" in REPOS_DOC, "the credentials message is not in the help")
NOTES = read(ROOT / "RELEASE_NOTES_1.17.100.md")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.99.md").is_file() and not (ROOT / "RELEASE_NOTES_1.17.99.md").exists(), "the 1.17.99 notes were not moved")
must(sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md")) == ["RELEASE_NOTES_1.17.100.md"], "exactly one root release note")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "## Checks on the test server", "## Not done here"):
    must(heading in NOTES, heading)
must("stat -c" in NOTES and "master.key" in NOTES and "AD-57" in NOTES and "AD-56" in NOTES, "the notes miss the key check or the decisions")
must(read(ROOT / "VERSION").strip() == "1.17.100" and json.loads(read(ROOT / "tec_tac_package.json"))["version"] == "1.17.100", "version not bumped")

# no module under modules/ already calls a name that changed shape
MODULES = ROOT.parents[1] / "modules"
if MODULES.is_dir():
    hits = []
    for path in MODULES.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "tec_tac.secret_store" in text or "core.secrets" in text:
            hits.append(str(path.relative_to(MODULES)))
    print(f"       modules/ users of the new store (informational): {hits or 'none'}")
    for path in MODULES.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        must("module_repository" not in text and "online_catalog" not in text and "credentials_rejected" not in text, f"a module uses the repository code: {path}")
print("       help and troubleshooting cover every code and reason, the footer is last, the 1.17.99 notes moved, the version is bumped")
print("[TEST] PASS secret store and held lows 1.17.100")
