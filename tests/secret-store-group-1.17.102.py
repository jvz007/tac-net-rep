#!/usr/bin/env python3
"""1.17.102: the secret store key group has one source, and each audit row type has its own cap.

Reuses the fakes of tests/secret-store-1.17.100.py (as tests/secret-store-hardening-1.17.101.py does).

1. install.sh records the group it gave the key in /etc/tec-tac/secrets/key-group; Core reads it (a record that is missing, not owned by
   root, group writable, or not a plain resolvable name is a fault). Tested with `tactical` and with a non-`tactical` group.
2. Deny rows and decrypt-failed rows have separate caps: a flood of deny rows cannot silence decrypt-failed rows.
3. install.sh (no CR, records the group), docs, troubleshooting (footer last), release notes, version, line endings.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
BASE = (HERE / "secret-store-1.17.100.py").read_text(encoding="utf-8")
cut = BASE.index("# --- 1. round trip")
harness = BASE[:cut].replace("from __future__ import annotations\n", "", 1)
NS: dict = {"__file__": str(HERE / "secret-store-1.17.100.py"), "__name__": "harness"}
exec(compile(harness, str(HERE / "secret-store-1.17.100.py"), "exec"), NS)  # noqa: S102 - the shared test harness
must, reset, ss, LIC, CORE, AUDIT, KEY_STATE, SENTINEL = (NS[k] for k in ("must", "reset", "ss", "LIC", "CORE", "AUDIT", "KEY_STATE", "SENTINEL"))
refused, ROOT, read = NS["refused"], NS["ROOT"], NS["read"]

# ---- 1. one source for the group
SOURCE = (ROOT / "framwork" / "tec_tac" / "secret_store.py").read_text(encoding="utf-8")
must("KEY_GROUP =" not in SOURCE, "a hard-coded group is left")
GROUP_FILE = Path(tempfile.mkdtemp()) / "key-group"
ss.KEY_GROUP_PATH = GROUP_FILE
GROUPS = {"tactical": 1001, "svc-rmm": 2002}


def getgrnam(name):
    if name not in GROUPS:
        raise KeyError(name)
    return SimpleNamespace(gr_gid=GROUPS[name])


sys.modules["grp"] = SimpleNamespace(getgrnam=getgrnam)  # this PC has no grp module
local: dict = {}
start, stop = SOURCE.index("def _key_group_id"), SOURCE.index("def _key_fault")
exec(compile(SOURCE[start:stop], "secret_store_group", "exec"), ss.__dict__, local)  # noqa: S102 - the real functions, on the module's globals
REAL_ID = local["_key_group_id"]
KEY_FSTAT = ss._fstat
FILE_STATE = {"uid": 0, "mode": 0o640}


def routed_fstat(fd):
    info = KEY_FSTAT(fd)
    if info.st_size == 32:  # the key file: the harness fake
        return info
    return SimpleNamespace(st_mode=(info.st_mode & ~0o777) | FILE_STATE["mode"], st_uid=FILE_STATE["uid"], st_gid=info.st_gid, st_size=info.st_size)


ss._fstat = routed_fstat


def run(record, key_gid):
    """Core's check with the real group lookup: a group record with this text (or none) and a key file in group ``key_gid``."""
    reset()
    ss._key_group_id = lambda: 1001
    LIC(ss.put, "licence_key", SENTINEL)
    ss._key_group_id = REAL_ID
    GROUP_FILE.unlink(missing_ok=True)
    if record is not None:
        GROUP_FILE.write_bytes(record.encode("ascii"))
    KEY_STATE["gid"] = key_gid
    FILE_STATE.update(uid=0, mode=0o640)


for record, gid in (("tactical\n", 1001), ("svc-rmm\n", 2002)):
    run(record, gid)
    must(LIC(ss.get, "licence_key") == SENTINEL, f"{record.strip()}: the right group must pass")
    run(record, 4242)
    must(refused(LIC, ss.get, "licence_key", code="master_key_unavailable").reason == "wrong_group")
run("svc-rmm\n", 1001)  # the record is the one source: a key left in tactical does not pass
must(refused(LIC, ss.put, "licence_key", "x", code="master_key_unavailable").reason == "wrong_group")
for record in (None, "", "no-such-group\n", "tactical;rm\n", "../etc\n", "x" * 70 + "\n"):
    run(record, 1001)
    must(refused(LIC, ss.get, "licence_key", code="master_key_unavailable").reason == "wrong_group", repr(record))
run("tactical\n", 1001)
FILE_STATE["uid"] = 1000
must(refused(LIC, ss.get, "licence_key", code="master_key_unavailable").reason == "wrong_group", "a record not owned by root")
FILE_STATE.update(uid=0, mode=0o664)
must(refused(LIC, ss.get, "licence_key", code="master_key_unavailable").reason == "wrong_group", "a group writable record")
FILE_STATE.update(uid=0, mode=0o640)
must(LIC(ss.get, "licence_key") == SENTINEL)
print("       item 1: Core reads the group install.sh recorded; tactical and a non-tactical group pass; a wrong, missing, odd or unsafe record is wrong_group")

# ---- 2. separate caps per row type
ss._fstat = KEY_FSTAT
ss._key_group_id = lambda: 1001
reset()
now = [1000.0]
ss._monotonic = lambda: now[0]
for i in range(ss._AUDIT_REPEAT_MAX + 50):
    refused(CORE, ss.get, f"flood{i}", code="caller_not_allowed")
must(len([a for a in AUDIT if a["action"] == "deny"]) == ss._AUDIT_REPEAT_MAX, "deny rows exceeded their cap")
scope = SimpleNamespace(module_id="licensing")
must(ss._repeat_gate(scope, "licence_key", "secret_unreadable") == 0, "a full deny table silenced a decrypt-failed row")
must(ss._repeat_gate(scope, "licence_key", "secret_unreadable") is None, "the repeat limit still applies")
for i in range(ss._AUDIT_REPEAT_MAX + 50):
    ss._repeat_gate(scope, f"n{i}", "secret_unreadable")
must(sum(1 for k in ss._repeat_seen if k[2] == "secret_unreadable") <= ss._AUDIT_REPEAT_MAX, "decrypt-failed cap")
must(ss._repeat_gate(scope, "late", "caller_not_allowed") is None, "the deny cap is still full")
now[0] += ss.AUDIT_REPEAT_SECONDS + 1
must(ss._repeat_gate(scope, "late", "caller_not_allowed") == 0, "expired entries of one type were not purged")
ss._monotonic = __import__("time").monotonic
print("       item 2: deny rows and decrypt-failed rows are capped separately (512 each)")

# ---- 3. install.sh, docs, notes, version
raw = (ROOT / "install.sh").read_bytes()
must(b"\r" not in raw, "install.sh has CR")
must(b"\r\n" in (ROOT / "framwork" / "tec_tac" / "secret_store.py").read_bytes(), "secret_store.py lost its CRLF")
INSTALL = raw.decode()
block = INSTALL[INSTALL.index("# BEGIN secret-store-master-key"):INSTALL.index("# END secret-store-master-key")]
must('"${SECRETS_ROOT}/key-group"' in block and "printf '%s\\n' \"${TACTICAL_GROUP}\"" in block, "install.sh does not record the group")
must('chown root:"${TACTICAL_GROUP}" "${SECRET_GROUP_FILE}"' in block and 'chmod 0640 "${SECRET_GROUP_FILE}"' in block, "the record's owner and mode")
try:
    syntax = subprocess.run(["bash", "-n", "install.sh"], cwd=str(ROOT), capture_output=True, text=True, check=False)
except OSError:
    print("       bash is not usable here; install.sh syntax not checked")
else:
    must(syntax.returncode == 0, syntax.stderr)
DOC, TS = read(ROOT / "docs" / "secret-store.md"), read(ROOT / "docs" / "troubleshooting-diagnostics.md")
for text, label in ((DOC, "secret-store.md"), (TS, "troubleshooting")):
    must("key-group" in text, f"{label} misses key-group")
    must(text.rstrip().endswith("Tech Flow Dynamics · techxflow.co.za") and text.count("Tech Flow Dynamics · techxflow.co.za") == 1, f"{label} footer")
NOTES = read(ROOT / "RELEASE_NOTES_1.17.102.md")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "## Checks on the test server", "## Not done here"):
    must(heading in NOTES, heading)
must("FAIL" in NOTES and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.101.md").is_file(), "notes or move")
must(sorted(p.name for p in ROOT.glob("RELEASE_NOTES_*.md")) == ["RELEASE_NOTES_1.17.102.md"], "exactly one root release note")
must(read(ROOT / "VERSION").strip() == "1.17.102" and json.loads(read(ROOT / "tec_tac_package.json"))["version"] == "1.17.102", "version")
print("[TEST] PASS secret store group 1.17.102")
