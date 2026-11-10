#!/usr/bin/env python3
"""1.17.101: hardening of the Core secret store (the Lows and Mediums held from 1.17.100).

The harness of tests/secret-store-1.17.100.py (a fake table, a fake audit writer, the real caller check and the real cryptography) is
reused: its source up to the first numbered check is run here, so both tests stand on the same fakes.

1. get() asks for the caller with a short cache (the event jobs snapshot), the other operations with none.
2. A read updates its counters at most once a minute, as F("read_count") + 1 inside its own savepoint; a failing update neither fails
   the read nor leaves the caller's transaction poisoned.
3. No function in secret_store.py (public, underscore, module level or nested) takes an owner argument; only the five public functions
   (and the read counter, which gets a row object) touch the table; the verified scope object is made in one place.
4. Deny and decrypt-failed rows: at most one per owner, name and reason per interval; the next row says how many were left out; a
   flood of different names cannot grow the memory or the log.
5. A concurrent first put (IntegrityError) is retried once as a replace; a second collision is secret_conflict (409).
6. The key file must be in the tactical group; the key folder is checked with lstat (a link is unsafe).
7. install.sh: mv -n's exit status is handled (a non-zero status after the move is fine; a non-zero status with no key is a clear
   failure), then the key's owner, group, mode and size are verified.
Also: docs, troubleshooting (footer last), release notes, version.
"""
from __future__ import annotations

import ast
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = (HERE / "secret-store-1.17.100.py").read_text(encoding="utf-8")
cut = BASE.index("# --- 1. round trip")
harness = BASE[:cut].replace("from __future__ import annotations\n", "", 1)
NS: dict = {"__file__": str(HERE / "secret-store-1.17.100.py"), "__name__": "harness"}
exec(compile(harness, str(HERE / "secret-store-1.17.100.py"), "exec"), NS)  # noqa: S102 - the shared test harness

must, reset, ss, LIC, HALO, CORE, TABLE, AUDIT, LOGS, ORDER = (NS[k] for k in ("must", "reset", "ss", "LIC", "HALO", "CORE", "TABLE", "AUDIT", "LOGS", "ORDER"))
refused, SENTINEL, ROOT, APP, read = NS["refused"], NS["SENTINEL"], NS["ROOT"], NS["APP"], NS["read"]
KEY_STATE, FOLDER_STATE, KEY_FILE, ENABLED, F, Atomic = NS["KEY_STATE"], NS["FOLDER_STATE"], NS["KEY_FILE"], NS["ENABLED"], NS["F"], NS["_Atomic"]
SOURCE = read(APP / "secret_store.py")
TREE = ast.parse(SOURCE)

# ---------------------------------------------------------------------------------------------------------------- 1. caller cache

seen: list = []
real_check = ss.calling_module_for_core_provider


# the spy is compiled under secret_store.py's own file name, so the caller walk skips its frame like any frame of the provider
SPY_SRC = (
    'def make(real, seen):\n'
    '    def spy(**kwargs):\n'
    '        seen.append(kwargs.get("cache_seconds"))\n'
    '        return real(**kwargs)\n'
    '    return spy\n'
)
spy = NS["compile_as"](str(APP / "secret_store.py"), SPY_SRC)["make"](real_check, seen)
ss.calling_module_for_core_provider = spy
reset()
LIC(ss.put, "k", "v")
LIC(ss.get, "k")
LIC(ss.configured, "k")
LIC(ss.list_names)
LIC(ss.delete, "k")
ss.calling_module_for_core_provider = real_check
must(seen == [0, ss.CALLER_CACHE_SECONDS, 0, 0, 0], seen)
must(0 < ss.CALLER_CACHE_SECONDS <= 10, ss.CALLER_CACHE_SECONDS)
must("cache_seconds=0" not in SOURCE.replace("cache_seconds: float = 0", ""), "a literal cache_seconds=0 call is back")
from tec_tac import event_jobs_policy

must(ss.CALLER_CACHE_SECONDS == event_jobs_policy.ENABLED_CACHE_SECONDS, "get() must use the event jobs snapshot time")
print("       item 1: get() asks for its caller with the event jobs snapshot (5 s); put, delete, configured and list_names read the state every time")

# ---------------------------------------------------------------------------------------------------------------- 2. read counting
reset()
LIC(ss.put, "k", SENTINEL)
real_now = ss._now
from datetime import datetime, timedelta, timezone

base_time = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
offset = [0]
ss._now = lambda: base_time + timedelta(seconds=offset[0])
row = TABLE.rows[0]
ORDER.clear()
for _ in range(5):
    must(LIC(ss.get, "k") == SENTINEL)
updates = [o for o in ORDER if o[0] == "update"]
must(len(updates) == 1 and row.read_count == 1, (updates, row.read_count))  # five reads in one minute: one update
# the update ran in its own savepoint (begin ... commit around it) and used F("read_count") + 1
at = next(i for i, o in enumerate(ORDER) if o[0] == "update")
must(ORDER[at - 1] == ("begin",) and ORDER[at + 1] == ("commit",), ORDER)
offset[0] = 59
LIC(ss.get, "k")
must(row.read_count == 1, "updated inside the throttle window")
offset[0] = 61
LIC(ss.get, "k")
must(row.read_count == 2 and row.last_read_at == base_time + timedelta(seconds=61), (row.read_count, row.last_read_at))
count_src = SOURCE[SOURCE.index("def _count_read") : SOURCE.index("# --- the public functions")]
must('F("read_count") + 1' in count_src and "int(row.read_count" not in SOURCE and "READ_STATS_SECONDS" in count_src, "the update is not F()+1 and throttled")
# a failing update never fails the read and never touches the caller's transaction: it is inside its own atomic
row.last_read_at = None
orig_update = NS["Query"].update


def boom(self, **kwargs):
    raise RuntimeError("database says no")


NS["Query"].update = boom
ORDER.clear()
LOGS.clear()
must(LIC(ss.get, "k") == SENTINEL, "a failed statistics update failed the read")
must(ORDER[:1] == [("begin",)] and ("rollback",) in ORDER and ("commit",) not in ORDER, ORDER)  # rolled back to its own savepoint
must(any("read statistics" in line for line in LOGS) and not any(SENTINEL in line or "database says no" in line for line in LOGS), LOGS)
NS["Query"].update = orig_update
ss._now = real_now
print("       item 2: five reads in a minute make one F()+1 update in its own savepoint; the next one is due after 60 s; a failing update neither fails the read nor leaves the caller's transaction poisoned")

# ---------------------------------------------------------------------------------------------------------------- 3. no owner argument
OWNER_NAMES = {"owner", "owner_module", "owner_id", "module_id", "module", "scope_owner"}
FORBIDDEN_ARGS = []


def all_functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            yield node


for fn in all_functions(TREE):
    args = fn.args
    names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs] + ([args.vararg.arg] if args.vararg else []) + ([args.kwarg.arg] if args.kwarg else [])
    for name in names:
        if name in OWNER_NAMES or "owner" in name.lower():
            FORBIDDEN_ARGS.append((getattr(fn, "name", "<lambda>"), name))
must(not FORBIDDEN_ARGS, f"a function takes an owner argument: {FORBIDDEN_ARGS}")
# the same check on the live module, by signature: nothing importable takes an owner
import inspect

for attr, value in vars(ss).items():
    if inspect.isfunction(value) and value.__module__ == ss.__name__:
        must(not [p for p in inspect.signature(value).parameters if "owner" in p.lower()], f"{attr} takes an owner")
# which functions touch the table: only the five public ones, plus the read counter (it gets a row, not an owner)
PUBLIC = {"put", "get", "delete", "configured", "list_names"}
touch = {fn.name for fn in all_functions(TREE) if isinstance(fn, ast.FunctionDef) and "_table(" in ast.get_source_segment(SOURCE, fn)}
# 1.17.113: plus the one private Core-internal read for server_maintenance (frame-checked, owner found from the signed registry, not a contract)
PRIVATE_CORE = {"_read_for_server_maintenance"}
must(touch - {"_table"} == PUBLIC | {"_count_read"} | PRIVATE_CORE, touch)
own_filter = {fn.name for fn in all_functions(TREE) if isinstance(fn, ast.FunctionDef) and "owner_module=" in ast.get_source_segment(SOURCE, fn)}
must(own_filter <= PUBLIC | PRIVATE_CORE, own_filter)
must(not any(n.startswith("_") and n in {"_put", "_get", "_delete", "_configured", "_list_names"} for n in vars(ss)), "an owner-taking helper is back")
# the verified scope is built in one place (plus the fixed unverified one)
# 1.17.113: the private server-maintenance read makes one more, from the owner it found in the ROOT registry after its own checks
must(SOURCE.count("_Scope(") == 3 and "    scope = _Scope(owner)" in SOURCE and "_UNVERIFIED = _Scope(" in SOURCE and "return None if identity is None else _Scope(identity.module_id)" in SOURCE, SOURCE.count("_Scope("))
# behaviour is unchanged: another module still sees nothing of the owner's
reset()
LIC(ss.put, "licence_key", SENTINEL)
must(HALO(ss.get, "licence_key") is None and LIC(ss.get, "licence_key") == SENTINEL)
refused(CORE, ss.get, "licence_key", code="caller_not_allowed")
# a module cannot reach another module's rows through any importable name
for attr in vars(ss):
    must(attr.lower().lstrip("_") not in {"put_for", "get_for", "read_as"}, attr)
print("       item 3: no function in secret_store.py takes an owner argument (checked by AST and by signature); only put, get, delete, configured, list_names and the read counter touch the table; the owner-taking helpers are gone")

# ---------------------------------------------------------------------------------------------------------------- 4. audit rate limit
reset()
now = [5000.0]
ss._monotonic = lambda: now[0]
for _ in range(50):
    refused(CORE, ss.get, "licence_key", code="caller_not_allowed")
denies = [a for a in AUDIT if a["action"] == "deny"]
must(len(denies) == 1, len(denies))
now[0] += ss.AUDIT_REPEAT_SECONDS - 1
refused(CORE, ss.get, "licence_key", code="caller_not_allowed")
must(len([a for a in AUDIT if a["action"] == "deny"]) == 1, "a row inside the interval")
now[0] += 2
refused(CORE, ss.get, "licence_key", code="caller_not_allowed")
denies = [a for a in AUDIT if a["action"] == "deny"]
must(len(denies) == 2 and denies[1]["metadata"]["left_out_since_last_row"] == 50, [d["metadata"] for d in denies])
# another name is another key, and the key is owner + name + reason
refused(CORE, ss.get, "other_name", code="caller_not_allowed")
must(len([a for a in AUDIT if a["action"] == "deny"]) == 3)
# decrypt failures: the same, and the Core log line follows the limit
reset()
ss._monotonic = lambda: now[0]
LIC(ss.put, "licence_key", SENTINEL)
LIC(ss.put, "other", SENTINEL)
TABLE.rows[0].key_id = "k1-notthekey"
LOGS.clear()
before = len(AUDIT)
for _ in range(30):
    refused(LIC, ss.get, "licence_key", code="secret_unreadable")
fails = [a for a in AUDIT[before:] if a["action"] == "custom:decrypt-failed"]
must(len(fails) == 1 and len([l for l in LOGS if "could not decrypt" in l]) == 30, (len(fails), len(LOGS)))  # 1.17.103: the log line is written every time; only the audit row is limited
now[0] += ss.AUDIT_REPEAT_SECONDS + 1
refused(LIC, ss.get, "licence_key", code="secret_unreadable")
fails = [a for a in AUDIT[before:] if a["action"] == "custom:decrypt-failed"]
must(len(fails) == 2 and fails[1]["metadata"]["left_out_since_last_row"] == 29, [f["metadata"] for f in fails])
must(not any(SENTINEL in json.dumps(a, default=lambda o: str(vars(o))) for a in AUDIT), "a value in an audit row")
# a flood of names cannot grow the table, and cannot make Core write more rows
reset()
ss._monotonic = lambda: now[0]
written = 0
for i in range(ss._AUDIT_REPEAT_MAX + 300):
    refused(CORE, ss.get, f"flood{i}", code="caller_not_allowed")
must(len(ss._repeat_seen) <= ss._AUDIT_REPEAT_MAX, len(ss._repeat_seen))
must(len([a for a in AUDIT if a["action"] == "deny"]) == ss._AUDIT_REPEAT_MAX, "a full table must leave further rows out")
now[0] += ss.AUDIT_REPEAT_SECONDS + 1
refused(CORE, ss.get, "after-expiry", code="caller_not_allowed")
must(len([a for a in AUDIT if a["action"] == "deny"]) == ss._AUDIT_REPEAT_MAX + 1, "expired entries were not purged")
ss._monotonic = __import__("time").monotonic
print("       item 4: one deny or decrypt-failed row per owner, name and reason every 5 minutes; the next says how many were left out; the Core log line is written every time (1.17.103); a flood of names cannot grow the table or the audit log")

# ---------------------------------------------------------------------------------------------------------------- 5. concurrent first put
reset()


class IntegrityError(Exception):
    pass


NS["mod"]("django.db", transaction=NS["SimpleNamespace"](atomic=lambda: Atomic()), IntegrityError=IntegrityError)
real_create = TABLE.create
state = {"fails": 1, "calls": 0}


def racing_create(**kwargs):
    state["calls"] += 1
    if state["fails"] > 0:
        state["fails"] -= 1
        # the other writer got there first: its row exists now
        real_create(owner_module=kwargs["owner_module"], name=kwargs["name"], ciphertext=b"other-writer", key_id="k1-other")
        raise IntegrityError("duplicate key value violates unique constraint")
    return real_create(**kwargs)


TABLE.create = racing_create
ORDER.clear()
result = LIC(ss.put, "licence_key", SENTINEL)
must(result == "replaced" and len(TABLE.rows) == 1 and state["calls"] == 1, (result, len(TABLE.rows)))
must(LIC(ss.get, "licence_key") == SENTINEL, "the retry did not store the value")
must(ORDER.count(("rollback",)) == 1, ORDER)  # the first attempt rolled back (with its audit row, in the real database)
# a second collision is a clear 409, never a raw IntegrityError
reset()
state.update(fails=2, calls=0)


def always_collide(**kwargs):
    state["calls"] += 1  # the row is gone again before the retry looks (deleted by a third writer): a second collision
    raise IntegrityError("again")


TABLE.create = always_collide
exc = refused(LIC, ss.put, "licence_key", SENTINEL, code="secret_conflict")
must(state["calls"] == 2, state)  # tried once, retried once, never a third time
must(exc.status_code == 409 and "Troubleshooting" in str(exc) and SENTINEL not in str(exc), (exc.status_code, str(exc)))
TABLE.create = real_create
reset()
must(LIC(ss.put, "licence_key", SENTINEL) == "created" and LIC(ss.put, "licence_key", "b") == "replaced", "normal puts changed")
must("soft limit" in SOURCE and "secret_conflict" in SOURCE, "the soft limit is not documented in the source")
print("       item 5: a collided first put is retried once as a replace; a second collision is secret_conflict (409); the soft name limit is documented")

# ---------------------------------------------------------------------------------------------------------------- 6. group and lstat
reset()
LIC(ss.put, "licence_key", SENTINEL)
KEY_STATE["gid"] = 4242
exc = refused(LIC, ss.get, "licence_key", code="master_key_unavailable")
must(exc.reason == "wrong_group" and exc.status_code == 503, exc.reason)
exc = refused(LIC, ss.put, "licence_key", "x", code="master_key_unavailable")
must(exc.reason == "wrong_group")
must(any("wrong_group" in line for line in LOGS) and not any(SENTINEL in line for line in LOGS))
KEY_STATE["gid"] = 1001
must(LIC(ss.get, "licence_key") == SENTINEL, "the right group must pass")
# a group Core cannot find is a fault, never a pass
real_gid = ss._key_group_id
ss._key_group_id = lambda: None
refused(LIC, ss.get, "licence_key", code="master_key_unavailable")
ss._key_group_id = real_gid
# the real lookup: finds the group when the system has one, and is None (not an exception) otherwise
try:
    import grp  # noqa: F401
except ImportError:
    pass
else:
    must(ss.__dict__["_key_group_id"] is not None)
# the folder: lstat, and a link (or anything that is not a folder) is unsafe
must("_lstat(path.parent)" in SOURCE and "os.stat" not in SOURCE and "_stat(path.parent)" not in SOURCE.replace("_lstat(path.parent)", ""), "the folder is not read with lstat")
FOLDER_STATE["mode"] = 0o120777  # S_IFLNK
exc = refused(LIC, ss.get, "licence_key", code="master_key_unavailable")
must(exc.reason == "folder_unsafe", exc.reason)
FOLDER_STATE["mode"] = 0o40750
must(LIC(ss.get, "licence_key") == SENTINEL)
FOLDER_STATE["mode"] = 0o100750  # a regular file where the folder should be
must(refused(LIC, ss.get, "licence_key", code="master_key_unavailable").reason == "folder_unsafe")
FOLDER_STATE["mode"] = 0o40750
print("       item 6: a key file outside the tactical group (or a group Core cannot find) is master_key_unavailable/wrong_group; the folder is read with lstat and a link or a file in its place is folder_unsafe")

# ---------------------------------------------------------------------------------------------------------------- 7. install.sh
INSTALL = read(ROOT / "install.sh")
begin, end = INSTALL.index("# BEGIN secret-store-master-key"), INSTALL.index("# END secret-store-master-key")
BLOCK = INSTALL[begin:end]
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh has CRLF line endings")
must("if ! mv -n --" in BLOCK and "\n    mv -n --" not in BLOCK, "mv -n is still a bare command under set -e")
must("root:${TACTICAL_GROUP} 640 32" in BLOCK and "stat -c '%U:%G %a %s'" in BLOCK, "the key is not verified after the move")
bash = shutil.which("bash")
if bash and subprocess.run([bash, "-c", "command -v mktemp stat head mv >/dev/null && echo ok"], capture_output=True, text=True, check=False).stdout.strip() == "ok":
    def run(mv_body, stat_facts=None, expect_ok=True):
        work = Path(tempfile.mkdtemp(prefix="tectac-install101-"))
        secrets = work / "secrets"
        stat_stub = ""
        if stat_facts is not None:
            stat_stub = f"stat() {{ if [[ \"$2\" == '%U:%G %a %s' ]]; then echo '{stat_facts}'; else command stat \"$@\"; fi; }}\n"
        else:
            stat_stub = "stat() { if [[ \"$2\" == '%U:%G %a %s' ]]; then echo \"root:tactical 640 $(command stat -c %s \"$3\")\"; else command stat \"$@\"; fi; }\n"
        script = work / "block.sh"
        script.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "log() { printf '[TEC-TAC] %s\\n' \"$*\"; }\n"
            "fail() { printf '[TEC-TAC] ERROR: %s\\n' \"$*\" >&2; exit 1; }\n"
            "TACTICAL_GROUP=tactical\n"
            "chown() { :; }\n"
            "install() { local d=''; for a in \"$@\"; do d=\"$a\"; done; mkdir -p \"$d\"; }\n"
            + stat_stub + mv_body
            + BLOCK.replace("/etc/tec-tac/secrets", secrets.as_posix()) + "\necho DONE\n",
            encoding="utf-8", newline="\n")
        result = subprocess.run([bash, str(script)], capture_output=True, text=True, timeout=60, check=False)
        must((result.returncode == 0) == expect_ok, (result.returncode, result.stdout, result.stderr))
        return secrets, result

    # coreutils 9.2 to 9.4: mv -n moves the file and still exits 1 -> the install goes on, the key is verified
    secrets, result = run("mv() { if [[ \"$1\" == \"-n\" ]]; then command mv \"$@\"; return 1; fi; command mv \"$@\"; }\n")  # only mv -n has the quirk; the key-group move (mv -f, 1.17.103) is normal
    must((secrets / "master.key").is_file() and (secrets / "master.key").stat().st_size == 32 and "DONE" in result.stdout and "created" in result.stdout, (result.stdout, result.stderr))
    must("non-zero status" in result.stdout, "the non-zero status is not logged")
    # mv fails and nothing was moved: a clear failure, not a silent pass
    secrets, result = run("mv() { return 1; }\n", expect_ok=False)
    must("was not created" in result.stderr and not (secrets / "master.key").exists() and "DONE" not in result.stdout, (result.stdout, result.stderr))
    # mv does nothing and reports success (a key that is not there): the same clear failure
    secrets, result = run("mv() { return 0; }\n", expect_ok=False)
    must("was not created" in result.stderr, result.stderr)
    # the key is there but with the wrong owner, mode or size: the install stops and says what it saw
    secrets, result = run("", stat_facts="johanvz:users 644 32", expect_ok=False)
    must("wrong owner, mode or size" in result.stderr and "johanvz:users 644 32" in result.stderr and "DONE" not in result.stdout, result.stderr)
    secrets, result = run("", stat_facts="root:tactical 640 31", expect_ok=False)
    must("expected root:tactical 640 32" in result.stderr)
    # a normal run is unchanged, and the key is not printed
    secrets, result = run("")
    must("DONE" in result.stdout and (secrets / "master.key").read_bytes().hex() not in result.stdout + result.stderr, result.stdout)
    # the replaced temporary file is gone
    must(sorted(p.name for p in secrets.iterdir()) == ["key-group", "master.key"], [p.name for p in secrets.iterdir()])
    print("       item 7: a non-zero mv -n status under set -e no longer ends the install; a key that is not there is a clear failure; owner, group, mode and size are verified after the move")
else:
    print("       item 7: bash is not usable on this PC; only the static guards ran")

# ---------------------------------------------------------------------------------------------------------------- docs, notes, version
DOC = read(ROOT / "docs" / "secret-store.md")
TS = read(ROOT / "docs" / "troubleshooting-diagnostics.md")
for text, label in ((DOC, "docs/secret-store.md"), (TS, "troubleshooting")):
    for needle in ("secret_conflict", "wrong_group", "5 minutes"):
        must(needle in text, f"{label} misses {needle}")
must("takes an owner as an argument" in DOC and "5 seconds" in DOC and "at most once a minute" in DOC and "soft" in DOC, "the help text is incomplete")
must("wrong owner, mode or size" in TS, "the installer message is not in troubleshooting")
must(TS.rstrip().endswith("Tech Flow Dynamics · techxflow.co.za") and TS.count("Tech Flow Dynamics · techxflow.co.za") == 1, "the footer is not last")
must(DOC.rstrip().endswith("Tech Flow Dynamics · techxflow.co.za"), "secret-store footer")
CONTRACTS = read(APP / "contracts.py")
must("secret_conflict" in CONTRACTS and "1.17.101" in CONTRACTS, "the contract text does not mention the new code")
NOTES = read(ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.101.md")
must((ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.100.md").is_file(), "the 1.17.100 notes were not moved")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "## Checks on the test server", "## Not done here"):
    must(heading in NOTES, heading)
for needle in ("secret_conflict", "wrong_group", "mv -n", "FAIL", "held from 1.17.100", "Fixed after review"):
    must(needle in NOTES, f"the notes miss {needle}")
must(read(ROOT / "VERSION").strip().startswith("1.17.10"), "version")
print("       help, troubleshooting (footer last), contract text, release notes and version")
print("[TEST] PASS secret store hardening 1.17.101")
