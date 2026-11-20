#!/usr/bin/python3
"""Core 1.18.25: the Patch C canary rows, run through the real launch path. DEV SERVER ONLY, as root, after Core 1.18.25 is installed.

    sudo bash tests/sandbox-canary-1.18.25.sh            (step 5w starts this file)
    sudo bash tests/sandbox-canary-1.18.25.sh patchc     (the guards, the selftest and this step only)

Why (AD-65, canary first, as 1.18.23 did for Patch B): the plan's Patch C fixes are NOT built in this release. These rows prove each hole exists on
the installed build, so the later fix release has a failing row to turn green. Every row is therefore EXPECTED to read ATTACK SUCCEEDED today (a row may
be NOT RUN, with a printed reason, only where the machine itself cannot show it). A row that reads OK proves nothing and fails the step.

Rows (stable ids; wall name "Patch C"):

* pc-leftover-before-credential: a run starts with --return-credential; its runner forks a leftover that outlives it and keeps replacing
  $SANDBOX_OUT/credential with a marker for a few seconds. ATTACK SUCCEEDED when the credential returned to the host carries the marker (the launcher
  read it while a leftover was alive). Three tries, because it is a race.
* pc-returned-credential-untrusted: the contract text (framwork/tec_tac/contracts.py) and docs/sandbox-capability.md do not yet say a returned
  credential is untrusted and must be checked against the same account. ATTACK SUCCEEDED while that sentence is missing from either.
* pc-selftest-in-sudoers: the helper file the Tactical user may run as root still contains the --selftest and --canary code (function names read as
  text; nothing is run).
* pc-helper-shebang-no-i: the first line of the installed helper is not a python -I line.
* pc-registration-type-checks: the helper's registration validator accepts (or dies with an uncaught TypeError on) a parameter whose max_length, minimum
  or maximum is a string or a boolean. Nothing is written to the registry.
* pc-pattern-field: the same validator accepts a parameter spec with a 'pattern' field.
* pc-io-uring-reachable, pc-userfaultfd-reachable, pc-keyctl-reachable: inside a run, the raw syscall is not refused by the filter.

How: the INSTALLED helper is loaded the way the 1.18.23 driver loads it; the in-unit rows are the groups ``patchc_syscalls`` and ``patchc_leftover`` of the
installed canary runner, started with the helper's own ``canary_row`` and ``launch`` (the group choice is added to this run's copy of the row, so the
helper's CANARY_GROUPS is never changed). It never touches the kill switch and writes nothing outside the helper's own canary run files.

Exit 0: every row is ATTACK SUCCEEDED, or NOT RUN with an allowed printed reason. Exit 1: an OK row (proves nothing), or any other result. Exit 2: a unit
could not be started.
"""
from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import sys
from pathlib import Path

INSTALLED_HELPER = "/usr/local/lib/tec-tac/sandbox/sandbox-helper.py"
SUDOERS_FILE = "/etc/sudoers.d/tec-tac-sandbox"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
WALL = "Patch C"
GROUP_SYSCALLS = "patchc_syscalls"
GROUP_LEFTOVER = "patchc_leftover"
RUN_SECONDS = 20
LEFTOVER_SECONDS = 5
LEFTOVER_TRIES = 3
MARKER = "patchc-leftover-marker"
EXPECTED = "ATTACK SUCCEEDED (hole present; fix is a later release)"

R_LEFTOVER = "pc-leftover-before-credential"
R_UNTRUSTED = "pc-returned-credential-untrusted"
R_SUDOERS = "pc-selftest-in-sudoers"
R_SHEBANG = "pc-helper-shebang-no-i"
R_TYPES = "pc-registration-type-checks"
R_PATTERN = "pc-pattern-field"
R_URING = "pc-io-uring-reachable"
R_UFFD = "pc-userfaultfd-reachable"
R_KEYCTL = "pc-keyctl-reachable"
ROW_IDS = (R_LEFTOVER, R_UNTRUSTED, R_SUDOERS, R_SHEBANG, R_TYPES, R_PATTERN, R_URING, R_UFFD, R_KEYCTL)
# the in-unit row names printed by the installed runner, and the id each one gets here
SYSCALL_ROWS = {"io_uring_setup reachable": R_URING, "userfaultfd reachable": R_UFFD, "keyctl reachable": R_KEYCTL}
LABELS = {
    R_LEFTOVER: "a leftover process rewrites the credential before the launcher reads it",
    R_UNTRUSTED: "the contract does not say a returned credential is untrusted",
    R_SUDOERS: "the sudo-reachable helper still holds --selftest and --canary",
    R_SHEBANG: "the helper's first line is not python -I",
    R_TYPES: "registration accepts string or boolean limits",
    R_PATTERN: "registration accepts a 'pattern' parameter field",
    R_URING: "io_uring_setup is not refused in a run",
    R_UFFD: "userfaultfd is not refused in a run",
    R_KEYCTL: "keyctl is not refused in a run",
}
# a NOT RUN is allowed only with one of these reasons (the machine cannot show the row)
ALLOWED_NOT_RUN = ("unknown machine architecture", "(ENOSYS)", "io_uring_disabled=2", "no credential returned")
SHEBANG_OK = re.compile(r"^#!\s*(/usr/bin/env\s+(-S\s+)?)?\S*python3?(\.\d+)?\s+(-[A-Za-z]*I[A-Za-z]*)(\s|$)")
UNTRUSTED_RE = re.compile(r"returned credential[^.]{0,120}untrusted|untrusted[^.]{0,120}returned credential", re.IGNORECASE)
TYPE_CASES = (
    ("max_length as a string", {"type": "string", "max_length": "10"}),
    ("max_length as a boolean", {"type": "string", "max_length": True}),
    ("minimum as a string", {"type": "integer", "minimum": "1"}),
    ("maximum as a boolean", {"type": "integer", "maximum": True}),
)


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def entry(rid, verdict, actual):
    return {"id": rid, "wall": WALL, "attack": LABELS[rid], "expected": EXPECTED, "actual": actual, "verdict": verdict}


def read_text(path, limit=4 * 1024 * 1024):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read(limit)


# ------------------------------------------------------------------------------------------------ the host-side rows (read only)
def row_untrusted(source_root):
    missing = []
    for label, relative in (("framwork/tec_tac/contracts.py", Path("framwork") / "tec_tac" / "contracts.py"), ("docs/sandbox-capability.md", Path("docs") / "sandbox-capability.md")):
        try:
            text = read_text(Path(source_root) / relative)
        except OSError:
            return entry(R_UNTRUSTED, "NOT RUN", f"{label} could not be read from the installed Core source")
        if not UNTRUSTED_RE.search(text):
            missing.append(label)
    if missing:
        return entry(R_UNTRUSTED, "ATTACK SUCCEEDED", "no sentence says a returned credential is untrusted and must be checked against the same account in: " + ", ".join(missing))
    return entry(R_UNTRUSTED, "OK", "both texts say a returned credential is untrusted")


def row_sudoers(helper_path, sudoers_path=SUDOERS_FILE):
    try:
        text = read_text(helper_path)
    except OSError:
        return entry(R_SUDOERS, "NOT RUN", "the installed helper could not be read")
    found = [name for name, needle in (("def selftest", "def selftest("), ("def run_canary", "def run_canary("), ("--selftest", '"--selftest"'), ("--canary", '"--canary"'))
             if needle in text]
    note = ""
    try:
        lines = [line.strip() for line in read_text(sudoers_path, 65536).splitlines() if "tec-tac-sandbox" in line and not line.lstrip().startswith("#")]
        note = f"; sudoers rule: {lines[0][:120]}" if lines else "; no sudoers rule line found"
    except OSError:
        note = "; the sudoers file could not be read"
    if found:
        return entry(R_SUDOERS, "ATTACK SUCCEEDED", "the sudo-reachable helper file still contains: " + ", ".join(found) + note)
    return entry(R_SUDOERS, "OK", "no selftest or canary entry point in the helper file" + note)


def row_shebang(helper_path):
    try:
        first = read_text(helper_path, 512).splitlines()[0]
    except (OSError, IndexError):
        return entry(R_SHEBANG, "NOT RUN", "the installed helper's first line could not be read")
    shown = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in first)[:80]
    if SHEBANG_OK.match(first):
        return entry(R_SHEBANG, "OK", f"first line is {shown!r}")
    return entry(R_SHEBANG, "ATTACK SUCCEEDED", f"first line is {shown!r}, not a python -I line")


def _validate(helper, spec):
    """'accepted', 'refused' (RuntimeError, the right answer) or 'crashed: <type>' for one parameter spec. Nothing is written anywhere."""
    check = getattr(helper, "_check_parameters", None)
    if check is None:
        return "no validator"
    try:
        check({"probe": dict(spec)}, "canary")
    except RuntimeError:
        return "refused"
    except Exception as exc:  # noqa: BLE001 - an uncaught TypeError is the finding itself
        return f"crashed: {type(exc).__name__}"
    return "accepted"


def row_types(helper):
    results = [(label, _validate(helper, spec)) for label, spec in TYPE_CASES]
    if any(result == "no validator" for _label, result in results):
        return entry(R_TYPES, "NOT RUN", "the helper has no registration validator by the expected name")
    bad = [f"{label}: {result}" for label, result in results if result != "refused"]
    if bad:
        return entry(R_TYPES, "ATTACK SUCCEEDED", "; ".join(bad))
    return entry(R_TYPES, "OK", "every string or boolean limit is refused")


def row_pattern(helper):
    result = _validate(helper, {"type": "string", "pattern": "^[a-z]+$"})
    if result == "no validator":
        return entry(R_PATTERN, "NOT RUN", "the helper has no registration validator by the expected name")
    if result == "refused":
        return entry(R_PATTERN, "OK", "a parameter with a pattern field is refused")
    return entry(R_PATTERN, "ATTACK SUCCEEDED", f"a parameter with a 'pattern' field is {result}")


# ------------------------------------------------------------------------------------------------ the runs
def run_group(helper, group, plan, status, credentials=None, person="canary-patchc"):
    """The group through the helper's own ``launch``, with the group choice added to this run's copy of the row. Returns (stdout bytes, end frame, refusal code)."""
    row = helper.canary_row(run_seconds=RUN_SECONDS)
    spec = dict(row["parameters"]["group"])
    spec["choices"] = [*spec["choices"], group]  # a new list: the helper's own constant is never changed
    row["parameters"] = {**row["parameters"], "group": spec}
    out = {"stdout": b"", "end": None}

    def emit(frame):
        if frame["t"] == "out":
            out["stdout"] += base64.b64decode(frame["b"])
        elif frame["t"] == "end":
            out["end"] = frame

    try:
        helper.launch(row, run_id=secrets.token_hex(16), person=person, parameters={"group": group}, credentials=credentials or {},
                      input_data=json.dumps(plan).encode("utf-8"), emit=emit, slots_n=None, person_n=helper.PERSON_SLOTS, status=status)
    except helper.Refusal as exc:
        return out["stdout"], None, exc.code
    return out["stdout"], out["end"], None


def row_leftover(helper, status, tries=LEFTOVER_TRIES):
    """Up to ``tries`` runs (it is a race). ATTACK SUCCEEDED as soon as a returned credential carries the marker."""
    seen = []
    for number in range(1, tries + 1):
        token = secrets.token_hex(8)
        _out, end, refused = run_group(helper, GROUP_LEFTOVER, {"marker": MARKER, "leftover_seconds": LEFTOVER_SECONDS}, status, credentials={"auth": token.encode()})
        if refused or end is None:
            return None, refused or "no end frame"
        back = end.get("credential_b64")
        got = base64.b64decode(back).decode("utf-8", "replace") if back else ""
        if MARKER in got:
            return entry(R_LEFTOVER, "ATTACK SUCCEEDED", f"try {number}: the credential returned to the host carries the leftover's marker (read while a leftover was alive)"), None
        seen.append("none" if not got else "original")
    if all(item == "none" for item in seen):
        return entry(R_LEFTOVER, "NOT RUN", f"no credential returned in {tries} tries"), None
    return entry(R_LEFTOVER, "OK", f"the returned credential never carried the marker in {tries} tries ({', '.join(seen)})"), None


def rows_syscalls(helper, status):
    stdout, end, refused = run_group(helper, GROUP_SYSCALLS, {}, status)
    if refused or end is None:
        return None, refused or "no end frame"
    printed = {r["attack"]: r for r in helper.parse_runner_rows(stdout)}
    table = []
    for name, rid in SYSCALL_ROWS.items():
        found = printed.get(name)
        if found is None:
            table.append(entry(rid, "NOT RUN", "the probe printed no result"))
        else:
            table.append(entry(rid, helper.classify_tag(found["tag"]), found["actual"]))
    return table, None


# ------------------------------------------------------------------------------------------------ the verdict
def classify(table):
    """[(row id, verdict, label, problem)]. ATTACK SUCCEEDED is the expected answer. NOT RUN passes only with an allowed printed reason. OK fails."""
    out, seen = [], set()
    for item in table:
        rid, verdict, actual = item["id"], item["verdict"], str(item["actual"])
        problem, label = True, ""
        if rid not in ROW_IDS or rid in seen:
            label = "UNEXPECTED (not a row of the list, or listed twice)"
        elif verdict == "ATTACK SUCCEEDED":
            problem, label = False, "ATTACK SUCCEEDED (as expected before the Patch C fix)"
        elif verdict == "NOT RUN" and any(reason in actual for reason in ALLOWED_NOT_RUN):
            problem, label = False, "NOT RUN with a printed reason"
        elif verdict == "OK":
            label = "OK (proves nothing: the row must show the hole before the fix)"
        else:
            label = f"UNEXPECTED ({verdict})"
        seen.add(rid)
        out.append((rid, verdict, label, problem))
    for rid in ROW_IDS:
        if rid not in seen:
            out.append((rid, "NOT RUN", "MISSING (the driver did not produce this row)", True))
    return out


def summary_line(table):
    attacks = sum(1 for e in table if e["verdict"] == "ATTACK SUCCEEDED")
    notrun = sum(1 for e in table if e["verdict"] == "NOT RUN")
    ok = sum(1 for e in table if e["verdict"] == "OK")
    return f"PATCH C ROWS: {attacks} ATTACK SUCCEEDED, {notrun} NOT RUN (reason), {ok} OK; expected: {', '.join(ROW_IDS)} (each ATTACK SUCCEEDED, or NOT RUN with a printed reason)"


def main(helper=None, out=print, source_root=SOURCE_ROOT, helper_path=INSTALLED_HELPER, sudoers_path=SUDOERS_FILE, tries=LEFTOVER_TRIES):
    if helper is None:
        if os.geteuid() != 0:
            out("FAIL this driver must run as root (it is started by tests/sandbox-canary-1.18.25.sh)")
            return 2
        try:
            helper = load("tec_tac_sandbox_helper", helper_path)
        except (OSError, SyntaxError, ImportError) as exc:
            out(f"FAIL the installed helper could not be loaded: {type(exc).__name__}")
            return 2
    status = helper.read_status()
    if status.get("ready") is not True:
        out("FAIL the sandbox selftest is not ready: run the selftest first (sudo /usr/local/sbin/tec-tac-sandbox --selftest)")
        return 2
    out("== Patch C rows: canary rows only, no fix in this release; ATTACK SUCCEEDED is expected on every row")
    table = [row_untrusted(source_root), row_sudoers(helper_path, sudoers_path), row_shebang(helper_path), row_types(helper), row_pattern(helper)]
    leftover, refused = row_leftover(helper, status, tries)
    if refused:
        out(f"FAIL the unit could not be started ({refused})")
        return 2
    table.append(leftover)
    syscalls, refused = rows_syscalls(helper, status)
    if refused:
        out(f"FAIL the unit could not be started ({refused})")
        return 2
    table.extend(syscalls)
    table.sort(key=lambda item: ROW_IDS.index(item["id"]))
    out(helper.format_table(table))
    for line in helper.row_lines(table):
        out(line)
    for line in helper.detail_lines(table):
        out(line)
    results = classify(table)
    for rid, verdict, label, problem in results:
        out(f"{'FAIL' if problem else 'ok  '} {rid}: {verdict}: {label}")
    out(summary_line(table))
    return 1 if any(problem for *_rest, problem in results) else 0


if __name__ == "__main__":
    sys.exit(main())
