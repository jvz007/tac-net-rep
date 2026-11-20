#!/usr/bin/python3
"""Core 1.18.27 (unchanged rows from 1.18.26): the Patch C rows, run through the real launch path. DEV SERVER ONLY, as root, after Core 1.18.27 is installed.

    sudo bash tests/sandbox-canary-1.18.27.sh            (step 5w starts this file)
    sudo bash tests/sandbox-canary-1.18.27.sh patchc     (the guards, the selftest and this step only)

Why (AD-65, canary first): Core 1.18.25 added these rows and every one read ATTACK SUCCEEDED. Core 1.18.26 builds the Patch C fixes, so every row must
now read OK. A row may be NOT RUN, with a printed reason, only where the machine itself cannot show it (an unknown architecture, ENOSYS, io_uring
turned off by the kernel, no credential returned). An ATTACK SUCCEEDED row, or a NOT RUN with no allowed reason, fails the step.

Rows (stable ids; wall name "Patch C"):

* pc-leftover-before-credential: a run starts with --return-credential; its runner forks a leftover that outlives it. The leftover keeps replacing
  $SANDBOX_OUT/credential with "<marker> <n>" and prints "LEFTOVER <n>" to the shared stdout after each replacement. The launcher reads the credential
  after the runner exits and carries the last n the leftover wrote before the read. ATTACK SUCCEEDED when the run's output shows a larger n than the
  credential carries: the leftover was still alive after the read, so the launcher had not stopped it first. Three tries, because it is a race.
* pc-returned-credential-untrusted: the contract text (framwork/tec_tac/contracts.py) and docs/sandbox-capability.md say a returned credential is
  untrusted and must be checked against the same account. ATTACK SUCCEEDED while that sentence is missing from either.
* pc-selftest-in-sudoers: the helper file the Tactical user may run as root holds no --selftest, --canary or --canary-launch code (read as text), the
  installed sandbox-selftest.py is root:root 0700, and the sudoers file does not name it.
* pc-helper-shebang-no-i: the first line of the installed helper (and of the selftest file) is exactly "#!/usr/bin/python3 -I".
* pc-registration-type-checks: the helper's registration validator refuses (with a plain RuntimeError, never an uncaught TypeError) a parameter whose
  max_length, minimum or maximum is a string or a boolean. Nothing is written to the registry.
* pc-pattern-field: the same validator refuses a parameter spec with a 'pattern' field.
* pc-io-uring-reachable, pc-userfaultfd-reachable, pc-keyctl-reachable: inside a run, the raw syscall is refused by the filter (EPERM).

How: the INSTALLED sandbox-selftest.py is loaded by path together with the helper beside it (tests/sandbox_test_support.py), so this file reaches the
helper's launch code and the selftest file's canary row as one object; the in-unit rows are the groups ``patchc_syscalls`` and ``patchc_leftover`` of the
installed canary runner, started with ``canary_row`` and ``launch`` (the group choice is added to this run's copy of the row, so the helper's own
constants are never changed). It never touches the kill switch and writes nothing outside the helper's own canary run files.

Exit 0: every row is OK, or NOT RUN with an allowed printed reason. Exit 1: an ATTACK SUCCEEDED row, a NOT RUN without a reason, or any other result.
Exit 2: a unit could not be started.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sys
from pathlib import Path

INSTALLED_HELPER = "/usr/local/lib/tec-tac/sandbox/sandbox-helper.py"
INSTALLED_SELFTEST = "/usr/local/lib/tec-tac/sandbox/sandbox-selftest.py"
SHEBANG = "#!/usr/bin/python3 -I"
SUDOERS_FILE = "/etc/sudoers.d/tec-tac-sandbox"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import (
    load_view,
)

WALL = "Patch C"
GROUP_SYSCALLS = "patchc_syscalls"
GROUP_LEFTOVER = "patchc_leftover"
RUN_SECONDS = 20
LEFTOVER_SECONDS = 5
LEFTOVER_TRIES = 3
MARKER = "patchc-leftover-marker"
EXPECTED = "OK (Patch C fix present)"

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
    R_SUDOERS: "the sudo-reachable helper still holds --selftest and --canary, or the selftest file is reachable",
    R_SHEBANG: "the helper's first line is not python -I",
    R_TYPES: "registration accepts (or crashes on) string or boolean limits",
    R_PATTERN: "registration accepts a 'pattern' parameter field",
    R_URING: "io_uring_setup is not refused in a run",
    R_UFFD: "userfaultfd is not refused in a run",
    R_KEYCTL: "keyctl is not refused in a run",
}
# a NOT RUN is allowed only with one of these reasons (the machine cannot show the row)
ALLOWED_NOT_RUN = ("unknown machine architecture", "(ENOSYS)", "io_uring_disabled=2", "no credential returned")
UNTRUSTED_RE = re.compile(r"returned credential[^.]{0,120}untrusted|untrusted[^.]{0,120}returned credential", re.IGNORECASE)
TYPE_CASES = (
    ("max_length as a string", {"type": "string", "max_length": "10"}),
    ("max_length as a boolean", {"type": "string", "max_length": True}),
    ("minimum as a string", {"type": "integer", "minimum": "1"}),
    ("maximum as a boolean", {"type": "integer", "maximum": True}),
)


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


def row_sudoers(helper_path, sudoers_path=SUDOERS_FILE, selftest_path=INSTALLED_SELFTEST, stat=os.stat):
    try:
        text = read_text(helper_path)
    except OSError:
        return entry(R_SUDOERS, "NOT RUN", "the installed helper could not be read")
    found = [name for name, needle in (("def selftest", "def selftest("), ("def run_canary", "def run_canary("), ("--selftest", '"--selftest"'), ("--canary", '"--canary"'),
                                       ("--canary-launch", '"--canary-launch"'), ("canary_row", "canary_row"))
             if needle in text]
    problems = []
    try:
        info = stat(selftest_path)
        if info.st_uid != 0 or info.st_gid != 0 or (info.st_mode & 0o777) != 0o700:
            problems.append(f"the installed selftest file is not root:root 0700 (owner {info.st_uid}:{info.st_gid}, mode {info.st_mode & 0o777:o})")
    except OSError:
        return entry(R_SUDOERS, "NOT RUN", "the installed sandbox-selftest.py could not be read (is Core 1.18.26 installed?)")
    note = ""
    try:
        lines = [line.strip() for line in read_text(sudoers_path, 65536).splitlines() if "tec-tac-sandbox" in line and not line.lstrip().startswith("#")]
        note = f"; sudoers rule: {lines[0][:120]}" if lines else "; no sudoers rule line found"
        if any("sandbox-selftest" in line for line in lines):
            problems.append("the sudoers file names the selftest file")
    except OSError:
        note = "; the sudoers file could not be read"
    if found:
        problems.append("the sudo-reachable helper file still contains: " + ", ".join(found))
    if problems:
        return entry(R_SUDOERS, "ATTACK SUCCEEDED", "; ".join(problems) + note)
    return entry(R_SUDOERS, "OK", "no selftest or canary entry point in the helper file, the selftest file is root:root 0700 and not in sudoers" + note)


def row_shebang(helper_path, selftest_path=INSTALLED_SELFTEST):
    shown = []
    for label, path in (("helper", helper_path), ("selftest", selftest_path)):
        try:
            first = read_text(path, 512).splitlines()[0]
        except (OSError, IndexError):
            return entry(R_SHEBANG, "NOT RUN", f"the installed {label}'s first line could not be read")
        shown.append((label, "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in first)[:80], first == SHEBANG))
    if all(good for _label, _line, good in shown):
        return entry(R_SHEBANG, "OK", "; ".join(f"{label} first line is {line!r}" for label, line, _good in shown))
    return entry(R_SHEBANG, "ATTACK SUCCEEDED", "; ".join(f"{label} first line is {line!r}" for label, line, good in shown if not good) + f" (expected {SHEBANG!r})")


def _validate(helper, spec):
    """'accepted', 'refused' (RuntimeError, the right answer) or 'crashed: <type>' for one parameter spec. Nothing is written anywhere."""
    check = getattr(helper, "_check_parameters", None)
    if check is None:
        return "no validator"
    try:
        check({"probe": dict(spec)}, "canary")
    except RuntimeError:
        return "refused"
    except Exception as exc:
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


LEFTOVER_LINE = re.compile(rb"^LEFTOVER ([0-9]{1,9})$", re.MULTILINE)


def leftover_verdict(stdout, end):
    """(verdict, text) for one try. The credential carries ``<marker> <n_cred>``; the largest ``LEFTOVER <n>`` line in the run's output is n_max. A leftover that
    was killed before the read prints at most n_cred; one that was alive after the read prints more. None when no credential came back."""
    back = (end or {}).get("credential_b64")
    got = base64.b64decode(back).decode("utf-8", "replace") if back else ""
    if not got:
        return None, "no credential returned"
    match = re.fullmatch(re.escape(MARKER) + r" ([0-9]{1,9})", got)
    counts = [int(item) for item in LEFTOVER_LINE.findall(stdout)]
    if match is None:
        return "NOT RUN", "the returned credential is not the leftover's own text, so the row cannot compare it"
    n_cred, n_max = int(match.group(1)), max(counts) if counts else 0
    if n_max > n_cred:
        return "ATTACK SUCCEEDED", f"the leftover was still alive after the credential was read (it wrote {n_cred} before the read and printed up to {n_max})"
    return "OK", f"no leftover output after the read (credential carries {n_cred}, last printed {n_max})"


def row_leftover(helper, status, tries=LEFTOVER_TRIES):
    """Up to ``tries`` runs (it is a race). ATTACK SUCCEEDED as soon as one try shows a leftover alive after the read."""
    seen = []
    for number in range(1, tries + 1):
        token = secrets.token_hex(8)
        stdout, end, refused = run_group(helper, GROUP_LEFTOVER, {"marker": MARKER, "leftover_seconds": LEFTOVER_SECONDS}, status, credentials={"auth": token.encode()})
        if refused or end is None:
            return None, refused or "no end frame"
        verdict, text = leftover_verdict(stdout, end)
        if verdict == "ATTACK SUCCEEDED":
            return entry(R_LEFTOVER, "ATTACK SUCCEEDED", f"try {number}: {text}"), None
        seen.append((verdict, text))
    if all(verdict is None for verdict, _text in seen):
        return entry(R_LEFTOVER, "NOT RUN", f"no credential returned in {tries} tries"), None
    if any(verdict == "NOT RUN" for verdict, _text in seen):
        return entry(R_LEFTOVER, "NOT RUN", next(text for verdict, text in seen if verdict == "NOT RUN")), None
    return entry(R_LEFTOVER, "OK", f"in {tries} tries the leftover never wrote or printed after the read ({'; '.join(text for _v, text in seen if _v)})"), None


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
    """[(row id, verdict, label, problem)]. OK is the answer. NOT RUN passes only with an allowed printed reason. ATTACK SUCCEEDED and the rest fail."""
    out, seen = [], set()
    for item in table:
        rid, verdict, actual = item["id"], item["verdict"], str(item["actual"])
        problem, label = True, ""
        if rid not in ROW_IDS or rid in seen:
            label = "UNEXPECTED (not a row of the list, or listed twice)"
        elif verdict == "OK":
            problem, label = False, "OK"
        elif verdict == "NOT RUN" and any(reason in actual for reason in ALLOWED_NOT_RUN):
            problem, label = False, "NOT RUN with a printed reason"
        elif verdict == "ATTACK SUCCEEDED":
            label = "ATTACK SUCCEEDED (a real hole: do not turn the sandbox on)"
        elif verdict == "NOT RUN":
            label = "NOT RUN without an allowed reason"
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
    return f"PATCH C ROWS: {ok} OK, {attacks} ATTACK SUCCEEDED, {notrun} NOT RUN (reason); expected: {', '.join(ROW_IDS)} (each OK, or NOT RUN with a printed kernel reason)"


def main(helper=None, out=print, source_root=SOURCE_ROOT, helper_path=INSTALLED_HELPER, sudoers_path=SUDOERS_FILE, tries=LEFTOVER_TRIES, selftest_path=INSTALLED_SELFTEST, stat_fn=os.stat):
    if helper is None:
        if os.geteuid() != 0:
            out("FAIL this driver must run as root (it is started by tests/sandbox-canary-1.18.27.sh)")
            return 2
        try:
            helper = load_view(selftest_path, "tec_tac_sandbox_helper")
        except (OSError, SyntaxError, ImportError) as exc:
            out(f"FAIL the installed helper and selftest file could not be loaded: {type(exc).__name__}")
            return 2
    status = helper.read_status()
    if status.get("ready") is not True:
        out("FAIL the sandbox selftest is not ready: run the selftest first (sudo /usr/bin/python3 -I /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py --selftest)")
        return 2
    out("== Patch C rows: every row must read OK (NOT RUN only with a printed kernel reason)")
    table = [row_untrusted(source_root), row_sudoers(helper_path, sudoers_path, selftest_path, stat_fn), row_shebang(helper_path, selftest_path), row_types(helper), row_pattern(helper)]
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
