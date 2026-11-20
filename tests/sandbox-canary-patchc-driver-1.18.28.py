#!/usr/bin/env python3
"""1.18.28 regression (from 1.18.26) (AD-65 Patch C): the root driver tests/sandbox-canary-patchc-1.18.28.py, with a stubbed helper loader and launch.

Successor of the 1.18.25 driver test (retired to tests/legacy). In 1.18.25 every row was expected to read ATTACK SUCCEEDED; in 1.18.26 the fixes are built,
so every row must read OK. Django-free; no socket, no listener, no syscall. The real helper and selftest sources are loaded from scripts/ (as one object)
only to read their text and call the registration validator, and ``launch`` is replaced by a fake that prints the in-unit rows. Covered:

* every row id exists once, in the order of ROW_IDS; the summary line carries the counts the canary script greps (OK first);
* on today's source tree every host row is OK (the contract and the doc carry the untrusted-credential sentence, the helper file holds no selftest or
  canary entry point, the first line is the -I shebang, the validator refuses string, boolean and pattern input), so the table exits 0;
* an ATTACK SUCCEEDED row exits 1; NOT RUN exits 0 only with an allowed reason (unknown architecture, ENOSYS, io_uring_disabled=2, no credential
  returned) and 1 for any other; a missing row exits 1; a unit that cannot start exits 2;
* each host row flips to ATTACK SUCCEEDED when its fix is missing (a text without the sentence, a helper that still has the entry points, a plain
  python3 shebang, a validator that accepts or crashes, a selftest file that is not 0700 root) and to NOT RUN when its input cannot be read;
* the leftover row compares the credential's counter with the run's output: a leftover that printed above the counter was alive after the read
  (ATTACK SUCCEEDED, on the first try it stops); the same number or fewer in three tries is OK; no credential in three tries is NOT RUN with
  'no credential returned';
* the driver adds only the group choice to its copy of the row and leaves the helper's constants alone.

Not runnable here: the real launcher, systemd, seccomp state (dev02: tests/sandbox-canary-1.18.28.sh, step 5w).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="tectac-pcdrv-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load("sandbox_patchc_driver", ROOT / "tests" / "sandbox-canary-patchc-1.18.28.py")
sh = load_helper(ROOT, "sandbox_helper_pcdrv")
HELPER_FILE = ROOT / "scripts" / "sandbox-helper.py"
SELFTEST_FILE = ROOT / "scripts" / "sandbox-selftest.py"


class RootStat:
    st_uid = st_gid = 0
    st_mode = 0o100700


def stat_ok(path):
    return RootStat()


must(len(D.ROW_IDS) == 9 and len(set(D.ROW_IDS)) == 9 and set(D.LABELS) == set(D.ROW_IDS), "nine rows, stable and unique")
must(set(D.SYSCALL_ROWS.values()) <= set(D.ROW_IDS), "the in-unit rows map to known ids")
must(b"\r" not in (ROOT / "tests" / "sandbox-canary-patchc-1.18.28.py").read_bytes(), "LF")
text = (ROOT / "tests" / "sandbox-canary-patchc-1.18.28.py").read_text(encoding="utf-8")
must('("0.0.0.0"' not in text and "bind(" not in text and "import socket" not in text, "the driver opens no socket")
must(D.SHEBANG == "#!/usr/bin/python3 -I" and "OK (Patch C fix present)" == D.EXPECTED, "the expected answer is OK")
for rid in D.ROW_IDS:
    must(len(rid) <= 40 and rid.startswith("pc-"), rid)

# ------------------------------------------------------------------------------------------------ the host rows on today's tree
must(D.row_untrusted(ROOT)["verdict"] == "OK", D.row_untrusted(ROOT))
sudoers = BASE / "sudoers"
sudoers.write_text("# comment tec-tac-sandbox\ntactical ALL=(root) NOPASSWD: /usr/local/sbin/tec-tac-sandbox --start, /usr/local/sbin/tec-tac-sandbox --stop, /usr/local/sbin/tec-tac-sandbox --status\n", encoding="utf-8")
entry = D.row_sudoers(HELPER_FILE, sudoers, SELFTEST_FILE, stat=stat_ok)
must(entry["verdict"] == "OK" and "NOPASSWD" in entry["actual"], entry)
entry = D.row_shebang(HELPER_FILE, SELFTEST_FILE)
must(entry["verdict"] == "OK" and "#!/usr/bin/python3 -I" in entry["actual"], entry)
entry = D.row_types(sh)
must(entry["verdict"] == "OK", entry)
entry = D.row_pattern(sh)
must(entry["verdict"] == "OK" and "refused" in entry["actual"], entry)

# ------------------------------------------------------------------------------------------------ each host row flips when its fix is missing
fixed = BASE / "fixed-source"
(fixed / "framwork" / "tec_tac").mkdir(parents=True)
(fixed / "docs").mkdir()
sentence = "A returned credential is untrusted: Core checks it against the same account before it is used."
(fixed / "framwork" / "tec_tac" / "contracts.py").write_text(sentence, encoding="utf-8")
(fixed / "docs" / "sandbox-capability.md").write_text("text. " + sentence, encoding="utf-8")
must(D.row_untrusted(fixed)["verdict"] == "OK", "both texts say it")
(fixed / "docs" / "sandbox-capability.md").write_text("nothing about it", encoding="utf-8")
entry = D.row_untrusted(fixed)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "docs/sandbox-capability.md" in entry["actual"] and "contracts.py" not in entry["actual"], "one missing text is enough")
must(D.row_untrusted(BASE / "nowhere")["verdict"] == "NOT RUN", "unreadable source is NOT RUN")

old_helper = BASE / "old-helper.py"
old_helper.write_text("#!/usr/bin/python3\ndef selftest(runner=None):\n    pass\n\n\ndef run_canary():\n    pass\n\n\nMODES = ('--selftest', \"--selftest\", \"--canary\", \"--canary-launch\")\ncanary_row = None\n", encoding="utf-8")
entry = D.row_sudoers(old_helper, sudoers, SELFTEST_FILE, stat=stat_ok)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "def selftest" in entry["actual"] and "def run_canary" in entry["actual"] and "--canary-launch" in entry["actual"] and "canary_row" in entry["actual"], entry)


class OpenStat:
    st_uid, st_gid, st_mode = 0, 0, 0o100755


entry = D.row_sudoers(HELPER_FILE, sudoers, SELFTEST_FILE, stat=lambda path: OpenStat())
must(entry["verdict"] == "ATTACK SUCCEEDED" and "0700" in entry["actual"], "the selftest file must be 0700")


class UserStat:
    st_uid, st_gid, st_mode = 1000, 1000, 0o100700


must(D.row_sudoers(HELPER_FILE, sudoers, SELFTEST_FILE, stat=lambda path: UserStat())["verdict"] == "ATTACK SUCCEEDED", "the selftest file must be owned by root")
bad_sudoers = BASE / "bad-sudoers"
bad_sudoers.write_text("tactical ALL=(root) NOPASSWD: /usr/local/sbin/tec-tac-sandbox --start, /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py --selftest\n", encoding="utf-8")
entry = D.row_sudoers(HELPER_FILE, bad_sudoers, SELFTEST_FILE, stat=stat_ok)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "names the selftest file" in entry["actual"], entry)


def missing_stat(path):
    raise OSError("missing")


must(D.row_sudoers(HELPER_FILE, sudoers, SELFTEST_FILE, stat=missing_stat)["verdict"] == "NOT RUN", "a missing selftest file is NOT RUN (Core not updated)")

clean = BASE / "clean.py"
for first, verdict in (("#!/usr/bin/python3 -I", "OK"), ("#!/usr/bin/python3", "ATTACK SUCCEEDED"), ("#!/usr/bin/env python3", "ATTACK SUCCEEDED"),
                       ("#!/usr/bin/python3 -B", "ATTACK SUCCEEDED"), ("#!/usr/bin/python3 -Is", "ATTACK SUCCEEDED"), ("# no shebang", "ATTACK SUCCEEDED")):
    clean.write_text(first + "\n", encoding="utf-8")
    must(D.row_shebang(clean, clean)["verdict"] == verdict, (first, verdict))
plain = BASE / "plain.py"
plain.write_text("#!/usr/bin/python3\n", encoding="utf-8")
clean.write_text("#!/usr/bin/python3 -I\n", encoding="utf-8")
entry = D.row_shebang(clean, plain)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "selftest first line" in entry["actual"], "the selftest file's line counts too")
must(D.row_shebang(BASE / "nowhere", clean)["verdict"] == "NOT RUN", "an unreadable file is NOT RUN")


class Strict:
    """A helper whose validator refuses everything it should (the fixed build)."""

    def _check_parameters(self, schema, label):
        spec = schema["probe"]
        if "pattern" in spec or any(not isinstance(spec.get(key, 0), int) or isinstance(spec.get(key, 0), bool) for key in ("max_length", "minimum", "maximum")):
            raise RuntimeError("refused")


class Lax:
    """The 1.18.25 validator: it accepts everything."""

    def _check_parameters(self, schema, label):
        return schema


must(D.row_types(Strict())["verdict"] == "OK" and D.row_pattern(Strict())["verdict"] == "OK", "a validator that refuses is OK")
entry = D.row_types(Lax())
must(entry["verdict"] == "ATTACK SUCCEEDED" and "max_length as a string: accepted" in entry["actual"], entry)
must(D.row_pattern(Lax())["verdict"] == "ATTACK SUCCEEDED", "a validator that accepts a pattern")


class Crashing:
    def _check_parameters(self, schema, label):
        raise TypeError("'<' not supported between 'str' and 'int'")


entry = D.row_types(Crashing())
must(entry["verdict"] == "ATTACK SUCCEEDED" and "crashed: TypeError" in entry["actual"], "an uncaught TypeError is the finding")
must(D.row_types(object())["verdict"] == "NOT RUN" and D.row_pattern(object())["verdict"] == "NOT RUN", "no validator by that name is NOT RUN")


# ------------------------------------------------------------------------------------------------ the leftover row
def cred(n):
    return f"{D.MARKER} {n}"


def printed(top):
    return "".join(f"LEFTOVER {i}\n" for i in range(1, top + 1))


def fake_helper(result_for_try, refuse=None):
    """The real helper's parsers with launch replaced; result_for_try(n) is (credential text or None, text the run printed)."""
    state = {"n": 0, "rows": []}

    class H:
        def __getattr__(self, name):
            return getattr(sh, name)

        def launch(self, row, **kw):
            state["rows"].append((row, kw))
            if refuse:
                raise sh.Refusal(refuse)
            state["n"] += 1
            credential, shown = result_for_try(state["n"])
            kw["emit"]({"t": "out", "b": base64.b64encode(shown.encode()).decode()})
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0, "credential_b64": base64.b64encode(credential.encode()).decode() if credential is not None else None})

        def read_status(self):
            return {"ready": True}

    return H(), state


# a leftover that printed above the credential's counter was alive after the read
helper, state = fake_helper(lambda n: (cred(120), printed(125)) if n == 2 else (cred(120), printed(120)))
entry, refused = D.row_leftover(helper, {"ready": True})
must(refused is None and entry["verdict"] == "ATTACK SUCCEEDED" and "try 2" in entry["actual"] and state["n"] == 2, (entry, state["n"]))
# killed before the read: the output never goes past the credential's counter (or one below it)
helper, state = fake_helper(lambda n: (cred(120), printed(119 + n % 2)))
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "OK" and state["n"] == 3, (entry, state["n"]))
helper, state = fake_helper(lambda n: (cred(1), ""))
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "OK", "a leftover that printed nothing and wrote once")
helper, state = fake_helper(lambda n: (None, ""))
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "NOT RUN" and "no credential returned" in entry["actual"], entry)
helper, state = fake_helper(lambda n: ("original-x", ""))
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "NOT RUN" and "not the leftover's own text" in entry["actual"], entry)
helper, state = fake_helper(lambda n: (None, ""), refuse="sandbox_unavailable")
entry, refused = D.row_leftover(helper, {"ready": True})
must(entry is None and refused == "sandbox_unavailable", "a unit that cannot start is reported")
# the group choice is added to the driver's own copy of the row; the credential goes in as 'auth'
row, kw = state["rows"][0]
must(D.GROUP_LEFTOVER in row["parameters"]["group"]["choices"] and D.GROUP_LEFTOVER not in sh.CANARY_GROUPS, "only the group choice is added")
must(kw["parameters"] == {"group": D.GROUP_LEFTOVER} and set(kw["credentials"]) == {"auth"} and json.loads(kw["input_data"])["marker"] == D.MARKER, kw["parameters"])


# ------------------------------------------------------------------------------------------------ whole runs
def out_frame(lines):
    return {"t": "out", "b": base64.b64encode("".join(lines).encode()).decode()}


def run_main(syscall_rows=None, credential_result=None, source=ROOT, helper_file=HELPER_FILE, selftest_file=SELFTEST_FILE, refuse_second=False, validator=None, stat_fn=None):
    """D.main with a fake launch: the leftover run returns ``credential_result`` (credential, printed text); the syscall run prints ``syscall_rows``."""
    syscall_rows = syscall_rows if syscall_rows is not None else {name: ("OK", "refused (EPERM)") for name in D.SYSCALL_ROWS}
    credential_result = credential_result if credential_result is not None else (cred(50), printed(50))
    saved = (sh.launch, sh.read_status, sh._check_parameters)

    def fake_launch(row, **kw):
        group = kw["parameters"]["group"]
        if group == D.GROUP_SYSCALLS:
            if refuse_second:
                raise sh.Refusal("sandbox_unavailable")
            kw["emit"](out_frame([f"CANARYROW\t{name}\t{tag}\t{actual}\n" for name, (tag, actual) in syscall_rows.items()]))
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0})
        else:
            token, shown = credential_result
            kw["emit"](out_frame([shown]))
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0, "credential_b64": base64.b64encode(token.encode()).decode() if token else None})

    sh.launch, sh.read_status = fake_launch, lambda: {"ready": True}
    if validator is not None:
        sh._check_parameters = validator
    lines = []
    try:
        code = D.main(helper=sh, out=lines.append, source_root=source, helper_path=helper_file, sudoers_path=sudoers, tries=3, selftest_path=selftest_file, stat_fn=stat_fn or stat_ok)
    finally:
        sh.launch, sh.read_status, sh._check_parameters = saved
    return code, lines


code, lines = run_main()
must(code == 0, "\n".join(lines))
must(sum(1 for line in lines if line.startswith("ok   pc-")) == 9 and not any(line.startswith("FAIL") for line in lines), "\n".join(lines))
summary = next(line for line in lines if line.startswith("PATCH C ROWS:"))
must(summary.startswith("PATCH C ROWS: 9 OK, 0 ATTACK SUCCEEDED, 0 NOT RUN (reason)"), summary)
for rid in D.ROW_IDS:
    must(rid in summary and f"ROW {rid} OK" in lines, rid)
# an ATTACK SUCCEEDED row exits 1 and the summary shows it
code, lines = run_main({**{name: ("OK", "x") for name in D.SYSCALL_ROWS}, "keyctl reachable": ("SUCCEEDED", "the call was not refused")})
must(code == 1 and any(line.startswith("FAIL pc-keyctl-reachable: ATTACK SUCCEEDED") for line in lines) and any(line.startswith("PATCH C ROWS: 8 OK, 1 ATTACK SUCCEEDED, 0 NOT RUN (reason)") for line in lines), "\n".join(lines))
# NOT RUN passes only with an allowed printed reason
allowed = {"io_uring_setup reachable": ("NOTRUN", "kernel.io_uring_disabled=2: the kernel itself refuses io_uring"), "userfaultfd reachable": ("NOTRUN", "the kernel has no userfaultfd (ENOSYS)"),
           "keyctl reachable": ("NOTRUN", "unknown machine architecture 'riscv64': no syscall numbers for it")}
code, lines = run_main(allowed)
must(code == 0 and any(line.startswith("PATCH C ROWS: 6 OK, 0 ATTACK SUCCEEDED, 3 NOT RUN (reason)") for line in lines), "\n".join(lines))
code, lines = run_main({**allowed, "keyctl reachable": ("NOTRUN", "the probe could not run (OSError)")})
must(code == 1 and any(line.startswith("FAIL pc-keyctl-reachable: NOT RUN") for line in lines), "NOT RUN with another reason fails")
code, lines = run_main({"io_uring_setup reachable": ("OK", "x")})
must(code == 1 and sum(1 for line in lines if line.startswith("FAIL pc-")) == 2, "\n".join(lines))  # two probes printed nothing: NOT RUN without a reason
code, lines = run_main({**{name: ("OK", "x") for name in D.SYSCALL_ROWS}, "keyctl reachable": ("SKIP", "x")})
must(code == 1, "a SKIPPED row is not an expected answer")
# the leftover row in a whole run
code, lines = run_main(credential_result=(cred(50), printed(60)))
must(code == 1 and any(line.startswith("FAIL pc-leftover-before-credential: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
code, lines = run_main(credential_result=("", ""))
must(code == 0 and any("pc-leftover-before-credential: NOT RUN: NOT RUN with a printed reason" in line for line in lines), "\n".join(lines))
# a tree without the fixes fails
(fixed / "docs" / "sandbox-capability.md").write_text("nothing about it", encoding="utf-8")
code, lines = run_main(source=fixed)
must(code == 1 and any(line.startswith("FAIL pc-returned-credential-untrusted: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
code, lines = run_main(validator=Lax()._check_parameters)
must(code == 1 and any(line.startswith("FAIL pc-registration-type-checks: ATTACK SUCCEEDED") for line in lines) and any(line.startswith("FAIL pc-pattern-field: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
code, lines = run_main(helper_file=old_helper)
must(code == 1 and any(line.startswith("FAIL pc-selftest-in-sudoers: ATTACK SUCCEEDED") for line in lines) and any(line.startswith("FAIL pc-helper-shebang-no-i: ATTACK SUCCEEDED") for line in lines), "\n".join(lines))
# a unit that cannot start is exit 2
code, lines = run_main(refuse_second=True)
must(code == 2 and any("could not be started (sandbox_unavailable)" in line for line in lines), "\n".join(lines))
# the helper's constants are untouched
must(not any(g.startswith("patchc") for g in sh.CANARY_GROUPS), "CANARY_GROUPS untouched")
# classify catches a repeated or missing row
table = [D.entry(D.R_PATTERN, "OK", "x"), D.entry(D.R_PATTERN, "OK", "x")]
results = D.classify(table)
must(any(problem for _rid, _verdict, _label, problem in results) and len(results) > 2, "a repeated row is a problem and the missing rows are listed")
print("[TEST] PASS sandbox canary patchc driver 1.18.28")
