#!/usr/bin/env python3
"""1.18.25 regression (AD-65 Patch C, canary rows only): the root driver tests/sandbox-canary-patchc-1.18.25.py, with a stubbed helper loader and launch.

Django-free; no socket, no listener, no syscall. The real helper source is loaded from scripts/ only to read its text and call its registration
validator, and ``launch`` is replaced by a fake that prints the in-unit rows. Covered:

* every row id exists once, in the order of ROW_IDS; the summary line carries the counts the canary script greps;
* on today's source tree every host row is ATTACK SUCCEEDED (the contract has no untrusted-credential sentence, the helper has --selftest and --canary
  and a plain python3 shebang, the validator accepts string and boolean limits and a 'pattern' field), so the table exits 0;
* the all-ATTACK table exits 0; one row OK exits 1; NOT RUN exits 0 only with an allowed reason (unknown architecture, ENOSYS, io_uring_disabled=2,
  no credential returned) and 1 for any other; a missing row exits 1; a unit that cannot start exits 2;
* each host row flips to OK when its fix is present (a text with the sentence, a helper without the entry points, a python -I shebang, a validator that
  refuses) and to NOT RUN when its input cannot be read;
* the leftover row: the marker in a returned credential is ATTACK SUCCEEDED (on the first try it stops), the original credential in three tries is OK,
  no credential in three tries is NOT RUN with 'no credential returned';
* the driver adds only the group choice to its copy of the row and leaves the helper's constants alone.

Not runnable here: the real launcher, systemd, seccomp state (dev02: tests/sandbox-canary-1.18.25.sh, step 5w).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
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


D = load("sandbox_patchc_driver", ROOT / "tests" / "sandbox-canary-patchc-1.18.25.py")
sh = load("sandbox_helper_pcdrv", ROOT / "scripts" / "sandbox-helper.py")
HELPER_FILE = ROOT / "scripts" / "sandbox-helper.py"

must(len(D.ROW_IDS) == 9 and len(set(D.ROW_IDS)) == 9 and set(D.LABELS) == set(D.ROW_IDS), "nine rows, stable and unique")
must(set(D.SYSCALL_ROWS.values()) <= set(D.ROW_IDS), "the in-unit rows map to known ids")
must(b"\r" not in (ROOT / "tests" / "sandbox-canary-patchc-1.18.25.py").read_bytes(), "LF")
text = (ROOT / "tests" / "sandbox-canary-patchc-1.18.25.py").read_text(encoding="utf-8")
must('("0.0.0.0"' not in text and "bind(" not in text and "socket" not in text.replace("secrets", ""), "the driver opens no socket")
for rid in D.ROW_IDS:
    must(len(rid) <= 40 and rid.startswith("pc-"), rid)

# ------------------------------------------------------------------------------------------------ the host rows on today's tree
must(D.row_untrusted(ROOT)["verdict"] == "ATTACK SUCCEEDED", D.row_untrusted(ROOT))
sudoers = BASE / "sudoers"
sudoers.write_text("# comment tec-tac-sandbox\ntactical ALL=(root) NOPASSWD: /usr/local/sbin/tec-tac-sandbox --start, /usr/local/sbin/tec-tac-sandbox --stop\n", encoding="utf-8")
entry = D.row_sudoers(HELPER_FILE, sudoers)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "def selftest" in entry["actual"] and "def run_canary" in entry["actual"] and "NOPASSWD" in entry["actual"], entry)
entry = D.row_shebang(HELPER_FILE)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "#!/usr/bin/python3" in entry["actual"], entry)
entry = D.row_types(sh)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "max_length as a string: accepted" in entry["actual"], entry)
entry = D.row_pattern(sh)
must(entry["verdict"] == "ATTACK SUCCEEDED" and "accepted" in entry["actual"], entry)

# ------------------------------------------------------------------------------------------------ each host row flips with its fix
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
clean_helper = BASE / "clean-helper.py"
clean_helper.write_text("#!/usr/bin/python3 -I\nimport sys\n", encoding="utf-8")
must(D.row_sudoers(clean_helper, sudoers)["verdict"] == "OK" and D.row_shebang(clean_helper)["verdict"] == "OK", "a clean helper file")
for first in ("#!/usr/bin/python3 -I", "#!/usr/bin/python3 -Is", "#!/usr/bin/env -S python3 -I", "#!/usr/bin/python3.12 -sI"):
    clean_helper.write_text(first + "\n", encoding="utf-8")
    must(D.row_shebang(clean_helper)["verdict"] == "OK", first)
for first in ("#!/usr/bin/python3", "#!/usr/bin/env python3", "#!/usr/bin/python3 -B", "# no shebang"):
    clean_helper.write_text(first + "\n", encoding="utf-8")
    must(D.row_shebang(clean_helper)["verdict"] == "ATTACK SUCCEEDED", first)
must(D.row_shebang(BASE / "nowhere")["verdict"] == "NOT RUN" and D.row_sudoers(BASE / "nowhere", sudoers)["verdict"] == "NOT RUN", "unreadable helper is NOT RUN")


class Strict:
    """A helper whose validator refuses everything it should (the fixed build)."""

    def _check_parameters(self, schema, label):
        spec = schema["probe"]
        if "pattern" in spec or any(not isinstance(spec.get(key, 0), int) or isinstance(spec.get(key, 0), bool) for key in ("max_length", "minimum", "maximum")):
            raise RuntimeError("refused")


must(D.row_types(Strict())["verdict"] == "OK" and D.row_pattern(Strict())["verdict"] == "OK", "a validator that refuses is OK")


class Crashing:
    def _check_parameters(self, schema, label):
        raise TypeError("'<' not supported between 'str' and 'int'")


entry = D.row_types(Crashing())
must(entry["verdict"] == "ATTACK SUCCEEDED" and "crashed: TypeError" in entry["actual"], "an uncaught TypeError is the finding")
must(D.row_types(object())["verdict"] == "NOT RUN" and D.row_pattern(object())["verdict"] == "NOT RUN", "no validator by that name is NOT RUN")
must(D.row_types(Strict())["verdict"] == "OK", "again")

# ------------------------------------------------------------------------------------------------ the leftover row
def fake_helper(credential_for_try, refuse=None):
    """The real helper's parsers with launch replaced; credential_for_try(n) is the credential text the n-th run returns (None for none)."""
    state = {"n": 0, "rows": []}

    class H:
        def __getattr__(self, name):
            return getattr(sh, name)

        def launch(self, row, **kw):
            state["rows"].append((row, kw))
            if refuse:
                raise sh.Refusal(refuse)
            state["n"] += 1
            credential = credential_for_try(state["n"])
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0, "credential_b64": base64.b64encode(credential.encode()).decode() if credential is not None else None})

        def read_status(self):
            return {"ready": True}

    return H(), state


helper, state = fake_helper(lambda n: D.MARKER if n == 2 else "original-x")
entry, refused = D.row_leftover(helper, {"ready": True})
must(refused is None and entry["verdict"] == "ATTACK SUCCEEDED" and "try 2" in entry["actual"] and state["n"] == 2, (entry, state["n"]))
helper, state = fake_helper(lambda n: "original-x")
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "OK" and state["n"] == 3, "three tries, the marker never arrived")
helper, state = fake_helper(lambda n: None)
entry, _r = D.row_leftover(helper, {"ready": True})
must(entry["verdict"] == "NOT RUN" and "no credential returned" in entry["actual"], entry)
helper, state = fake_helper(lambda n: None, refuse="sandbox_unavailable")
entry, refused = D.row_leftover(helper, {"ready": True})
must(entry is None and refused == "sandbox_unavailable", "a unit that cannot start is reported")
# the group choice is added to the driver's own copy of the row; the credential goes in as 'auth'
row, kw = state["rows"][0]
must(D.GROUP_LEFTOVER in row["parameters"]["group"]["choices"] and D.GROUP_LEFTOVER not in sh.CANARY_GROUPS, "only the group choice is added")
must(kw["parameters"] == {"group": D.GROUP_LEFTOVER} and set(kw["credentials"]) == {"auth"} and json.loads(kw["input_data"])["marker"] == D.MARKER, kw["parameters"])


# ------------------------------------------------------------------------------------------------ whole runs
def out_frame(lines):
    return {"t": "out", "b": base64.b64encode("".join(lines).encode()).decode()}


def run_main(syscall_rows=None, credential="MARK", source=ROOT, helper_file=HELPER_FILE, refuse_second=False, validator=None):
    """D.main with a fake launch: the leftover run returns ``credential``; the syscall run prints ``syscall_rows`` (name -> (tag, text))."""
    syscall_rows = syscall_rows if syscall_rows is not None else {name: ("SUCCEEDED", "the call was not refused") for name in D.SYSCALL_ROWS}
    saved = (sh.launch, sh.read_status, sh._check_parameters)
    calls = {"n": 0}

    def fake_launch(row, **kw):
        calls["n"] += 1
        group = kw["parameters"]["group"]
        if group == D.GROUP_SYSCALLS:
            if refuse_second:
                raise sh.Refusal("sandbox_unavailable")
            kw["emit"](out_frame([f"CANARYROW\t{name}\t{tag}\t{actual}\n" for name, (tag, actual) in syscall_rows.items()]))
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0})
        else:
            token = D.MARKER if credential == "MARK" else credential
            kw["emit"]({"t": "end", "reason": "exited", "exit": 0, "credential_b64": base64.b64encode(token.encode()).decode() if token else None})

    sh.launch, sh.read_status = fake_launch, lambda: {"ready": True}
    if validator is not None:
        sh._check_parameters = validator
    lines = []
    try:
        code = D.main(helper=sh, out=lines.append, source_root=source, helper_path=helper_file, sudoers_path=sudoers, tries=3)
    finally:
        sh.launch, sh.read_status, sh._check_parameters = saved
    return code, lines


code, lines = run_main()
must(code == 0, "\n".join(lines))
must(sum(1 for line in lines if line.startswith("ok   pc-")) == 9 and not any(line.startswith("FAIL") for line in lines), "\n".join(lines))
summary = next(line for line in lines if line.startswith("PATCH C ROWS:"))
must(summary.startswith("PATCH C ROWS: 9 ATTACK SUCCEEDED, 0 NOT RUN (reason), 0 OK"), summary)
for rid in D.ROW_IDS:
    must(rid in summary and f"ROW {rid} ATTACK SUCCEEDED" in lines, rid)
must("expected: " in summary, summary)
# one row OK exits 1 and the summary shows it
code, lines = run_main({**{name: ("SUCCEEDED", "x") for name in D.SYSCALL_ROWS}, "keyctl reachable": ("OK", "refused (EPERM)")})
must(code == 1 and any(line.startswith("FAIL pc-keyctl-reachable: OK") for line in lines) and any(line.startswith("PATCH C ROWS: 8 ATTACK SUCCEEDED, 0 NOT RUN (reason), 1 OK") for line in lines), "\n".join(lines))
# NOT RUN passes only with an allowed printed reason
allowed = {"io_uring_setup reachable": ("NOTRUN", "kernel.io_uring_disabled=2: the kernel itself refuses io_uring"), "userfaultfd reachable": ("NOTRUN", "the kernel has no userfaultfd (ENOSYS)"),
           "keyctl reachable": ("NOTRUN", "unknown machine architecture 'riscv64': no syscall numbers for it")}
code, lines = run_main(allowed)
must(code == 0 and any(line.startswith("PATCH C ROWS: 6 ATTACK SUCCEEDED, 3 NOT RUN (reason), 0 OK") for line in lines), "\n".join(lines))
code, lines = run_main({**allowed, "keyctl reachable": ("NOTRUN", "the probe could not run (OSError)")})
must(code == 1 and any(line.startswith("FAIL pc-keyctl-reachable: NOT RUN") for line in lines), "NOT RUN with another reason fails")
code, lines = run_main({"io_uring_setup reachable": ("SUCCEEDED", "x")})
must(code == 1 and sum(1 for line in lines if line.startswith("FAIL pc-")) == 2, "\n".join(lines))  # two probes printed nothing: NOT RUN without a reason
code, lines = run_main({**{name: ("SUCCEEDED", "x") for name in D.SYSCALL_ROWS}, "keyctl reachable": ("SKIP", "x")})
must(code == 1, "a SKIPPED row is not an expected answer")
# the leftover row in a whole run
code, lines = run_main(credential="original-only")
must(code == 1 and any(line.startswith("FAIL pc-leftover-before-credential: OK") for line in lines), "\n".join(lines))
code, lines = run_main(credential="")
must(code == 0 and any("pc-leftover-before-credential: NOT RUN: NOT RUN with a printed reason" in line for line in lines), "\n".join(lines))
# a fixed tree shows OK rows and exits 1
(fixed / "docs" / "sandbox-capability.md").write_text("text. " + sentence, encoding="utf-8")
code, lines = run_main(source=fixed)
must(code == 1 and any(line.startswith("FAIL pc-returned-credential-untrusted: OK") for line in lines), "\n".join(lines))
code, lines = run_main(validator=Strict()._check_parameters)
must(code == 1 and any(line.startswith("FAIL pc-registration-type-checks: OK") for line in lines) and any(line.startswith("FAIL pc-pattern-field: OK") for line in lines), "\n".join(lines))
# a unit that cannot start is exit 2
code, lines = run_main(refuse_second=True)
must(code == 2 and any("could not be started (sandbox_unavailable)" in line for line in lines), "\n".join(lines))
# the helper's constants are untouched
must(not any(g.startswith("patchc") for g in sh.CANARY_GROUPS), "CANARY_GROUPS untouched")
# classify catches a repeated or missing row
table = [D.entry(D.R_PATTERN, "ATTACK SUCCEEDED", "x"), D.entry(D.R_PATTERN, "ATTACK SUCCEEDED", "x")]
results = D.classify(table)
must(sum(1 for r in results if r[3]) == 1 + 8, results)  # the repeat, and the eight rows never produced
print("[TEST] PASS sandbox canary patchc driver 1.18.25")
