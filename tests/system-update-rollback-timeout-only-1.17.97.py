#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.97 (held Medium of the 1.17.96 review): a rollback warning is only for a verification step that TIMED OUT.

The warning needs exit 79, the "[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying <step>" marker AND the installer's own
"VERIFY STEP FAILED: <step> (timed out after N s ..." line for the same step. A verification step that failed for another reason (a model or RBAC
assertion, a missing route, a registry assertion) means the restored Core may not load: ROLLBACK FAILED. The old installer's text (exit 1) cannot
prove a timeout, so it is ROLLBACK FAILED too. The text before the rollback offset (the forward installer) never counts. The warning's advice names
what may not have run. Same ast-extract harness as tests/system-update-rollback-verify-warning-1.17.96.py (the helper cannot load on this PC)."""
from __future__ import annotations

from pathlib import Path

_here = Path(__file__).resolve().parent
_name = "system-update-rollback-verify-warning-1.17.96.py"
_source = (_here / _name).read_text(encoding="utf-8")
_cut = _source.index("# (1) new installer")
exec(compile(_source[:_cut], str(_here / _name), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

OTHER_STEP = "Framework API route"
OTHER_TIMEOUT = f"[TEC-TAC] VERIFY STEP FAILED: {OTHER_STEP} (timed out after 120 s; 121 s elapsed)"
NON_TIMEOUT = f"[TEC-TAC] VERIFY STEP FAILED: {VERIFY_STEP} (exit status 1; 3 s elapsed)"


def failed(effect, why):
    s = scenario(effects=[FORWARD_FAIL, effect], git_state=GIT_STATE)
    f = s["final"]
    must(f["rollback"]["status"] == "failed" and f["stage"] == "rollback-failed", (why, f["rollback"]))
    must("ROLLBACK FAILED" in s["log"] and "verification warning" not in s["log"], (why, s["log"]))
    must("installer_exit_status" not in f["rollback"] and "rollback installer exited with status" in f["rollback"]["error"], (why, f["rollback"]))


# (1) the timeout and its marker, for the same step: a warning with advice that names what may not have run
s = scenario(effects=[FORWARD_FAIL, (79, OLD_ERR + "\n" + TIMEOUT_LINE + "\n" + NEW_MARK)], git_state=GIT_STATE)
f = s["final"]
must(f["rollback"]["status"] == "warning" and f["stage"] == "rolled-back" and f["rollback"]["warning"] == f"Verifying {VERIFY_STEP}", f["rollback"])
must(f["rollback"]["incomplete_stages"] == ["helper scripts", "timers", "service restart"], f["rollback"])
advice = f["rollback"]["advice"]
must("helper scripts" in advice and "timers" in advice and "restart" in advice and VERIFY_STEP in advice, advice)
must("systemctl restart" in f["rollback"]["restart"] and "daphne" in f["rollback"]["restart"], f["rollback"])
must(WARN_LOG in s["log"] and "ROLLBACK FAILED" not in s["log"], s["log"])
print("       exit 79 + marker + timed-out line: warning; the advice names helpers, timers and the restart; the log line is unchanged")

# (2) the marker without the timed-out line: the step failed for another reason
failed((79, NON_TIMEOUT + "\n" + NEW_MARK), "marker and a non-timeout failure line")
failed((79, NEW_MARK), "marker only")
print("       exit 79 + marker but no timed-out line (a model, route or registry failure): ROLLBACK FAILED")

# (3) no marker at all: the old 'an installer verification step' fallback is gone
failed((79, TIMEOUT_LINE), "timed-out line, no marker")
failed((79, ""), "exit 79 and nothing else")
failed((79, "[TEC-TAC-INSTALL] VERIFY-FAILED: nothing useful"), "marker without a Verifying label")
failed((79, TIMEOUT_LINE + "\n[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying A step that does not exist"), "marker of an unknown step")
print("       exit 79 with no usable marker: ROLLBACK FAILED, no fallback label")

# (4) a timed-out line of a DIFFERENT step than the marker
failed((79, OTHER_TIMEOUT + "\n" + NEW_MARK), "timeout line of another step")
print("       the timed-out line of another step than the marker: ROLLBACK FAILED")

# (5) the old installer: exit 1 and its error text can never prove a timeout
failed((1, OLD_ERR), "old installer text")
failed((1, TIMEOUT_LINE + "\n" + OLD_ERR), "old installer text with a timed-out line")
print("       the old installer's exit 1 text: ROLLBACK FAILED")

# (6) the forward installer's text before the offset never counts
s = scenario(effects=[(79, TIMEOUT_LINE + "\n" + NEW_MARK), (79, "")], git_state=GIT_STATE)
must(s["final"]["rollback"]["status"] == "failed" and "ROLLBACK FAILED" in s["log"], s["final"]["rollback"])
s = scenario(effects=[(79, OTHER_TIMEOUT + "\n" + "[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying " + OTHER_STEP), (79, TIMEOUT_LINE)], git_state=GIT_STATE)
must(s["final"]["rollback"]["status"] == "failed", s["final"]["rollback"])
print("       text written by the forward installer, before the rollback offset, never counts")

# (7) the classifier on its own
probe_dir = Path(tempfile.mkdtemp(prefix="suh-timeout-only-"))
log_path = probe_dir / "job.log"
log_path.write_text("older line\n", encoding="utf-8")
offset = log_path.stat().st_size
with log_path.open("a", encoding="utf-8") as handle:
    handle.write(TIMEOUT_LINE + "\n" + NEW_MARK + "\n")
ns2: dict = {"re": re, "os": os}
exec(compile(ast.Module(body=EXTRACTED, type_ignores=[]), str(HELPER), "exec"), ns2)  # noqa: S102 - test only
classify = ns2["_rollback_verification_step"]
must(classify(79, log_path, offset) == f"Verifying {VERIFY_STEP}", "the pair after the offset counts")
must(classify(1, log_path, offset) is None and classify(0, log_path, offset) is None and classify(78, log_path, offset) is None, "only exit 79")
must(classify(79, log_path, None) is None and classify(79, probe_dir / "missing.log", 0) is None, "no offset or no log: nothing")
must("an installer verification step" not in HELPER.read_text(encoding="utf-8"), "the fallback label is deleted")
print("       classifier: the pair after the offset only; exit 79 only; no offset and no log are safe")
print("[TEST] PASS system update rollback timeout only 1.17.97")
