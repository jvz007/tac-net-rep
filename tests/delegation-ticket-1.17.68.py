#!/usr/bin/env python3
"""1.17.68 regression (review rounds 1 to 3): the delegated start is on by AD-43 (CQ204, Johan, 21 October 2026), one ticket starts one run, and the Yes/No text says what happens.

Covered. (1) ``delegation.DECISION_RECORDED`` is True, and it may be True only while docs/review-accepted-decisions.md has a delegation row that names
the ticket and the grant. (2) The switch: with it False a one-off with a valid marker is NOT unattended (the owner's permission and scope are re-checked, so a
disabled owner fails closed); with it True, and as shipped, it is exempt. (3) A second ``start`` with another endpoint subset on the same ticket is refused (ticket_used,
one deny row, nothing started); the same endpoints again answer the earlier run; a new ticket is a new call. (4) The Yes/No text has one wording, for the live
state. It reuses the set-up of delegation-run-1.17.68.py (everything before its first numbered section) and its own helpers.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISIONS = ROOT.parents[1] / "docs" / "review-accepted-decisions.md"
RUN_TEST = ROOT / "tests" / "delegation-run-1.17.68.py"
SOURCE = (ROOT / "framwork" / "tec_tac" / "delegation.py").read_text(encoding="utf-8")

flag = re.search(r"^DECISION_RECORDED = (True|False)", SOURCE, re.MULTILINE)
text = DECISIONS.read_text(encoding="utf-8") if DECISIONS.exists() else ""
row = [ln for ln in text.splitlines() if ln.lstrip().startswith("|") and re.search(r"delegat", ln, re.IGNORECASE) and re.search(r"CQ204|unattended", ln, re.IGNORECASE)]
problems = []
if flag is None:
    problems.append("DECISION_RECORDED is missing from delegation.py")
elif flag.group(1) == "True" and not (row and all(k in row[0].lower() for k in ("ticket", "grant"))):
    problems.append("DECISION_RECORDED is True but no accepted delegation row names the ticket and grant conditions")
elif flag.group(1) != "True":
    problems.append("AD-43 is signed: DECISION_RECORDED must be True")
if problems:
    raise AssertionError(problems)
print("       DECISION_RECORDED is True only while the accepted-decisions file records the delegation")

code = RUN_TEST.read_text(encoding="utf-8")
code = code.split("# ---- (1) the whole path, with the owner disabled")[0]
code += """
fresh()
save_grant()
t = ticket()
run = start(t)
LIVE_SWITCH = deleg.DECISION_RECORDED
must(LIVE_SWITCH is True and deleg.run_is_validly_delegated(run) is True and sched._is_unattended_scheduled_run(run) is True, "as shipped: a valid marker is exempt")
deleg.DECISION_RECORDED = False
try:
    must(deleg.run_is_validly_delegated(run) is False and sched._is_unattended_scheduled_run(run) is False, "switched off: a delegated one-off keeps every re-check")
finally:
    deleg.DECISION_RECORDED = LIVE_SWITCH
must(deleg.run_is_validly_delegated(run) is True and sched._is_unattended_scheduled_run(run) is True, "switched on again: it is exempt")
del AUDITS[:]
refused(lambda: start(t, agents=[1]), "ticket_used")
one_deny("ticket_used")
must(start(t) is run and len(delegated_runs()) == 1 and len(QUEUED_IDS) == 1, "the same endpoints answer the earlier run")
must(start(ticket(), agents=[1]) is not run and len(delegated_runs()) == 2, "a new ticket is a new call")
print("       as shipped a valid marker is exempt; switched off it is not; a second endpoint subset on one ticket is refused, the same one is a retry, a new ticket is new")
# the Yes/No text says what really happens: one wording, for the live state
import types
_real_applies = deleg._sa._reapprove_warning_applies
deleg._sa._reapprove_warning_applies = lambda definition, entry: False
try:
    def _text_for(flag, dangerous=False, vanished=0):
        deleg.DECISION_RECORDED = flag
        try:
            return deleg._text({"total": 1, "groups": 1, "vanished": vanished}, types.SimpleNamespace(username="alice", pk=1), "maintenance",
                               types.SimpleNamespace(label="Install", dangerous=dangerous), None)
        finally:
            deleg.DECISION_RECORDED = LIVE_SWITCH
    live_text = _text_for(True)
    for needle in ("Install: 1 endpoint(s)", "maintenance will start this for you later", "with nobody signed in", "each time its own schedule says so",
                   "Core checks that this confirmation is unchanged", "the modules involved are on", "the replacement is still in place",
                   "every endpoint is inside the targets you confirm here", "Core does not look at your account again", "even if your account is later disabled",
                   "Editing or removing the profile stops it", "Requested by alice. Do you want to continue?"):
        must(needle in live_text, (needle, live_text))
    must("does not check your rights" not in live_text and "checks your rights again each time it starts" not in live_text, "the old over-short sentence and the held-only sentence are gone")
    must(_text_for(False) == live_text, "one wording")
    many = _text_for(True, dangerous=True, vanished=2)
    must("This action can change many endpoints at once." in many and "2 target(s) no longer exist and are left out." in many, many)
finally:
    deleg._sa._reapprove_warning_applies = _real_applies
print("       the Yes/No text names who starts it, nobody signed in, the run-time checks, the account-disabled consequence and the edit-or-remove ending")
print("PASS delegation ticket 1.17.68")
"""
exec(compile(code, str(RUN_TEST), "exec"), {"__file__": str(RUN_TEST), "__name__": "__main__"})  # noqa: S102 - the repo's own test source
