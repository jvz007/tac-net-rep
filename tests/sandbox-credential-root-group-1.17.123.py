#!/usr/bin/env python3
"""1.17.123 regression: group root is accepted for the credential file only with an ACL that names the unit's uid (core.sandbox canary, fix 6).

Correction of the 1.17.122 record (appended to RELEASE_NOTES_1.17.122.md as 'Correction (Core 1.17.123)'): 1.17.122 was not a pure narrowing of
1.17.120. It newly accepted root as owner or group and added the uid floor (61184) while removing the 'any dynamic gid' case. 1.17.123
narrows group root to the one case that works: the file's ACL exists and holds the named entry user:<unit uid> with read only. Mode 400 or 440
root:root with no ACL is refused with a plain reason (the unit could not read it anyway). The owner rule is unchanged (root or the unit's uid);
the group is otherwise only the unit's own gid. The dev02 shape (root:root, 440, ACL user::r--, user:<uid>:r--, group::---, mask::r--,
other::---) stays accepted.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_123f", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_123f", "sandbox-fake-runner-1.17.120.py")
sh, must, BASE = H.sh, H.must, H.BASE
P = sh.credential_mode_problem
U = "61500"


def acl(uid=U, perm="r--", mask="r--", group="---"):
    return f"ACL user::r--,user:{uid}:{perm},group::{group},mask::{mask},other::---"


# ---- group root with no ACL: refused, with a plain reason (1.17.122 accepted it)
for mode in ("400", "440"):
    for ans in ("ACL none", ""):
        problem = P(f"{mode} 0 0", U, U, ans)
        must(problem != "", (mode, ans))
    problem = P(f"{mode} 0 0", U, U, "ACL none")
    must("group is root" in problem and "no read-only entry for the unit's own user" in problem and f"uid {U}" in problem and "could not read it" in problem, problem)
    must("found: owner root, group root" in problem, "the problem names what was found")
    problem = P(f"{mode} {U} 0", U, U, "ACL none")  # owner is the unit, group root, no ACL: the same rule
    must("group is root" in problem, (mode, problem))
# ---- group root with an ACL naming the unit's uid, read only: accepted
must(P("440 0 0", U, U, acl()) == "", "root:root 440 with the unit's entry")
must(P("400 0 0", U, U, acl(mask="---")) == "", "root:root 400, the entry present")
must(P("440 0 0", "61908", "61908", "ACL user::r--,user:61908:r--,group::---,mask::r--,other::---") == "", "the exact dev02 shape (group::---)")
must(P("440 0 0", "61908", "61908", "ACL user::r--,user:61908:r--,group::r--,mask::r--,other::---") == "", "the same with group::r-- (the 1.17.122 fake default)")
must(P(f"440 {U} 0", U, U, acl()) == "", "owner the unit, group root, the entry present")
# ---- group root with an ACL that names another uid, a group, write or execute: refused
for label, answer, part in (("another uid", acl(uid="61999"), "not the unit's own"), ("two users", f"ACL user::r--,user:{U}:r--,user:61999:r--,group::---,mask::r--,other::---", "not the unit's own"),
                            ("write on the entry", acl(perm="rw-", mask="rw-"), "not read only"), ("execute on the entry", acl(perm="r-x"), "not read only"),
                            ("a named group", f"ACL user::r--,user:{U}:r--,group:{U}:r--,group::---,mask::r--,other::---", "named group"),
                            ("other readable", f"ACL user::r--,user:{U}:r--,group::---,mask::r--,other::r--", "other users"),
                            ("only a named group", f"ACL user::r--,group:{U}:r--,group::---,mask::r--,other::---", "named group"),
                            ("incomplete", f"ACL user::r--,user:{U}:r--,mask::r--,other::---", "incomplete"),
                            ("garbled", "ACL user::r--,user:61500:r", "missing or garbled"), ("missing answer", "", "missing or garbled")):
    problem = P("440 0 0", U, U, answer)
    must(problem != "" and part in problem, (label, problem))
# ---- the owner and mode rules are unchanged
must(P("440 0 0", U, U, acl()) == "" and P("640 0 0", U, U, acl()) != "" and P("444 0 0", U, U, acl()) != "" and P("600 0 0", U, U, acl()) != "", "mode 400 or 440 only")
must(P("440 1000 0", U, U, acl()) != "" and P("440 0 0", "1000", "61500", acl("1000")) != "", "owner root or the unit's uid; the unit's ids at or above 61184")
# ---- the unit's own gid is still accepted without any ACL
must(P(f"440 {U} {U}", U, U, "ACL none") == "" and P(f"400 {U} {U}", U, U, "ACL none") == "" and P(f"440 0 {U}", U, U, "ACL none") == "", "own gid, no ACL")
must(P(f"440 {U} {U}", U, U, acl()) == "", "own gid with the unit's entry")
# ---- the old 'any dynamic gid' case is still refused
must("not root or the unit's own" in P(f"440 {U} 61999", U, U, "ACL none") and "not root or the unit's own" in P("440 0 61999", U, U, acl()), "any dynamic gid is refused")
must("not root or the unit's own" in P(f"440 {U} 65000", U, U, acl()), "gid 65000 against 61500")
# ---- through the selftest: ready only for the accepted shapes (the fake's default is the dev02 shape)


def run(**changes):
    fake = F.Fake()
    fake.credential.update(changes)
    return F.run_selftest(sh, H.RUN, BASE, fake)


dev02 = run()
must(dev02["ready"] is True and dev02["checks"]["credential"]["detail"].startswith("arrived, owner root, group root, mode 440, ACL user::r--, user:61500:r--"), dev02["checks"]["credential"])
no_acl = run(acl="ACL none")  # root:root 440 with no ACL: what 1.17.122 accepted
must(no_acl["ready"] is False and "LoadCredential did not work" in no_acl["reason"] and "no read-only entry for the unit's own user" in no_acl["checks"]["credential"]["detail"], no_acl)
other = run(acl=acl(uid="61999"))
must(other["ready"] is False and "not the unit's own" in other["checks"]["credential"]["detail"], other)
must(run(uid=U, gid=U, acl="ACL none")["ready"] is True, "own uid and gid, no ACL")
must(run(uid=U, gid="61999", acl="ACL none")["ready"] is False, "any dynamic gid")
# the correction is on record
notes = (H.ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.122.md").read_text(encoding="utf-8")
must("Correction (Core 1.17.123)" in notes and "not a pure narrowing" in notes and "61184" in notes and "group root" in notes, "the 1.17.122 notes carry the correction")
new = (H.ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.123.md").read_text(encoding="utf-8")
must("not a pure narrowing" in new and "ACL" in new and "61184" in new, "the 1.17.123 notes say it plainly too")

print("[TEST] PASS sandbox credential root group 1.17.123")
