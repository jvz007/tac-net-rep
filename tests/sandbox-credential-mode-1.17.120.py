#!/usr/bin/env python3
"""1.17.120 regression: the credential file mode check and the foreign-reader canary row (core.sandbox canary fix 3).

systemd 255 creates a LoadCredential file with mode 0440, not 0400. The selftest accepts exactly two shapes:

(1.17.122: the rule is tightened, see tests/sandbox-credential-acl-1.17.122.py; the 'any dynamic group' acceptance is gone.)

* mode exactly 400 or 440, owner is root or the unit's uid, group is root or the unit's own gid, the unit's ids are in the dynamic range
  (>= 61184), and an ACL, if any, holds one named entry only: user:<unit uid>, read only.

Everything else fails closed with a plain detail: any 'other' bit (444, 404, 640 has group write but no other bit and is still not 400/440),
a group that is not the unit's own, a gid below 61184, a foreign owner, a missing or garbled stat line, a wrong token, a source that stays.

The canary gets one more row, 'another dynamic user reads the credential file' (expected denied): OK on DENIED, ATTACK SUCCEEDED on READ, NOT
RUN when the probe unit did not start. The row never prints the token or the credential path.

Not runnable here: real systemd. tests/sandbox-canary-1.17.120.sh proves the row on dev02.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_120c", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_120c", "sandbox-fake-runner-1.17.120.py")
sh, must, BASE = H.sh, H.must, H.BASE


def selftest(fake):
    return F.run_selftest(sh, H.RUN, BASE, fake)


def credential(**changes):
    fake = F.Fake()
    fake.credential.update(changes)
    return selftest(fake)


# ---- the two accepted shapes
# 1.17.122: the default fake answer is the real dev02 shape; the detail names owner, group, mode and every ACL entry
ok = credential()
must(ok["ready"] is True and ok["checks"]["credential"] == {"ok": True, "detail": "arrived, owner root, group root, mode 440, ACL user::r--, user:61500:r--, group::r--, mask::r--, other::---, source removed"}, ok["checks"]["credential"])
ok = credential(mode="400", uid="61500", gid="61500", acl="ACL none")
must(ok["ready"] is True and ok["checks"]["credential"]["detail"] == "arrived, owner 61500, group 61500, mode 400, ACL none, source removed", ok["checks"]["credential"])
ok = credential(mode="440", uid="61500", gid="61500", acl="ACL none")
must(ok["ready"] is True and "mode 440" in ok["checks"]["credential"]["detail"] and "ACL none" in ok["checks"]["credential"]["detail"], ok["checks"]["credential"])
must(credential(mode="440", uid="0", gid="61500", acl="ACL none")["ready"] is True, "440 owned by root, group is the unit's own")
must(credential(mode="440", uid="61500", gid="0", acl="ACL none")["ready"] is False, "1.17.123: 440 owned by the unit, group root and no ACL is refused")
must(credential(mode="440", uid="65000", gid="65000", unit_uid="65000", unit_gid="65000", acl="ACL none")["ready"] is True, "a dynamic gid that is the unit's own")
must(credential(mode="440", uid="61184", gid="61184", unit_uid="61184", unit_gid="61184", acl="ACL none")["ready"] is True, "the floor itself is in the dynamic range")
must(not [p for p in H.RUN.iterdir() if p.name.startswith(sh.SELFTEST_PREFIX)], "the probe folder is removed")


# ---- everything else fails closed
def refused(label, part="", **changes):
    status = credential(**changes)
    must(status["ready"] is False and status["checks"]["credential"]["ok"] is False, (label, status["checks"]["credential"]))
    must("LoadCredential did not work" in status["reason"], (label, status["reason"]))
    if part:
        must(part in status["checks"]["credential"]["detail"], (label, status["checks"]["credential"]["detail"]))
    return status


refused("440, another group", "not root or the unit's own", mode="440", uid="61500", gid="61999", acl="ACL none")
refused("440, group is a normal group below 61184", "dynamic range", mode="440", uid="500", gid="500", unit_uid="500", unit_gid="500", acl="ACL none")
refused("440, a foreign owner", "not root or the unit's own", mode="440", uid="1000", gid="61500")
refused("400, a foreign owner", "not root or the unit's own", mode="400", uid="1000", gid="61500")
refused("640", "mode is 640", mode="640")
refused("444, others can read", "other users could read it", mode="444")
refused("404, others can read", "other users could read it", mode="404")
refused("600 owned by a foreign uid", "mode is 600", mode="600", uid="1000")
refused("600", "mode is 600", mode="600")
refused("660", "mode is 660", mode="660")
refused("777", "other users could read it", mode="777")
refused("1440", "not 400 or 440", mode="1440")
refused("a missing stat line", "", stat="")
refused("a stat line without the group", "could not be read", stat="440 61500")
refused("a stat line with words", "could not be read", stat="440 uid gid")
refused("a wrong token", "did not arrive", token="someone else's text")
refused("a source that was not removed", "not removable", remove=False)
must(credential(stat="400 -1 61500")["ready"] is False, "a negative owner is not a number")
# the unit's own ids come from the unit itself: a lying file group does not match a different unit gid
fake = F.Fake()
fake.credential.update(mode="440", uid="61500", gid="61500", acl="ACL none")
real_run = fake.run_unit


def mismatched(name, properties, command, *, timeout=30):
    code, out, err = real_run(name, properties, command, timeout=timeout)
    if name == "credential":
        lines = out.splitlines()
        lines[3] = "61501"  # the unit's gid is not the file's group
        out = "\n".join(lines) + "\n"
    return code, out, err


fake.run_unit = mismatched
must(selftest(fake)["ready"] is False, "440 with a group that is not the id of the unit")

# the unit prints content, 'mode uid gid', uid and gid in one script
fake = F.Fake()
selftest(fake)
script = next(call for call in fake.calls if call[0] == "credential")[2]
must(script[0] == "/bin/sh" and script[1] == "-c" and "stat -c" in script[2] and "id -u" in script[2] and "id -g" in script[2], script)

# the pure function
P = sh.credential_mode_problem
N = "ACL none"
must(P("400 61500 61500", "61500", "61500", N) == "" and P("440 61500 61500", "61500", "61500", N) == "" and P("440 0 61500", "61500", "61500", N) == "", "accepted")
must(P("440 61500 61183", "61183", "61183", N) != "" and P("440 61500 61500", "61500", "61501", N) != "" and P("0440 61500 61500", "61500", "61500", N) != "", "refused")
must(P("", "1", "1", N) != "" and P("440 1 1", "", "1", N) != "" and P("440 1 1", "1", "x", N) != "", "unreadable")

# ---- the canary row
TOKEN = {}


def collect(group, plan, **kwargs):
    TOKEN["token"] = plan["credential_token"]
    stdout = ("CANARYROW\tcredential arrives\tOK\tarrived\nCANARYROW\tcredential mode\tOK\t0o440\n"
              "CANARYROW\tcredential not in environment\tOK\tabsent\n").encode()
    import base64
    return {"stdout": stdout, "stderr": b"", "refused": None, "run_id": kwargs.get("run_id", ""),
            "end": {"reason": "exited", "exit": 0, "credential_b64": base64.b64encode(("refreshed-" + plan["credential_token"]).encode()).decode()}}


sh._holders_search = lambda token, unit: []
status = {"ready": True, "resolver": "127.0.0.53", "resolvers": ["127.0.0.53"]}
WALL = "another dynamic user reads the credential file"


def rows_for(probe):
    rows = sh._credential_rows(collect, status, probe, lambda unit: True)  # 1.17.121: the root-side pre-check is injected (no real systemd here)
    found = [r for r in rows if r["attack"] == WALL]
    must(len(found) == 1 and found[0]["wall"] == "Credential" and found[0]["expected"] == "denied", rows)
    text = json.dumps(rows)
    must(TOKEN["token"] not in text and "/run/credentials" not in text and "auth" not in found[0]["actual"], "the row prints neither the token nor a path")
    return rows, found[0]


seen = []
rows, row = rows_for(lambda unit: seen.append(unit) or "DENIED")
must(row["verdict"] == "OK" and row["actual"] == "denied", row)
must(len(seen) == 1 and seen[0].startswith("tectac-sbx-") or seen[0], seen)
passed, counts = sh.canary_summary(rows)
must(passed is True and counts["ATTACK SUCCEEDED"] == 0 and counts["NOT RUN"] == 0, counts)
rows, row = rows_for(lambda unit: "READ")
must(row["verdict"] == "ATTACK SUCCEEDED" and row["actual"] == "read it", row)
passed, counts = sh.canary_summary(rows)
must(passed is False and counts["ATTACK SUCCEEDED"] == 1, "CANARY FAILED on READ")
for label, probe in (("did not start", lambda unit: ""), ("odd answer", lambda unit: "maybe"), ("raises", lambda unit: (_ for _ in ()).throw(RuntimeError("boom")))):
    rows, row = rows_for(probe)
    must(row["verdict"] == "NOT RUN" and row["actual"] == "probe unit did not start or gave no usable answer", (label, row))
    passed, counts = sh.canary_summary(rows)
    must(passed is False and counts["NOT RUN"] == 1, (label, "NOT RUN fails the canary"))

# ---- the real probe function: a second transient unit with its own dynamic user, nothing shared, answering READ or DENIED only
calls = []


class StubRunner:
    answer = (0, "DENIED\n", "")

    def run_unit(self, name, properties, command, *, timeout=30):
        calls.append((name, tuple(properties), tuple(command)))
        return StubRunner.answer


real_runner = sh.UnitRunner
sh.UnitRunner = StubRunner
try:
    must(sh._foreign_credential_probe("tectac-sbx-abc") == "DENIED", "denied")
    name, properties, command = calls[-1]
    must(properties == ("DynamicUser=yes",), properties)  # no LoadCredential, no bind, no share with the first unit
    must(command[:3] == (sh.UNIT_PYTHON, "-I", "-c") and command[-1] == "/run/credentials/tectac-sbx-abc.service/auth", command)
    must("%" not in "".join(command) and "$" not in "".join(command), "no systemd specifier in the probe command")
    StubRunner.answer = (0, "READ\n", "")
    must(sh._foreign_credential_probe("tectac-sbx-abc") == "READ", "read")
    for answer in ((1, "DENIED\n", "x"), (0, "", ""), (0, "something else\n", ""), (127, "", "no systemd-run")):
        StubRunner.answer = answer
        must(sh._foreign_credential_probe("tectac-sbx-abc") == "", answer)
finally:
    sh.UnitRunner = real_runner
# the probe program itself: READ when the file opens, DENIED when it does not, and it never prints the content
import contextlib
import io

secret = BASE / "foreign-secret"
secret.write_text("TOPSECRET", encoding="utf-8")
for path, want in ((secret, "READ"), (BASE / "no-such-credential", "MISSING")):  # 1.17.121: a missing file is MISSING, never DENIED
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sys.argv = ["-c", str(path)]
        exec(compile(sh._FOREIGN_READ, "foreign-read", "exec"), {})
    must(out.getvalue().strip() == want and "TOPSECRET" not in out.getvalue(), (path, out.getvalue()))

print("[TEST] PASS sandbox credential mode 1.17.120")
