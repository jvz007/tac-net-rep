#!/usr/bin/env python3
"""1.17.122 regression: the selftest credential check reads the file's owner, group, mode and POSIX ACL, and accepts only the one-user shape.

dev02 (Core 1.17.120 run) showed the LoadCredential file is root:root mode 440 with the ACL entry user:<unit uid>:r--. The 1.17.120 rule
('the unit's own dynamic group') refused that correct file. The rule is now (1.17.122), fail closed:

* mode exactly 0400 or 0440, no 'other' bit; owner root or the unit's uid; group root or the unit's own gid; the unit's uid and gid are in the
  dynamic range (>= 61184);
* an ACL, if any: its only named entry is user:<unit uid>, read only; no named group; the mask and every entry except the owner entry grant no
  write; no entry grants execute; 'other' grants nothing; owner, group and other entries are present; a missing, garbled or truncated answer fails;
* the 1.17.120 'any dynamic group' acceptance is gone.

The detail text names owner, group, mode and each ACL entry on OK and on NO, never the token or the path. The in-unit program that decodes
system.posix_acl_access is run here against hand-built bytes (header version 2, user, group, mask, other entries).

Not runnable here: real systemd and a real ACL. tests/sandbox-canary-1.17.122.sh proves the real file on dev02.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import runpy
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_122a", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_122a", "sandbox-fake-runner-1.17.120.py")
sh, must, BASE = H.sh, H.must, H.BASE

U = "61500"
FULL = f"ACL user::r--,user:{U}:r--,group::r--,mask::r--,other::---"


def run(**changes):
    fake = F.Fake()
    fake.credential.update(changes)
    return F.run_selftest(sh, H.RUN, BASE, fake)


def accepted(label, **changes):
    status = run(**changes)
    must(status["ready"] is True and status["checks"]["credential"]["ok"] is True, (label, status["checks"]["credential"]))
    return status["checks"]["credential"]["detail"]


def refused(label, part="", **changes):
    status = run(**changes)
    check = status["checks"]["credential"]
    must(status["ready"] is False and check["ok"] is False and "LoadCredential did not work" in status["reason"], (label, check))
    must(part in check["detail"], (label, check["detail"]))
    return check["detail"]


# ---- accepted
detail = accepted("dev02 shape")  # the fake default: root:root 440, user:61500:r--, mask r--
must(detail == "arrived, owner root, group root, mode 440, ACL user::r--, user:61500:r--, group::r--, mask::r--, other::---, source removed", detail)
accepted("dev02 shape from the real run", mode="440", uid="0", gid="0", unit_uid="61908", unit_gid="61908", acl=FULL.replace(U, "61908"))
must(sh.credential_mode_problem("440 0 0", "61908", "61908", "ACL user::r--,user:61908:r--,group::r--,mask::r--,other::---") == "", "READY: the real dev02 shape")
accepted("0400, owner is the unit, no ACL", mode="400", uid=U, gid=U, acl="ACL none")
accepted("0400, root:root, ACL names the unit", mode="400", uid="0", gid="0", acl=f"ACL user::r--,user:{U}:r--,group::---,mask::---,other::---")
accepted("0440, owner and group are the unit's, no ACL", mode="440", uid=U, gid=U, acl="ACL none")

# ---- refused
refused("ACL for another user", "not the unit's own", acl="ACL user::r--,user:61999:r--,group::r--,mask::r--,other::---")
refused("two named users", "not the unit's own", acl=f"ACL user::r--,user:{U}:r--,user:61999:r--,group::r--,mask::r--,other::---")
refused("a named group", "named group", acl=f"ACL user::r--,user:{U}:r--,group:{U}:r--,group::r--,mask::r--,other::---")
refused("a named group only", "named group", acl="ACL user::r--,group:61999:r--,group::r--,mask::r--,other::---")
refused("user entry with write", "not read only", acl=f"ACL user::r--,user:{U}:rw-,group::r--,mask::rw-,other::---")
refused("mask with write", "grants write", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask::rw-,other::---")
refused("group entry with write", "grants write", acl=f"ACL user::r--,user:{U}:r--,group::rw-,mask::r--,other::---")
refused("write in the mode (660)", "mode is 660", mode="660")
refused("write in the mode (640)", "mode is 640", mode="640")
refused("execute in the user entry", "not read only", acl=f"ACL user::r--,user:{U}:r-x,group::r--,mask::r--,other::---")
refused("execute in the mask", "grants execute", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask::r-x,other::---")
refused("execute in the owner entry", "grants execute", acl=f"ACL user::r-x,user:{U}:r--,group::r--,mask::r--,other::---")
refused("other bits in the mode (444)", "other users could read it", mode="444")
refused("other bits in the mode (404)", "other users could read it", mode="404")
refused("other::r-- in the ACL", "other users access", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask::r--,other::r--")
refused("no mask beside a named user", "no mask", acl=f"ACL user::r--,user:{U}:r--,group::r--,other::---")
refused("no other entry", "incomplete", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask::r--")
refused("no group entry", "incomplete", acl=f"ACL user::r--,user:{U}:r--,mask::r--,other::---")
# the 1.17.120 'any dynamic group' acceptance is gone: owner is the unit's uid or root, group 61999 is not the unit's own gid (65000 vs 61500)
refused("any dynamic gid, old rule", "not root or the unit's own", mode="440", uid=U, gid="61999", acl="ACL none")
refused("any dynamic gid, old rule, root owner", "not root or the unit's own", mode="440", uid="0", gid="61999", acl="ACL none")
refused("gid 65000 against a unit gid 61500", "not root or the unit's own", mode="440", uid=U, gid="65000", acl="ACL none")
refused("a foreign owner", "not root or the unit's own", uid="1000")
# the unit's own ids below the dynamic floor
refused("unit uid below the floor", "dynamic range", mode="440", uid="0", gid="0", unit_uid="1000", unit_gid="61500", acl="ACL none")
refused("unit gid below the floor", "dynamic range", mode="440", uid="0", gid="0", unit_uid="61500", unit_gid="999", acl="ACL none")
# a missing, garbled or truncated ACL answer
refused("no ACL line at all", "missing or garbled", acl=False)
refused("ACL error from the unit", "missing or garbled", acl="ACL error")
refused("garbled ACL text", "missing or garbled", acl="ACL banana")
refused("truncated ACL text", "missing or garbled", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask::r")
refused("empty ACL list", "missing or garbled", acl="ACL ")
refused("a mask with an id", "missing or garbled", acl=f"ACL user::r--,user:{U}:r--,group::r--,mask:5:r--,other::---")
refused("not an ACL line", "missing or garbled", acl="440")

# ---- the detail names owner, group, mode and every ACL entry on NO as well, and never the token or the path
detail = refused("NO detail", "found: owner 1000, group root, mode 440, ACL user::r--, user:61500:r--, group::r--, mask::r--, other::---", uid="1000")
must("owner" in detail and "group" in detail and "mode" in detail and "ACL" in detail, detail)
for status in (run(), run(uid="1000")):
    text = status["checks"]["credential"]["detail"]
    must("/run/" not in text and "credentials" not in text.lower().replace("the credential", "") and "probe" not in text, text)
    must(len(text) < 300, text)
no_token_fake = F.Fake()
status = F.run_selftest(sh, H.RUN, BASE, no_token_fake)
must(not [p for p in H.RUN.iterdir() if p.name.startswith(sh.SELFTEST_PREFIX)], "the probe folder is removed")

# the in-unit script calls the stdlib decoder, not getfacl, and the decoder text has no quote, percent or dollar that would break 'sh -c'
fake = F.Fake()
F.run_selftest(sh, H.RUN, BASE, fake)
script = next(call for call in fake.calls if call[0] == "credential")[2]
must(script[0] == "/bin/sh" and "python3 -I -c" in script[2] and "getfacl" not in script[2] and "id -g" in script[2], script)
body = sh._PROBE_ACL
must("'" not in body and "%" not in body and "$" not in body, "decoder text safe inside sh -c and a systemd command line")


# ---- the decoder program against hand-built bytes
PROGRAM = BASE / "probe-acl-program.py"
PROGRAM.write_text(sh._PROBE_ACL, encoding="utf-8")


def decode(data, errno_value=None):
    real = getattr(os, "getxattr", None)

    def fake_getxattr(path, name):
        must(name == "system.posix_acl_access", name)
        if errno_value:
            raise OSError(errno_value, "x")
        return data

    os.getxattr = fake_getxattr
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            sys.argv = ["-c", "credential-path"]
            try:
                runpy.run_path(str(PROGRAM), run_name="__main__")
            except SystemExit:
                pass
    finally:
        if real is None:
            del os.getxattr
        else:
            os.getxattr = real
    return out.getvalue().strip()


def entry(tag, perm, ident=0xFFFFFFFF):
    return struct.pack("<HHI", tag, perm, ident)


header = struct.pack("<I", 2)
good = header + entry(1, 4) + entry(2, 4, 61908) + entry(4, 4) + entry(0x10, 4) + entry(0x20, 0)
must(decode(good) == "ACL user::r--,user:61908:r--,group::r--,mask::r--,other::---", decode(good))
must(decode(header + entry(1, 6) + entry(4, 5) + entry(0x20, 1)) == "ACL user::rw-,group::r-x,other::--x", "rw- and r-x and --x")
must(decode(header + entry(1, 4) + entry(8, 4, 70000) + entry(4, 0) + entry(0x10, 4) + entry(0x20, 0)) == "ACL user::r--,group:70000:r--,group::---,mask::r--,other::---", "named group")
must(decode(b"", 61) == "ACL none" and decode(b"", 95) == "ACL none", "no ACL")
must(decode(b"", 13) == "ACL error", "permission denied is an error, not 'none'")
must(decode(struct.pack("<I", 1) + entry(1, 4) + entry(4, 4) + entry(0x20, 0)) == "ACL error", "wrong header version")
must(decode(good[:-3]) == "ACL error", "truncated bytes")
must(decode(header) == "ACL error" and decode(b"") == "ACL error", "header only and empty bytes")
must(decode(header + entry(3, 4) + entry(4, 4) + entry(0x20, 0)) == "ACL error", "unknown tag")
must(decode(header + entry(1, 9) + entry(4, 4) + entry(0x20, 0)) == "ACL error", "unknown permission bits")
# what the decoder prints goes straight through the parser and the rule
must(sh.credential_mode_problem("440 0 0", "61908", "61908", decode(good)) == "", "decoder output is accepted by the rule")
must(sh.parse_acl(decode(good))[1] == ("user", "61908", "r--"), "parse")

# ---- pure function checks
P = sh.credential_mode_problem
must(P("440 0 0", "61500", "61500", FULL) == "" and P("400 61500 61500", "61500", "61500", "ACL none") == "", "accepted")
must(P("440 0 0", "61500", "61500", "") != "" and P("440 0 0", "61500", "61500", "ACL none") == "", "an empty answer fails, 'ACL none' passes")
must(P("440 0 0", "61500", "61500", FULL.replace("user:61500", "user:61501")) != "", "other uid")
must(sh.credential_found_text("440 0 0", FULL) == "owner root, group root, mode 440, ACL user::r--, user:61500:r--, group::r--, mask::r--, other::---", "found text")
must(sh.credential_found_text("x", "") == "owner, group and mode unreadable, ACL answer missing or garbled", "found text, unreadable")
must(sh.DYNAMIC_GID_MIN == 61184, "the floor")

print("[TEST] PASS sandbox credential acl 1.17.122")
