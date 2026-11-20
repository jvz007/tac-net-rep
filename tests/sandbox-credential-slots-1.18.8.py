#!/usr/bin/env python3
"""1.18.8 regression: credential slots (core.sandbox Patch A, part 2).

The unit's LoadCredential files carry the fixed names cred0 and cred1. The launcher maps each declared name (a ``--credential=<name>`` argument,
strict rule) to its slot with a symlink under ``/work/credentials`` and gives the runner ``CREDENTIALS_DIRECTORY=/work/credentials``, so a runner
still reads ``$CREDENTIALS_DIRECTORY/<declared name>``.

* ``link_credentials`` with a fake CREDENTIALS_DIRECTORY: links (a copy where this system has no symlink privilege), a name that fails the rule
  is skipped but keeps its slot number, a third name and a missing slot file are skipped, nothing holds a secret except the slot files;
* the launcher run as a program: the child's CREDENTIALS_DIRECTORY is the new folder, the declared name opens the token, a launcher with no
  names leaves the environment alone, slots that could not be linked leave the child with no CREDENTIALS_DIRECTORY at all, the header line and the
  credential_return frame are as before;
* end to end through ``--start`` with the fake systemd: the runner reads ``$CREDENTIALS_DIRECTORY/auth``, the secrets folder holds cred0 and is
  removed at the end of the run.

Not runnable here: systemd's LoadCredential itself (dev02: the credential rows of tests/sandbox-canary-1.18.8.sh).
"""
from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load("sandbox_launcher_188", HERE.parent / "scripts" / "sandbox-launcher.py")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


TMP = Path(tempfile.mkdtemp(prefix="tectac-slots-"))
HAS_SYMLINK = True
try:
    os.symlink(str(TMP), str(TMP / "probe-link"))
except (OSError, NotImplementedError, AttributeError):
    HAS_SYMLINK = False
    print("[NOTE] this system cannot make a symlink without a privilege: the launcher copies the slot file instead (a server always links)")


def fresh(name):
    folder = TMP / name
    (folder / "source").mkdir(parents=True)
    (folder / "work").mkdir()
    return folder / "source", folder / "work"


# ---- link_credentials
source, work = fresh("one")
(source / "cred0").write_text("token-zero", encoding="utf-8")
(source / "cred1").write_text("token-one", encoding="utf-8")
folder = launcher.link_credentials(["auth", "extra"], str(source), str(work))
must(folder == str(work / "credentials") and (work / "credentials").is_dir(), folder)
must((work / "credentials" / "auth").read_text(encoding="utf-8") == "token-zero" and (work / "credentials" / "extra").read_text(encoding="utf-8") == "token-one", "each name opens its slot")
if HAS_SYMLINK:
    must(os.path.islink(work / "credentials" / "auth") and os.readlink(work / "credentials" / "auth") == str(source / "cred0"), "a symlink to the slot, holding no secret itself")
if os.name == "posix":
    must(oct((work / "credentials").stat().st_mode & 0o777) == "0o700", "the folder is 0700")

source, work = fresh("skip")
(source / "cred0").write_text("a", encoding="utf-8")
(source / "cred1").write_text("b", encoding="utf-8")
(source / "cred2").write_text("c", encoding="utf-8")
folder = launcher.link_credentials(["Bad Name", "good.name", "third"], str(source), str(work))
must(sorted(p.name for p in (work / "credentials").iterdir()) == ["good.name"], "a bad name is skipped, a third slot does not exist")
must((work / "credentials" / "good.name").read_text(encoding="utf-8") == "b", "the second name keeps slot 1 even though the first was skipped")
for hostile in ("../escape", "a/b", "A", "", "x" * 65, ".hidden", "a b", "a;b", "a\nb"):
    source, work = fresh("h" + str(abs(hash(hostile))))
    (source / "cred0").write_text("x", encoding="utf-8")
    result = launcher.link_credentials([hostile], str(source), str(work))
    must(result is None and not list((work / "credentials").iterdir()), f"{hostile!r} was linked")
source, work = fresh("missing")
(source / "cred1").write_text("only-slot-one", encoding="utf-8")
folder = launcher.link_credentials(["auth", "extra"], str(source), str(work))
must(sorted(p.name for p in (work / "credentials").iterdir()) == ["extra"] and folder is not None, "a missing slot file is skipped")
must(launcher.link_credentials([], str(source), str(work)) is None and launcher.link_credentials(["auth"], None, str(work)) is None, "nothing to do")
must(launcher.CREDENTIAL_NAME_RE.pattern == r"^[a-z0-9][a-z0-9._-]{0,63}$" and launcher.CREDENTIAL_SLOTS_MAX == 2, "the same rule as the helper")
helper_text = "\n".join((HERE.parent / "scripts" / name).read_text(encoding="utf-8") for name in ("sandbox-helper.py", "sandbox-selftest.py"))
must('CREDENTIAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")' in helper_text and "CREDENTIAL_FILES_MAX = 2" in helper_text, "the helper uses the same rule and ceiling")


# ---- the launcher as a program
sys.path.insert(0, str(HERE))
from sandbox_test_support import launcher_for_tests  # noqa: E402

launcher_file = launcher_for_tests(HERE.parent, tempfile.mkdtemp(prefix="tectac-slots-launcher-"))  # 1.18.26: a PC without /proc runs a copy that skips the leftover check


def run_launcher(args, env_extra, child_code):
    env = {k: v for k, v in os.environ.items() if k not in ("CREDENTIALS_DIRECTORY",)}
    env.update(env_extra)
    command = [sys.executable, str(launcher_file), *args, "--", sys.executable, "-c", child_code]
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=60, check=False)


CHILD = ("import os;d=os.environ.get('CREDENTIALS_DIRECTORY');print('DIR=' + str(d));"
         "print('TOKEN=' + (open(os.path.join(d,'auth')).read() if d and os.path.exists(os.path.join(d,'auth')) else 'none'))")
source, work = fresh("prog")
(source / "cred0").write_text("secret-token", encoding="utf-8")
done = run_launcher(["--credential=auth"], {"CREDENTIALS_DIRECTORY": str(source), "SANDBOX_WORK": str(work)}, CHILD)
lines = done.stdout.splitlines()
must(done.returncode == 0 and lines[0].startswith("TECTAC-SBX-LAUNCHER ") and lines[1] == f"DIR={work / 'credentials'}" and lines[2] == "TOKEN=secret-token", (done.returncode, done.stdout, done.stderr))
must(str(source) not in done.stdout, "the runner never sees the slot folder")
_s_ret, w_ret = fresh("ret")
done = run_launcher(["--credential=auth", "--return-credential"], {"CREDENTIALS_DIRECTORY": str(source), "SANDBOX_WORK": str(w_ret), "SANDBOX_OUT": str(w_ret / "out")},
                    CHILD + ";open(os.path.join(os.environ['SANDBOX_OUT'],'credential'),'w').write('refreshed')")
must("TOKEN=secret-token" in done.stdout and " CRED " in done.stdout, done.stdout)
frame = next(line for line in done.stdout.splitlines() if " CRED " in line)
must(base64.b64decode(frame.split(" CRED ")[1]) == b"refreshed", "the credential return frame is as before")
# the options may come in any order before --
_s_order, w_order = fresh("order")
done = run_launcher(["--return-credential", "--credential=auth"], {"CREDENTIALS_DIRECTORY": str(source), "SANDBOX_WORK": str(w_order)}, CHILD)
must("TOKEN=secret-token" in done.stdout, done.stdout)
# no names: the environment is left alone (here: there is none)
done = run_launcher([], {"SANDBOX_WORK": str(work)}, CHILD)
must("DIR=None" in done.stdout and done.returncode == 0, done.stdout)
done = run_launcher([], {"CREDENTIALS_DIRECTORY": "/somewhere", "SANDBOX_WORK": str(work)}, CHILD)
must("DIR=/somewhere" in done.stdout, "no names declared: the launcher does not rewrite the variable")
# names declared but nothing linkable: the runner finds no file and never the raw slot folder
source2, work2 = fresh("none")
done = run_launcher(["--credential=auth"], {"CREDENTIALS_DIRECTORY": str(source2), "SANDBOX_WORK": str(work2)}, CHILD)
must("DIR=None" in done.stdout and "TOKEN=none" in done.stdout and str(source2) not in done.stdout, done.stdout)
_s_bad, w_bad = fresh("bad")
done = run_launcher(["--credential=Bad"], {"CREDENTIALS_DIRECTORY": str(source), "SANDBOX_WORK": str(w_bad)}, CHILD)
must("DIR=None" in done.stdout, done.stdout)
done = run_launcher(["--credential=auth"], {"CREDENTIALS_DIRECTORY": str(source)}, "print(1)")
done = subprocess.run([sys.executable, str(HERE.parent / "scripts" / "sandbox-launcher.py"), "--credential=auth"], capture_output=True, text=True, timeout=30, check=False)
must(done.returncode == 64 and "usage" in done.stderr, "no -- is a usage error")

# ---- end to end through --start with the fake systemd
H = load("sandbox_harness_188c", HERE / "sandbox-harness-1.17.118.py")
sh = H.sh
H.write_ready_status()
TOKEN = "tok-" + os.urandom(6).hex()
seen = {}


def body_for(note):
    return ("d = os.environ['CREDENTIALS_DIRECTORY']\n"
            "print('DIRNAME=' + os.path.basename(d))\n"
            "print('NAMES=' + ','.join(sorted(os.listdir(d))))\n"
            "print('TOKEN=' + open(os.path.join(d, 'auth')).read())\n"
            "open(os.path.join(os.environ['SANDBOX_OUT'], 'credential'), 'w').write('refreshed-' + open(os.path.join(d, 'auth')).read())\n")


H.make_runner("ai.slots", body=body_for("x"), credential_files=["auth"], credential_return=True)
code, frames = H.start(H.header("ai.slots", credentials={"auth": TOKEN}))
end = H.end_of(frames)
out = H.joined(frames, "out").decode("utf-8")
must(code == 0 and end["reason"] == "exited" and end["exit"] == 0, (code, frames))
must("DIRNAME=credentials" in out and "NAMES=auth" in out and f"TOKEN={TOKEN}" in out, out)
must(base64.b64decode(end["credential_b64"]).decode() == "refreshed-" + TOKEN, "credential_return still works through the slot")
log = H.unit_log(frames[0]["run_id"])
creds = [p for p in log["props"] if p.startswith("LoadCredential=")]
must(len(creds) == 1 and creds[0].startswith("LoadCredential=cred0:") and "auth" not in creds[0].replace(str(sh.SECRETS_ROOT), ""), creds)
must("--credential=auth" in log["command"] and not any("auth" in p for p in log["props"] if not p.startswith("LoadCredential=cred0:")), "the declared name is a launcher argument only")
must(not H.leftovers(), H.leftovers())
# two credentials, declared in the other order
H.make_runner("ai.two", body="d = os.environ['CREDENTIALS_DIRECTORY']\nprint('B=' + open(os.path.join(d, 'beta')).read() + ' A=' + open(os.path.join(d, 'alpha')).read())",
              credential_files=["beta", "alpha"])
code, frames = H.start(H.header("ai.two", credentials={"beta": "bb", "alpha": "aa"}))
must("B=bb A=aa" in H.joined(frames, "out").decode("utf-8"), H.joined(frames, "out"))
must(not H.leftovers(), H.leftovers())
# a stale secrets folder is cleaned like before
rid = os.urandom(16).hex()
sh.write_secrets(rid, {"auth": b"x"})
must((sh.SECRETS_ROOT / rid / "cred0").is_file() and not (sh.SECRETS_ROOT / rid / "auth").exists(), "the secrets folder holds the slot file")
sh.remove_secrets(rid)
must(not (sh.SECRETS_ROOT / rid).exists(), "removed")

print("[TEST] PASS sandbox credential slots 1.18.8")
