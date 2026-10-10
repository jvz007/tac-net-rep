#!/usr/bin/env python3
"""1.17.15 regression: a module job whose dispatch fails because the root helper has Windows line endings says so in plain
words, instead of the bare sudo error (Johan, dev server, 10 October 2026). Django-free.

The root helper is installed with a CRLF first line; sudo then reports "unable to execute ...: No such file or directory".
``module_manager._dispatch`` must detect that symptom and name the fault. Any other dispatch error keeps its own text.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import module_manager as mm  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="tt-dispatch-"))
CR = bytes([13])
LF = bytes([10])
SUDO_ERROR = "sudo: unable to execute /usr/local/sbin/tec-tac-module-job: No such file or directory"
WINDOWS_TEXT = "Unable to dispatch privileged module job: helper has Windows line endings - reinstall it from this version."

crlf_helper = TMP / "tec-tac-module-job-crlf"
crlf_helper.write_bytes(b"#!/usr/bin/python3" + CR + LF + b'"""Root helper."""' + CR + LF)
lf_helper = TMP / "tec-tac-module-job-lf"
lf_helper.write_bytes(b"#!/usr/bin/python3" + LF + b'"""Root helper."""' + LF)

must(mm._helper_has_crlf(crlf_helper) is True, "a CRLF first line is detected")
must(mm._helper_has_crlf(lf_helper) is False, "an LF first line is not")
must(mm._helper_has_crlf(TMP / "missing") is False, "a missing helper is not reported as CRLF")

real_run = subprocess.run


def sudo_fails(stderr):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr=stderr)
    return fake_run


def dispatch_error(helper, stderr):
    mm.HELPER = helper
    subprocess.run = sudo_fails(stderr)
    try:
        mm._dispatch("00000000-0000-4000-8000-000000000001")
    except mm.ModuleManagerError as exc:
        return str(exc)
    finally:
        subprocess.run = real_run
    raise AssertionError("the dispatch must fail")


# the Windows line-ending symptom is named in plain words, and the bare sudo text is gone
message = dispatch_error(crlf_helper, SUDO_ERROR + "\n")
must(message == WINDOWS_TEXT, message)
must("unable to execute" not in message and message.isascii(), message)

# a helper with LF endings keeps the sudo text, so a real fault is not hidden
message = dispatch_error(lf_helper, SUDO_ERROR + "\n")
must(message == "Unable to dispatch privileged module job: " + SUDO_ERROR, message)

# another dispatch error on a CRLF helper keeps its own text
message = dispatch_error(crlf_helper, "sudo: a password is required\n")
must(message == "Unable to dispatch privileged module job: sudo: a password is required", message)

print("[TEST] PASS module job dispatch CRLF 1.17.15")
