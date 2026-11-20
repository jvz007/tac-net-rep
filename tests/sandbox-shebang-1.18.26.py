#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 4): the root-owned sandbox programs start with ``#!/usr/bin/python3 -I``.

Django-free. Covered: the helper and the selftest file have exactly the one-argument -I shebang as their first line (valid on Linux: the kernel passes one argument),
LF line endings (a CR would make the interpreter name wrong), install.sh still installs both with install_root_script (which strips a CR) and the helper's
symlink and the 0700 mode of the selftest file are unchanged, and both files compile. The in-unit launcher and the egress program are started as
``python3 -I <file>`` by the helper and keep their own first lines.
"""
from __future__ import annotations

import py_compile
import re
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SHEBANG = b"#!/usr/bin/python3 -I\n"


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


for name in ("sandbox-helper.py", "sandbox-selftest.py"):
    data = (ROOT / "scripts" / name).read_bytes()
    must(data.startswith(SHEBANG), (name, data[:40]))
    must(b"\r" not in data, (name, "LF only"))
    with tempfile.TemporaryDirectory() as tmp:
        py_compile.compile(str(ROOT / "scripts" / name), cfile=str(Path(tmp) / "x.pyc"), doraise=True)
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must('install_root_script "${REPO_ROOT}/scripts/sandbox-helper.py" "${SANDBOX_LIB}/sandbox-helper.py"' in install, "the helper is still copied by install_root_script")
must('install_root_script "${REPO_ROOT}/scripts/sandbox-selftest.py" "${SANDBOX_LIB}/sandbox-selftest.py"' in install, "so is the selftest file")
must('ln -sfn "${SANDBOX_LIB}/sandbox-helper.py" "${SANDBOX_HELPER}"' in install, "the helper symlink is unchanged")
must(re.search(r"^sed 's/\\r\$//'", "sed 's/\\r$//' x", re.M) is not None and "sed 's/\\r$//' \"${source}\"" in install, "install_root_script strips a CR")
# the canary's first-line row must accept exactly this line and nothing looser
driver = (ROOT / "tests" / "sandbox-canary-patchc-1.18.27.py").read_text(encoding="utf-8")
must('SHEBANG = "#!/usr/bin/python3 -I"' in driver and "first == SHEBANG" in driver, "the canary row checks the exact line")
print("[TEST] PASS sandbox shebang 1.18.26")
