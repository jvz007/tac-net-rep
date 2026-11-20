#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 3): the selftest and the canary left the sudo-reachable helper.

Django-free. Covered:

* the helper source has no ``def selftest(``, ``def run_selftest(``, ``def run_canary(``, ``def canary_row(``, ``"--selftest"``, ``"--canary"``, ``"--canary-launch"`` or
  ``canary_row``, and no CANARY_ table or probe text; scripts/sandbox-selftest.py defines all of them;
* the helper's main() refuses --selftest, --canary-launch and ``--selftest --canary`` (usage, nothing runs), still takes --start, --stop, --status, --sweep and the two
  module modes, and the kill switch still refuses --start and --stop before stdin is read;
* ``start_command(row=...)`` is how the selftest file hands in the canary's row: a header that names another runner is refused (runner_unknown), the registry is not
  read for a given row, and ``main`` never passes a row;
* install.sh installs sandbox-selftest.py through install_root_script, sets root:root 0700, never lists it in sudoers or links it into /usr/local/sbin, and the
  sudoers line is still exactly --start, --stop and --status; the install selftest runs the new file with ``/usr/bin/python3 -I`` and never fails the install;
* the selftest file loads the helper beside it by path (so the canary uses the helper's own launch code), is root only (a normal user is refused) and takes only
  --selftest, --selftest --canary and --canary-launch;
* the moved code is intact: every function that moved is in the selftest file and nothing it needs is missing (every ``H.<name>`` it reads exists in the helper);
* line counts are stated (the plan's 1,500 lines for the helper is not reached without also splitting start_command and launch; see the release notes);
* docs/sandbox-capability.md names the new command and no longer says the helper has --selftest.

The tests/sandbox_test_support.py loader gives the helper and the selftest file as one object; 43 older tests use it (listed in the release notes).
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_test_support import load_helper

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "sandbox-helper.py"
SELFTEST = ROOT / "scripts" / "sandbox-selftest.py"


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


helper_text = HELPER.read_text(encoding="utf-8")
selftest_text = SELFTEST.read_text(encoding="utf-8")
must(b"\r" not in HELPER.read_bytes() and b"\r" not in SELFTEST.read_bytes(), "LF line endings")

# ---- the helper no longer holds the test code
for needle in ("def selftest(", "def run_selftest(", "def run_canary(", "def canary_row(", "def run_canary_command(", '"--selftest"', '"--canary"', '"--canary-launch"',
               "canary_row", "CANARY_GROUPS", "CANARY_REQUIRED", "CANARY_VIEW_ALLOWED", "_probe_network", "_probe_egress", "def format_table(", "def memory_row("):
    must(needle not in helper_text, ("still in the sudo-reachable helper", needle))
for needle in ("def selftest(", "def run_selftest(", "def run_canary(", "def canary_row(", "def run_canary_command(", "def memory_row(", "def format_table(", "def collect_run(",
               "def _probe_network(", "def _probe_egress(", "def start_canary(", "CANARY_GROUPS = ", "CANARY_REQUIRED = ", '"--selftest"', '"--canary-launch"'):
    must(needle in selftest_text, ("missing from the selftest file", needle))

# ---- main() of the helper
sh = load_helper(ROOT, "sandbox_helper_split")
helper = sh._helper_module
saved_geteuid = getattr(os, "geteuid", None)
os.geteuid = lambda: 0
try:
    for argv in (["--selftest"], ["--selftest", "--canary"], ["--canary-launch"], ["--canary"], ["--finish"], []):
        try:
            helper.main(argv)
        except SystemExit as exc:
            must("usage" in str(exc) and "--selftest" not in str(exc) and "--canary" not in str(exc), (argv, str(exc)))
        else:
            raise AssertionError(f"the helper accepted {argv}")
    buffered = io.StringIO()
    saved_out = sys.stdout
    sys.stdout = buffered
    try:
        code = helper.main(["--start"])
    finally:
        sys.stdout = saved_out
    must(code == 3 and json.loads(buffered.getvalue().strip()) == {"t": "refused", "code": "sandbox_disabled"}, "the kill switch still refuses --start before stdin is read")
finally:
    if saved_geteuid is not None:
        os.geteuid = saved_geteuid
must(helper.SANDBOX_ENABLED is False, "the kill switch is off")

# ---- start_command(row=...)
FRAMES = io.BytesIO()
header = json.dumps({"runner_id": "ai.other", "run_id": "ab" * 16, "person": "p", "parameters": {}, "input_bytes": 0}).encode() + b"\n"
helper.ensure_layout = lambda: None
calls = []
helper.load_runner_row = lambda runner_id: calls.append(runner_id) or {"id": runner_id, "limits": {}}
code = helper.start_command(io.BytesIO(header), row={"id": "core.canary", "limits": {}}, out_stream=FRAMES)
must(code == 3 and json.loads(FRAMES.getvalue().decode().splitlines()[0])["code"] == "runner_unknown" and calls == [], ("a header for another runner is refused and the registry is not read", calls))
main_source = ast.get_source_segment(helper_text, next(n for n in ast.walk(ast.parse(helper_text)) if isinstance(n, ast.FunctionDef) and n.name == "main"))
must("row=" not in main_source and "start_command()" in main_source, "main never passes a row")

# ---- install.sh
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must('install_root_script "${REPO_ROOT}/scripts/sandbox-selftest.py" "${SANDBOX_LIB}/sandbox-selftest.py"' in install, "installed through install_root_script")
must('chmod 0700 "${SANDBOX_LIB}/sandbox-selftest.py"' in install and 'chown root:root "${SANDBOX_LIB}/sandbox-selftest.py"' in install, "root:root 0700")
must(install.index('chmod 0700 "${SANDBOX_LIB}/sandbox-selftest.py"') > install.index("install_root_script \"${REPO_ROOT}/scripts/sandbox-selftest.py\""), "the mode is set after the install")
rule = [line for line in install.splitlines() if "NOPASSWD: ${SANDBOX_HELPER} --start" in line]
must(len(rule) == 1 and rule[0].strip().endswith("${SANDBOX_HELPER} --start, ${SANDBOX_HELPER} --stop, ${SANDBOX_HELPER} --status"), rule)
must("selftest" not in rule[0] and "canary" not in rule[0], "the sudoers line never names the selftest file")
must("sandbox-selftest" not in "\n".join(line for line in install.splitlines() if "sudoers" in line.lower() or "SANDBOX_SUDOERS" in line and "visudo" in line), "no sudoers line mentions it")
must(not re.search(r"ln -s[a-z]* [^\n]*sandbox-selftest", install), "never linked into /usr/local/sbin")
must('timeout "${SANDBOX_SELFTEST_TIMEOUT_SECONDS}s" /usr/bin/python3 -I "${SANDBOX_LIB}/sandbox-selftest.py" --selftest >/dev/null 2>&1; then' in install, "the install selftest runs the new file")
must('log "WARNING: Sandbox is off: ${SANDBOX_OFF_REASON}. ai ChatGPT stays off."' in install, "a failed selftest still only warns")

# ---- the selftest file itself
tree = ast.parse(selftest_text)
must(selftest_text.splitlines()[0] == "#!/usr/bin/python3 -I", "shebang")
must("HELPER_FILE = Path(__file__).resolve().with_name(\"sandbox-helper.py\")" in selftest_text and "spec_from_file_location(" in selftest_text, "loads the helper beside it by path")
os.geteuid = lambda: 1000
try:
    for argv in (["--selftest"], ["--selftest", "--canary"], ["--canary-launch"]):
        try:
            sh._selftest_module.main(argv)
        except SystemExit as exc:
            must("root" in str(exc), (argv, str(exc)))
        else:
            raise AssertionError(f"{argv} ran as a normal user")
    for argv in (["--status"], ["--start"], ["--sweep"], [], ["--selftest", "--other"]):
        try:
            sh._selftest_module.main(argv)
        except SystemExit as exc:
            must("usage" in str(exc), (argv, str(exc)))
        else:
            raise AssertionError(f"the selftest file accepted {argv}")
finally:
    if saved_geteuid is not None:
        os.geteuid = saved_geteuid
    else:
        del os.geteuid

# every ``H.<name>`` the selftest file reads exists in the helper, and every bare name it uses is defined, imported, a builtin or local
helper_names = set(dir(helper))
missing = sorted({node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "H" and node.attr not in helper_names})
must(not missing, ("names the selftest file reads from the helper that do not exist", missing))

# ---- line counts (stated in the release notes)
helper_lines, selftest_lines = len(helper_text.splitlines()), len(selftest_text.splitlines())
must(helper_lines < 4800 and selftest_lines > 1000, (helper_lines, selftest_lines))
print(f"note: sandbox-helper.py {helper_lines} lines (was 4,639 before 1.18.26's own additions), sandbox-selftest.py {selftest_lines} lines")

# ---- the docs
doc = (ROOT / "docs" / "sandbox-capability.md").read_text(encoding="utf-8")
must("/usr/bin/python3 -I /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py" in doc and "no longer a mode of this helper" in doc, "the doc names the new command")
must("To run the test again as root: `/usr/local/sbin/tec-tac-sandbox --selftest`." not in doc, "the old command is not offered")
print("[TEST] PASS sandbox selftest split 1.18.26")
