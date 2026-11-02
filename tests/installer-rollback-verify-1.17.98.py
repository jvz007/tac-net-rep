#!/usr/bin/env python3
"""1.17.98: install.sh passes each verification step's Python code to manage.py as a positional argument.

A rollback on tt01 failed in the contract-catalog check with NameError: name 'framework_version' is not defined. Cause:
run_verify_step built  bash -lc "... shell -c \\"${code}\\""  so every double quote inside a VERIFY_*_CODE string ended the
quoting. The failure message c["framework_version"] reached Python as c[framework_version]: a NameError hid the real
assertion ('framework version mismatch'), which only fires on the rollback path. The same flaw was the held Low from the
1.15.115-1 review ("escaped quotes in the new assert messages are stripped by the inner bash -lc").

Checked here: all 13 manage.py shell steps (12 fatal, the saved views repair as a warning) reach Python byte for byte; each string
compiles; the contract-catalog code, run against a stub catalog whose version differs, raises the real AssertionError with its full
text and no NameError; the helper's INSTALLER_VERIFY_STEPS equals the fatal labels in install.sh in order; and a rollback run (the
version asked for differs from the installed one) runs every step to the end under the real run_verify_step. Real bash is used when
the PC has it; otherwise only the static checks run. A real rollback needs a server and is not run here.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
HELPER = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


# (1) static ---------------------------------------------------------------------------------------------------------------------------
must(re.search(r"""bash -lc 'cd "\$1" && "\$2" "\$3" shell -c "\$4"' _ "\$\{BACKEND_DIR\}" "\$\{VENV_PYTHON\}" "\$\{MANAGE_PY\}" "\$\{code\}\"""", INSTALL),
     "the code must travel as the fourth positional argument")
must('shell -c \\"${code}\\"' not in INSTALL, "the old inline interpolation is gone")
must(len(re.findall(r"shell -c ", INSTALL)) == 1, "one manage.py shell command, inside run_verify_step")
steps = re.findall(r'run_verify_step "([^"]+)" "\$\{(VERIFY_\w+_CODE)\}"(?: (fatal|warn))?(?: "(\w+)")?', INSTALL, re.MULTILINE)
must(len(steps) == 13, steps)
code_lines = re.findall(r'^(VERIFY_\w+_CODE)="(.*)"$', INSTALL, re.MULTILINE)
must(sorted(n for n, _ in code_lines) == sorted(c for _, c, _, _ in steps), "every VERIFY_*_CODE has a step and the reverse")
fatal_labels = [label for label, _, mode, _ in steps if mode != "warn"]
helper_tree = ast.parse(HELPER)
helper_steps = next(ast.literal_eval(n.value) for n in helper_tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "INSTALLER_VERIFY_STEPS" for t in n.targets))
must(list(helper_steps) == fatal_labels and len(fatal_labels) == 12, (helper_steps, fatal_labels))
print("       install.sh: the code is argument $4; 13 steps; helper INSTALLER_VERIFY_STEPS equals the 12 fatal labels in order")

bash = shutil.which("bash")
if bash is None:
    print("[TEST] PASS installer rollback verify 1.17.98 (static checks only: no bash on this machine)")
    raise SystemExit(0)

# (2) the real run_verify_step under bash, with a python stub that writes the code it receives ------------------------------------------
start = INSTALL.index("VERIFY_STEP_TIMEOUT_SECONDS=120")
end = INSTALL.index('log "Verifying framework models and RBAC."')
function_text = INSTALL[start:end]
work = Path(tempfile.mkdtemp(prefix="installer-rollback-verify-"))
(work / "fn.sh").write_text(function_text, encoding="utf-8", newline="\n")
(work / "cap").mkdir()
(work / "intended").mkdir()
(work / "fakepy").write_text(
    '#!/bin/bash\n'
    '# manage.py shell -c <code>: $1=manage.py $2=shell $3=-c $4=<code>\n'
    '[ "$2" = shell ] && [ "$3" = -c ] || { echo "unexpected arguments: $*" >&2; exit 64; }\n'
    'n=$(ls cap | wc -l)\n'
    'printf %s "$4" > "cap/step-$(printf %02d $((n + 1)))"\n'
    'echo "TEC-TAC stub OK"\n', encoding="utf-8", newline="\n")
os.chmod(work / "fakepy", 0o755)
(work / "vars.sh").write_text("\n".join(f'{name}="{body}"' for name, body in code_lines) + "\n", encoding="utf-8", newline="\n")
calls = "\n".join(f'run_verify_step "{label}" "${{{var}}}"' + (f" {mode}" if mode else "") + (f' "{noun}"' if noun else "") for label, var, mode, noun in steps)
dump = "\n".join(f'printf %s "${{{var}}}" > "intended/{var}"' for _, var, _, _ in steps)
(work / "driver.sh").write_text(
    f"""set -uo pipefail
fail() {{ printf '[TEC-TAC] ERROR: %s\\n' "$*" >&2; exit 1; }}
log() {{ printf '[TEC-TAC] %s\\n' "$*"; }}
run_as_tactical() {{ "$@"; }}
BACKEND_DIR="$PWD"; VENV_PYTHON="$PWD/fakepy"; MANAGE_PY=manage.py
PACKAGE_VERSION="${{PACKAGE_VERSION:-1.17.98}}"
source ./vars.sh
{dump}
source ./fn.sh
VERIFY_STEP_TIMEOUT_SECONDS=60
{calls}
echo "ALL-STEPS-DONE"
""", encoding="utf-8", newline="\n")


def run(version="1.17.98"):
    for sub in ("cap", "intended"):
        for f in (work / sub).iterdir():
            f.unlink()
    env = dict(os.environ, CHERE_INVOKING="1", PACKAGE_VERSION=version)
    return subprocess.run([bash, "driver.sh"], cwd=work, env=env, capture_output=True, text=True, timeout=300, check=False)


done = run()
must(done.returncode == 0 and "ALL-STEPS-DONE" in done.stdout, (done.returncode, done.stdout[-800:], done.stderr[-800:]))
captured = sorted((work / "cap").iterdir())
must(len(captured) == 13, [p.name for p in captured])
for (label, var, _mode, _noun), path in zip(steps, captured):
    got = path.read_bytes()
    intended = (work / "intended" / var).read_bytes()
    must(got == intended, f"{label}: the code Python received differs from the intended code\n--- got\n{got[:300]!r}\n--- intended\n{intended[:300]!r}")
    must(len(got) > 20, label)
    compile(got.decode("utf-8"), label, "exec")  # the string is valid Python exactly as received
quoted = [label for (label, var, _m, _n), p in zip(steps, captured) if b'["' in p.read_bytes() or b'\\"' in p.read_bytes()]
must(any("contract" in label.lower() for label in quoted) and any("Resource Directory" in label for label in quoted), f"the steps with quoted keys are covered: {quoted}")
print(f"       all 13 steps reach Python byte for byte and compile; steps that use double quotes: {len(quoted)}")

# (3) the contract-catalog check reports the real assertion, not a NameError ----------------------------------------------------------------
contract = next(p for (label, _v, _m, _n), p in zip(steps, captured) if label == "Tec-Tac developer contract catalog")
code = contract.read_text(encoding="utf-8")
must("expected='1.17.98'" in code, code[:200])
catalog = {"framework_version": "1.17.97"}
stub_contracts = types.ModuleType("tec_tac.contracts")
stub_contracts.build_contract_catalog = lambda: catalog
stub_contracts.render_markdown = lambda c: "# Tec-Tac Public Contracts"
stub_contracts.render_text = lambda c: "TEC-TAC PUBLIC CONTRACTS"
stub_resources = types.ModuleType("tec_tac.resources")
stub_resources.CONTRACT_ID, stub_resources.CONTRACT_VERSION = "core.resources", "1.12.0"
saved = {k: sys.modules.get(k) for k in ("tec_tac", "tec_tac.contracts", "tec_tac.resources")}
sys.modules["tec_tac"] = types.ModuleType("tec_tac")
sys.modules["tec_tac"].__path__ = []
sys.modules["tec_tac.contracts"], sys.modules["tec_tac.resources"] = stub_contracts, stub_resources
try:
    try:
        exec(compile(code, "contract-step", "exec"), {})  # noqa: S102 - the check string from install.sh, run against stubs
        raise AssertionError("a version mismatch must fail the check")
    except NameError as exc:
        raise AssertionError(f"NameError hides the real assertion: {exc}") from exc
    except AssertionError as exc:
        must(str(exc) == "framework version mismatch: expected 1.17.98, got 1.17.97", str(exc))
    # the resource-directory messages (also quoted keys) read the same way
    catalog.update(framework_version="1.17.98")
    catalog.update(core=[{"name": "get_capability", "area": "x"}, {"name": "revoke_user_sessions", "area": "session-security"}, {"name": "record", "area": "audit"}, {"name": "list_clients", "area": "resources"}])
    catalog.update(resource_directory={"id": "wrong", "version": "1.12.0"}, capabilities=[], http=[], counts={})
    try:
        exec(compile(code, "contract-step", "exec"), {})  # noqa: S102
        raise AssertionError("a resource id mismatch must fail the check")
    except NameError as exc:
        raise AssertionError(f"NameError hides the resource assertion: {exc}") from exc
    except AssertionError as exc:
        must(str(exc) == "resource directory id mismatch: expected core.resources, got wrong", str(exc))
finally:
    for key, value in saved.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value
print("       contract-catalog code against a stub whose version differs: AssertionError 'framework version mismatch: expected 1.17.98, got 1.17.97', no NameError")

# (4) a rollback: the installer of the previous version asks for a version that is not the installed one --------------------------------------
rollback = run(version="1.17.96")
must(rollback.returncode == 0 and "ALL-STEPS-DONE" in rollback.stdout and "VERIFY STEP FAILED" not in rollback.stdout, (rollback.stdout[-600:], rollback.stderr[-600:]))
must(len(list((work / "cap").iterdir())) == 13, "every verification step ran on the rollback path")
position = [label for label, *_ in steps].index("Tec-Tac developer contract catalog") + 1
rolled = (work / "cap" / f"step-{position:02d}").read_text(encoding="utf-8")
must("expected='1.17.96'" in rolled and "NameError" not in rolled, "the previous version is asserted by name")
print("       rollback scenario (previous version fed to the harness): all 13 steps run to the end")

shutil.rmtree(work, ignore_errors=True)
print("[TEST] PASS installer rollback verify 1.17.98")
