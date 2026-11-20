#!/usr/bin/env python3
"""1.18.29 regression: ``tec-tac-sandbox --verify-module <module-id>`` (root only, not in sudoers) re-verifies one module's runners.

Uses the shared harness of tests/sandbox-harness-1.17.118.py (helper loaded as ``sh`` over a fake file layer; root helper and systemd cannot run here).

Covered: only the named module's rows are judged and rewritten; a verified row becomes unverified when the runtime tree no longer matches its
recorded listing and an unverified row becomes verified once it matches again; another module's rows are left byte for byte; a module with no
runners is a quiet no-op; bad ids are refused; one ``module.runners_verified`` audit row; a non-root caller is refused; the sweep still
judges every row as before; the sudoers text of install.sh still lists only --start, --stop and --status.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, make_runner, must, sh) = (H.BASE, H.make_runner, H.must, H.sh)

with contextlib.redirect_stdout(io.StringIO()):
    sh.ensure_layout()

TREE = BASE / "tree-good"
TREE.mkdir()
(TREE / "run.js").write_text("console.log(1)\n", encoding="utf-8")
LISTING = f"{hashlib.sha256((TREE / 'run.js').read_bytes()).hexdigest()}  run.js\n".encode()
LISTING_SHA = hashlib.sha256(LISTING).hexdigest()
for owner in ("ai", "other"):
    (sh.EXTENSIONS_ROOT / owner / "sandbox").mkdir(parents=True)
    (sh.EXTENSIONS_ROOT / owner / "sandbox" / "t.txt").write_bytes(LISTING)
BAD_TREE = BASE / "tree-bad"
BAD_TREE.mkdir()
(BAD_TREE / "run.js").write_text("changed\n", encoding="utf-8")
CURRENT = {"ai": TREE, "other": TREE}
real_verify = sh.verify_runtime


def verify(path, listing):
    owner = path.split("/")[4]
    return real_verify(str(CURRENT[owner]), listing)


sh.verify_runtime = verify


def root(owner):
    return {"path": f"/opt/tec-tac/runtimes/{owner}/rt", "tree_sha256_file": "sandbox/t.txt", "listing_sha256": LISTING_SHA}


def row_file(runner_id):
    return sh.REGISTRY_ROOT / f"{runner_id}.json"


def run_main(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = sh.main(list(args))
    return code, out.getvalue()


def audit():
    return [json.loads(line) for line in sh.AUDIT_FILE.read_text(encoding="utf-8").splitlines()] if sh.AUDIT_FILE.is_file() else []


make_runner("ai.one", roots=[root("ai")], verified=False)   # recorded unverified, the tree matches: becomes verified
make_runner("ai.two", roots=[root("ai")], verified=True)    # recorded verified, the tree matches: unchanged
make_runner("other.one", roots=[root("other")], verified=True)
CURRENT["other"] = BAD_TREE                                  # other's runtime is now wrong, but verify-module "ai" must not look
before_other = row_file("other.one").read_bytes()

code, out = run_main("--verify-module", "ai")
summary = json.loads(out)
must(code == 0 and summary == {"module": "ai", "checked": 2, "changed": ["ai.one"]}, (code, out))
must(json.loads(row_file("ai.one").read_text())["runtime_verified"] is True, "unverified row became verified")
must(json.loads(row_file("ai.one").read_text())["runtime_reason"] == "", "reason cleared")
must(json.loads(row_file("ai.two").read_text())["runtime_verified"] is True, "a matching verified row stays verified")
must(row_file("other.one").read_bytes() == before_other, "another module's row is byte for byte the same")
events = audit()
verified_rows = [r for r in events if "module.runners_verified" in json.dumps(r)]
must(len(verified_rows) == 1, events)
detail = verified_rows[0].get("detail", verified_rows[0])
must(detail["module"] == "ai" and detail["runners_checked"] == 2 and detail["runtime_state_changed"] == ["ai.one"], detail)

# a verified row becomes unverified when the tree changed
CURRENT["ai"] = BAD_TREE
code, out = run_main("--verify-module", "ai")
must(code == 0 and sorted(json.loads(out)["changed"]) == ["ai.one", "ai.two"], out)
got = json.loads(row_file("ai.two").read_text())
must(got["runtime_verified"] is False and got["runtime_reason"], got)
must(row_file("other.one").read_bytes() == before_other, "other still untouched")
# ... and verified again once it matches
CURRENT["ai"] = TREE
code, out = run_main("--verify-module", "ai")
must(json.loads(row_file("ai.two").read_text())["runtime_verified"] is True, "verified again")

# a module with no runners: quiet no-op, exit 0, summary, nothing rewritten
snapshot = {p.name: p.read_bytes() for p in sh.REGISTRY_ROOT.glob("*.json")}
code, out = run_main("--verify-module", "nobody")
must(code == 0 and json.loads(out) == {"module": "nobody", "checked": 0, "changed": []}, out)
must(snapshot == {p.name: p.read_bytes() for p in sh.REGISTRY_ROOT.glob("*.json")}, "no row rewritten")

# bad ids are refused before any row is read
for bad in ("../x", "", "a" * 101, "--x", "a/b", "a b", "a\x00b"):
    try:
        run_main("--verify-module", bad)
    except RuntimeError as exc:
        must("invalid" in str(exc), (bad, str(exc)))
    else:
        raise AssertionError(f"accepted {bad!r}")
# the verb needs its argument and takes no more
for argv in (["--verify-module"], ["--verify-module", "ai", "extra"]):
    try:
        run_main(*argv)
    except SystemExit as exc:
        must("usage" in str(exc) and "--verify-module" in str(exc), exc)
    else:
        raise AssertionError(argv)

# a non-root caller is refused
real_euid = sh.os.geteuid
sh.os.geteuid = lambda: 1000
try:
    run_main("--verify-module", "ai")
except SystemExit as exc:
    must("root" in str(exc), exc)
else:
    raise AssertionError("non-root accepted")
finally:
    sh.os.geteuid = real_euid

# the sweep still judges every row (no owner filter)
CURRENT["other"], CURRENT["ai"] = BAD_TREE, BAD_TREE
with contextlib.redirect_stdout(io.StringIO()) as buf:
    sh.sweep()
swept = json.loads(buf.getvalue())
must(swept["checked"] == 3 and sorted(swept["changed"]) == ["ai.one", "ai.two", "other.one"], swept)
must(json.loads(row_file("other.one").read_text())["runtime_verified"] is False, "sweep judged the other module's row too")

# sudoers text: only the three commands, no verify-module anywhere in install.sh's sudoers line
install = (ROOT / "install.sh").read_text(encoding="utf-8")
line = [x for x in install.splitlines() if "NOPASSWD: ${SANDBOX_HELPER}" in x]
must(len(line) == 1 and line[0].count("${SANDBOX_HELPER}") == 3, line)
must(all(flag in line[0] for flag in ("--start", "--stop", "--status")) and "verify-module" not in line[0], line)
must("verify-module" not in install, "install.sh never names the verb")

print("[TEST] PASS sandbox reverify 1.18.29")
shutil.rmtree(BASE, ignore_errors=True)
