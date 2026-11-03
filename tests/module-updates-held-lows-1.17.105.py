#!/usr/bin/env python3
"""1.17.105: the two Lows held from 1.17.104, plus the install.sh Low held from 1.17.103.

Reuses tests/module-updates-1.17.104.py (run whole, so its own checks pass first) for its stubs and the extracted _validate_release.

1. A release notes link with a query, a fragment or ;params is null (module_repository.py), as the contract and docs/module-updates.md say.
2. list_updates() gives every caller its own deep copy: a contract caller that changes its result never changes what the routes serve.
3. install.sh removes the .key-group temporary file when chown or chmod fails, and stays LF.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE / "module-updates-1.17.104.py"
HARNESS = types.ModuleType("harness")  # registered, so the harness's dataclass can find its own module
HARNESS.__file__ = str(BASE)
sys.modules["harness"] = HARNESS
NS: dict = HARNESS.__dict__
exec(compile(BASE.read_text(encoding="utf-8"), str(BASE), "exec"), NS)  # noqa: S102 - the shared test harness
must, mu, rns, catalog, module, reset, ROOT = (NS[k] for k in ("must", "mu", "rns", "catalog", "module", "reset", "ROOT"))

# --- 1. release notes link: null, not stripped
base = {"id": "alpha", "version": "1.0.1", "download": "alpha.zip", "sha256": "a" * 64}
for notes, expected in [
    ("https://docs.test/a.html?a=1", None), ("https://docs.test/a.html#x", None), ("https://docs.test/a.html;p", None),
    ("https://docs.test/a.html?", None), ("https://docs.test/a.html#", None), ("notes/a.html?a=1", None), ("notes/a.html;p", None),
    ("https://docs.test/notes/a.html", "https://docs.test/notes/a.html"), ("notes/a.html", "https://repo.test/idx/notes/a.html"),
]:
    got = rns["_validate_release"]({**base, "release_notes": notes}, "https://repo.test/idx/index.json")["release_notes_url"]
    must(got == expected, f"release notes {notes!r}: {got!r} != {expected!r}")
print("       1. a release notes link with a query, a fragment or ;params is null")

# --- 2. a deep copy for every caller
reset()
NS["CATALOG"]["value"] = catalog([module("alpha", "1.0.0", "1.0.1", notes="https://example.test/notes/alpha-1.0.1.html")])
first = mu.list_updates(fresh=True)
first["updates"][0]["release_notes_url"] = "https://evil.test/"
first["updates"].append({"id": "planted"})
first["count"] = 99
again = mu.list_updates()
must(again["count"] == 1 and len(again["updates"]) == 1, f"the cached list was changed: {again}")
must(again["updates"][0]["release_notes_url"] == "https://example.test/notes/alpha-1.0.1.html", "a cached row was changed")
NS["CALLER"]["value"] = NS["types"].SimpleNamespace(module_id="notifications", kind="module", module_version="1.0.0")
from_contract = mu.updates_for_module()
from_contract["updates"][0]["level"] = "changed"
from_contract["levels"]["patch"] = 42
served = mu.list_updates()
must(served["updates"][0]["level"] == "patch" and served["levels"]["patch"] == 1, f"a contract caller changed what the routes serve: {served}")
must(mu.update_count()["levels"]["patch"] == 1, "the badge changed")
print("       2. the routes and the contract each get their own deep copy of the cached list")

# --- 3. install.sh: no leftover .key-group temporary file
INSTALL = (ROOT / "install.sh").read_bytes()
must(b"\r" not in INSTALL, "install.sh has CR")
text = INSTALL.decode("utf-8")
start = text.index('SECRET_GROUP_TMP="$(mktemp')
block = text[start:text.index('log "Secret store key group: recorded', start)]
for command in ('chown root:"${TACTICAL_GROUP}" "${SECRET_GROUP_TMP}"', 'chmod 0640 "${SECRET_GROUP_TMP}"', 'mv -f -- "${SECRET_GROUP_TMP}"'):
    line = next(row for row in block.splitlines() if row.strip().startswith(command.split(" ", 1)[0]) and command in row)
    must('|| { rm -f "${SECRET_GROUP_TMP}"; fail ' in line, f"no clean-up on failure: {line.strip()}")
print("       3. install.sh removes the temporary key-group file when chown, chmod or mv fails; LF only")
print("[TEST] PASS module updates held lows 1.17.105")
