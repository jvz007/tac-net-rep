#!/usr/bin/env python3
"""1.17.6 regression: the runtime-settings PATCH 403 text states the real rule (doc fix from the UI 0.12.86 review).

Parses contracts.py with ast, as the contract section of tests/update-source-1.17.5.py does. Documentation only.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
APP = Path(__file__).resolve().parents[1] / "framwork" / "tec_tac"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))

rt = details["/api/tfd/system/runtime-settings/"]["PATCH"]
text = rt["errors"]["403"]
must("core.runtime_settings.manage" in text and "core.privileged_operations" in text, text)
must("update source" not in text.lower() and "may change the update source" not in text, text)
must("Checked before the body" in text and "never sees 400" in text, text)
must("core.runtime_settings.manage" in rt["authorization"] and "core.privileged_operations" in rt["authorization"], rt["authorization"])

us = details["/api/tfd/system/update-source/"]["PATCH"]["errors"]["403"]
must(us == "caller is not an effective superuser: 'Only a Tec-Tac superuser may change the update source.' Checked before the body, so a non-superuser never sees 400", us)

# generic guard 1: a long (specific, not boilerplate) 403 string is never reused by two rows whose authorization differ
# generic guard 2: a permission codename named in a 403 string also appears in that row's authorization line
import re

CODENAME = re.compile(r"\b(?:core|licensing|agents|reportmanager)\.[a-z_]+(?:\.[a-z_]+)*\b")
seen = {}
for path, methods in details.items():
    for method, row in methods.items():
        if not isinstance(row, dict) or not isinstance(row.get("errors"), dict):
            continue
        err = row["errors"].get("403")
        auth = row.get("authorization")
        if not isinstance(err, str) or not isinstance(auth, str):
            continue
        for name in CODENAME.findall(err):
            must(name in auth, f"{method} {path}: the 403 text names {name} but the authorization line does not")
        if len(err) >= 80:
            if err in seen:
                other_auth, other = seen[err]
                must(other_auth == auth, f"{method} {path} and {other} share a 403 text but differ in authorization: {err!r}")
            else:
                seen[err] = (auth, f"{method} {path}")
print("runtime settings contract 1.17.6: ok")
