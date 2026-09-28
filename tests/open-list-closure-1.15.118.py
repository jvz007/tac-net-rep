#!/usr/bin/env python3
"""Closure guards for L06/L07 in Core 1.15.118."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
module_views = (ROOT / "framwork/tec_tac/module_v2_views.py").read_text(encoding="utf-8")
session_views = (ROOT / "framwork/tec_tac/session_security_views.py").read_text(encoding="utf-8")

# L06: no-parameter compatibility requests retain the historical bounded
# 200-row response instead of silently shrinking to the paginated default 50.
assert 'limit = int(request.query_params.get("limit") or 200)' in module_views
assert 'rows = list_jobs(limit=limit)' in module_views
assert 'limit = int(request.query_params.get("limit") or 200)' in session_views
assert 'rows = list_audit_events(username=username, event_type=event_type, limit=limit)' in session_views

# L07: privileged helpers must resolve a trusted root-owned bash from either
# conventional location. Do not hard-code /usr/bin/bash as the only executable.
helpers = [
    "module-job-helper.py",
    "module-v2-job-helper.py",
    "module-hotfix-job-helper.py",
    "system-update-helper.py",
    "server-backup-helper.py",
]
for name in helpers:
    text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    assert 'for raw in ("/bin/bash", "/usr/bin/bash")' in text, f"{name}: trusted bash resolver missing"
    assert "def _resolve_trusted_bash" in text, f"{name}: trusted bash resolver missing"
    assert "TRUSTED_BASH = _resolve_trusted_bash()" in text, f"{name}: trusted bash must be resolved once"
    # Reject direct subprocess command construction that pins only /usr/bin/bash.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not re.search(r"(?:\[|\()\s*[\"']/usr/bin/bash[\"']\s*,", stripped), f"{name}: hard-coded /usr/bin/bash command: {stripped}"

print("open-list closure 1.15.118: OK")
