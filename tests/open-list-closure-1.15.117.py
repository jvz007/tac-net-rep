#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
install = (ROOT / "install.sh").read_text(encoding="utf-8")
recovery = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "scripts/recovery").glob("*.sh"))
views = (ROOT / "framwork/tec_tac/views.py").read_text(encoding="utf-8")
session_views = (ROOT / "framwork/tec_tac/session_security_views.py").read_text(encoding="utf-8")
docs = (ROOT / "docs/session-security.md").read_text(encoding="utf-8")

# L02: uninstall may use the audited safe loader, but must never source the config file as shell code.
assert 'source "${TEC_TAC_CONFIG_FILE}"' not in uninstall
assert '. "${TEC_TAC_CONFIG_FILE}"' not in uninstall
assert 'source "${CONFIG_LOADER}"' in uninstall

# L03: privileged installer/recovery Python calls use the fixed system interpreter, never PATH lookup.
for label, text in (("install.sh", install), ("scripts/recovery", recovery)):
    for line in text.splitlines():
        stripped = line.strip()
        if "python3" in stripped and not stripped.startswith("#"):
            assert "/usr/bin/python3" in stripped, f"{label} still has PATH python3: {stripped}"

# L50: document the admin MFA recovery endpoint and both supported verbs.
assert '/api/tfd/access/users/<user_id>/mfa/' in docs
assert 'GET    /api/tfd/access/users/<user_id>/mfa/' in docs
assert 'DELETE /api/tfd/access/users/<user_id>/mfa/' in docs

# L51: views.py no longer carries the obsolete timedelta import.
assert 'timedelta' not in views.split('from urllib.parse', 1)[0]

# L54: pagination parse errors are stable API messages, not raw int() exception strings.
assert session_views.count('"Invalid pagination parameters."') >= 2
assert 'invalid literal for int()' not in session_views

print("open-list closure 1.15.117: OK")
