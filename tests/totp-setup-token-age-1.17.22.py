#!/usr/bin/env python3
"""Core 1.17.22: the TOTP setup token is judged by its age, not by expiry minus created.

Django and Knox are not installed on the development PC, so the function is extracted with ast and run against stub request objects.
"""
import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "framwork/tec_tac/views.py").read_text()
tree = ast.parse(source)
func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_is_short_lived_knox_setup_token")
ns = {"datetime": datetime, "timezone": timezone}
exec(compile(ast.Module(body=[func], type_ignores=[]), "views.py", "exec"), ns)
check = ns["_is_short_lived_knox_setup_token"]


def old_rule(request):
    auth = request.auth
    seconds = (auth.expiry - auth.created).total_seconds()
    return 0 < seconds <= 5 * 60


def req(created_ago=60, expiry_in=180, totp_key=None, sso=False, digest="d" * 8, naive=False, no_created=False):
    now = datetime.now(timezone.utc)
    created = now - timedelta(seconds=created_ago)
    expiry = now + timedelta(seconds=expiry_in)
    if naive:
        created = created.replace(tzinfo=None)
    auth = SimpleNamespace(digest=digest, created=None if no_created else created, expiry=expiry)
    return SimpleNamespace(auth=auth, user=SimpleNamespace(totp_key=totp_key, is_sso_user=sso))


# A fresh token with a 3 minute life passes.
assert check(req(created_ago=10, expiry_in=170))
# The same token after Knox auto refresh (expiry now + 5 h, created 2 min ago) passes; the old rule failed it.
refreshed = req(created_ago=120, expiry_in=5 * 3600)
assert check(refreshed)
assert not old_rule(refreshed), "the old rule must show the bug"
# Created 10 minutes ago with a 5 h expiry fails.
assert not check(req(created_ago=600, expiry_in=5 * 3600))
# A normal login token created a minute ago for a user who has a totp_key fails.
assert not check(req(created_ago=60, expiry_in=5 * 3600, totp_key="ABCDEF"))
assert not check(req(totp_key="ABCDEF"))
# SSO user fails.
assert not check(req(sso=True))
# No digest, no created, naive created, future created, expired token all fail.
assert not check(req(digest=""))
assert not check(req(no_created=True))
assert not check(req(naive=True))
assert not check(req(created_ago=-600))
assert check(req(created_ago=-10))  # small skew allowed
assert not check(req(created_ago=60, expiry_in=-5))
assert not check(SimpleNamespace(auth=None, user=SimpleNamespace(totp_key=None, is_sso_user=False)))

# Source assertions.
assert '"code": "setup_session_required"' in source
assert "request.user.check_password(password)" in source
assert "auth.delete()" in source
body = source.split("def _is_short_lived_knox_setup_token")[1].split("def _render_totp_qr_svg")[0]
assert "(expiry - created)" not in body
print("totp setup token age 1.17.22: PASS")
