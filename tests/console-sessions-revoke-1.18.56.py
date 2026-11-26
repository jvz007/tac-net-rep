#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). Every way a Console session can end ends the Console session and its live tunnels.

Real Core files and SQLite. For each cause (certificate revoke, CA replacement, an administrator's revoke of one session, of one user's sessions and
of every session, the user-name revoke of the session contract, the idle sweep, the engineer's sign-out and a deactivated account) the Console row is
revoked with its reason, one non-strict custom:console-signout row is written, the Knox token is deleted and the next request is refused. The person's
access marker moves so their live tunnels re-check within one tick: the re-check of the revoked session's Knox digest gives a session reason while a
browser-opened tunnel of the same person is left alone; access_events accepts exactly update_site and console_session_ended from probe_tunnel.py and
refuses any other function and any other file. A failing audit write or a failing hook never stops a revoke. The Access list row carries `console`
only for a Console session.
"""
import importlib.util
import sys
from datetime import timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("cs_harness", Path(__file__).with_name("console_sessions_harness.py"))
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must, rows_of = H.must, H.rows_of

h = H.boot()
if h is None:
    print("console sessions revoke 1.18.56 regression: PASS (Django is not installed: nothing to run)")
    sys.exit(0)

M, cc, cs, V, ss = h.models, h.cc, h.cs, h.views, h.ss
CURRENT = "/api/tfd/console-sessions/current/"


def get(pc):
    return h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", CURRENT)


def row_of(pc):
    return M.TecTacConsoleSession.objects.get(token_hash=cs.token_hash(pc.token))


def digest_of(pc):
    return M.TecTacSessionTrust.objects.get(pk=row_of(pc).trust_id).knox_digest


def start():
    h.reset()
    admin = h.new_user("admin", superuser=True)
    user, pc, r = h.sign_in()
    must(r.status_code == 201 and get(pc).status_code == 200, "a live Console session")
    return admin, user, pc


def check_ended(label, user, pc, reason, digest=None):
    row = row_of(pc)
    must(row.revoked and row.revoked_reason == reason and row.revoked_at is not None, f"{label}: revoked with reason {reason}, found {row.revoked} {row.revoked_reason!r}")
    must(not h.AuthToken.objects.filter(digest=digest or digest_of(pc)).exists(), f"{label}: the Knox token is deleted")
    out = [x for x in rows_of(h, "custom:console-signout") if x["metadata"]["console_session_id"] == str(row.pk)]
    must(len(out) == 1 and out[0]["strict"] is False and out[0]["metadata"]["reason"] == reason and out[0]["metadata"]["serial"] == pc.serial, f"{label}: one non-strict signout row: {[o['metadata'] for o in out]}")
    must(out[0]["operation_context"] == {"server_provenance": "console-sessions"} and out[0]["module_id"] == "core", f"{label}: provenance")
    r = get(pc)
    must(r.status_code == 401, f"{label}: the next request is refused, got {r.status_code}")
    must(h.tunnel.access_changed_at(user.pk) is not None, f"{label}: the person's access marker moved, so live tunnels re-check within a tick")


# ------------------------------------------------------------------------------------------------ certificate revoke, CA replacement
admin, user, pc = start()
digest = digest_of(pc)
_, pc_b = h.enrol_pc(user, label="Laptop")
_, _, rb = h.sign_in(user, pc_b)
must(rb.status_code == 201, "a second PC")
cc.revoke(user, pc.serial, "lost", can_manage=False)
check_ended("certificate revoke", user, pc, "certificate_revoked", digest)
must(get(pc_b).status_code == 200 and not row_of(pc_b).revoked, "another PC's session is not ended by that revoke")
must(h.queued and h.queued[-1] == ("certificate_revoked", pc.serial), "and the tunnel end is still queued as before (1.18.55)")

admin, user, pc = start()
digest = digest_of(pc)
_, pc_b = h.enrol_pc(user, label="Laptop")
h.sign_in(user, pc_b)
digest_b = digest_of(pc_b)
cc.replace_ca(admin)
check_ended("CA replacement", user, pc, "ca_replaced", digest)
must(row_of(pc_b).revoked and row_of(pc_b).revoked_reason == "ca_replaced" and not h.AuthToken.objects.filter(digest=digest_b).exists(), "every live Console session ends when the CA is replaced")
must(h.queued[-1][0] == "ca_replaced", "and the tunnel end is queued")

# a failing end does not stop the revoke itself (each Console request re-reads its certificate)
admin, user, pc = start()
real_end = cs.end_sessions
cs.end_sessions = lambda **k: (_ for _ in ()).throw(RuntimeError("table missing"))
result = cc.revoke(user, pc.serial, "lost", can_manage=False)
cs.end_sessions = real_end
must(result["changed"] is True and result["state"] == "revoked", "the certificate is revoked even though ending the sessions failed")
r = get(pc)
must(r.status_code == 401 and row_of(pc).revoked and row_of(pc).revoked_reason == "certificate_revoked", "and the very next Console request ends the session")

# ------------------------------------------------------------------------------------------------ the administrator's revokes (Access > sessions)
admin, user, pc = start()
digest = digest_of(pc)
ref = ss._login_session_ref(digest)
ss.revoke_active_login_session(ref, requested_by=admin.username, requester=admin)
check_ended("admin revoke of one session", user, pc, "admin", digest)

admin, user, pc = start()
digest = digest_of(pc)
real_get_user_model = ss.get_user_model


class _PlainUsers:  # the test user model has no role relation to join (Tactical's has)
    objects = type("Objects", (), {"select_related": staticmethod(lambda *names: h.User.objects)})


ss.get_user_model = lambda: _PlainUsers
try:
    ss.revoke_user_login_sessions(user.pk, requested_by=admin.username, requester=admin)
finally:
    ss.get_user_model = real_get_user_model
check_ended("admin revoke of a user's sessions", user, pc, "admin", digest)

admin, user, pc = start()
digest = digest_of(pc)
ss.revoke_all_login_sessions(requested_by=admin.username, requester=admin)
check_ended("revoke all", user, pc, "admin", digest)

admin, user, pc = start()
digest = digest_of(pc)
ss.revoke_user_sessions(user.username, requested_by=admin.username)
check_ended("revoke by user name (the session contract)", user, pc, "admin", digest)

# an exception in the revoke hook never blocks the revoke
admin, user, pc = start()
digest = digest_of(pc)
real_hook = cs.on_trust_revoked
cs.on_trust_revoked = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("hook down"))
ss.revoke_active_login_session(ss._login_session_ref(digest), requested_by=admin.username, requester=admin)
cs.on_trust_revoked = real_hook
must(M.TecTacSessionTrust.objects.get(pk=row_of(pc).trust_id).revoked and not h.AuthToken.objects.filter(digest=digest).exists(), "the Tec-Tac session is revoked although the hook failed")
r = get(pc)
must(r.status_code == 401 and row_of(pc).revoked, "and the next Console request is refused and ends the row")

# a failing audit write never blocks a revoke
admin, user, pc = start()
digest = digest_of(pc)
real_row = h.audit._record_row


def broken(**kwargs):
    if kwargs.get("action") == "custom:console-signout":
        raise RuntimeError("audit down")
    return real_row(**kwargs)


h.audit._record_row = broken
ss.revoke_active_login_session(ss._login_session_ref(digest), requested_by=admin.username, requester=admin)
h.audit._record_row = real_row
must(row_of(pc).revoked and row_of(pc).revoked_reason == "admin" and not h.AuthToken.objects.filter(digest=digest).exists(), "a failed signout row does not stop the revoke")

# ------------------------------------------------------------------------------------------------ idle sweep, sign-out, account
admin, user, pc = start()
digest = digest_of(pc)
M.TecTacSessionTrust.objects.filter(pk=row_of(pc).trust_id).update(last_activity_at=h.timezone.now() - timedelta(minutes=31))
ss.sweep_expired_sessions()
check_ended("idle sweep", user, pc, "idle", digest)

admin, user, pc = start()
digest = digest_of(pc)
r = h.pc_call(V.ConsoleSessionSignOutView, pc, "POST", "/api/tfd/console-sessions/sign-out/")
must(r.status_code == 200, "sign-out")
check_ended("engineer sign-out", user, pc, "engineer", digest)

admin, user, pc = start()
digest = digest_of(pc)
h.user_flags[user.pk]["is_active"] = False
r = get(pc)
must(r.status_code == 401 and row_of(pc).revoked and row_of(pc).revoked_reason == "account_inactive" and not h.AuthToken.objects.filter(digest=digest).exists(), "a deactivated account: refused, ended, token deleted")
must(h.tunnel.access_changed_at(user.pk) is not None, "and the access marker moved")

# ------------------------------------------------------------------------------------------------ live tunnels: only the ended session's tunnels end
admin, user, pc = start()
console_trust = M.TecTacSessionTrust.objects.get(pk=row_of(pc).trust_id)
browser = h.browser(user)
h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=browser,
       data={"serial": pc.serial, "code_challenge": "A" * 43, "redirect_port": 40000})  # makes the browser's Tec-Tac session row
browser_trust = M.TecTacSessionTrust.objects.get(knox_digest=browser.instance.digest)
console_ticket = {"user_id": user.pk, "trust_id": str(console_trust.pk), "knox_digest": console_trust.knox_digest}
browser_ticket = {"user_id": user.pk, "trust_id": str(browser_trust.pk), "knox_digest": browser_trust.knox_digest}
must(ss.record_terminal_activity(console_ticket["trust_id"], user.pk, console_ticket["knox_digest"]) is None, "before: the Console-opened tunnel's sign-in holds")
must(ss.record_terminal_activity(browser_ticket["trust_id"], user.pk, browser_ticket["knox_digest"]) is None, "before: the browser-opened tunnel's sign-in holds")
cc.revoke(user, pc.serial, "lost", can_manage=False)
must(ss.record_terminal_activity(console_ticket["trust_id"], user.pk, console_ticket["knox_digest"]) in ("session_revoked", "credential_unavailable"), "after: the re-check of the Console-opened tunnel ends it")
must(ss.record_terminal_activity(browser_ticket["trust_id"], user.pk, browser_ticket["knox_digest"]) is None, "after: a browser-opened tunnel of the same person is not ended")
must(h.tunnel.access_changed_at(user.pk) is not None, "and the marker that makes the tunnel re-check within one tick is there")
must(h.tunnel.access_changed_at(user.pk + 999) is None, "nobody else's marker moved")

# ------------------------------------------------------------------------------------------------ access_events: exactly two callers
import ast  # noqa: E402

ae = h.access_events
must(ae._ALLOWED["mark_changed"] == ("tunnel", ("update_site", "console_session_ended")), f"mark_changed accepts update_site and console_session_ended: {ae._ALLOWED['mark_changed']}")
must(ae._ALLOWED["changed_at"] == ("tunnel", "access_changed_at") and ae._ALLOWED["notify_access_changed"] == ("dispatcher", None), "the other two callers did not change")
ae.clear_callers_for_tests()
must(ae.mark_changed([5]) == 0, "a call from a test (not Core's tunnel code) is refused and changes nothing")
tunnel_file = str(Path(h.tunnel.__file__))
for name, expected in (("console_session_ended", 1), ("update_site", 1), ("end_session", 0), ("some_other_function", 0), ("certificate_revoked", 0)):
    namespace = {}
    exec(compile(f"def {name}():\n    from tec_tac import access_events\n    return access_events.mark_changed([5])\n", tunnel_file, "exec"), namespace)
    ae.clear_callers_for_tests()
    got = namespace[name]()
    must(got == expected, f"a function named {name} in probe_tunnel.py: mark_changed returned {got}, expected {expected}")
# a module's file is refused even with a good name
module_file = str(Path(h.tmp) / "modules" / "networkprobe" / "views.py")
namespace = {}
exec(compile("def console_session_ended():\n    from tec_tac import access_events\n    return access_events.mark_changed([5])\n", module_file, "exec"), namespace)
ae.clear_callers_for_tests()
must(namespace["console_session_ended"]() == 0, "the same function name in another file is refused")
must(h.tunnel.console_session_ended(True) is None and h.tunnel.console_session_ended("x") is None, "a non-integer user id is ignored")
tree = ast.parse(Path(h.tunnel.__file__).read_text(encoding="utf-8"))
callers = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and "mark_changed" in ast.unparse(n)]
must(sorted(callers) == ["console_session_ended", "update_site"], f"probe_tunnel.py calls mark_changed only from those two functions: {callers}")

# ------------------------------------------------------------------------------------------------ the Access list
admin, user, pc = start()
browser = h.browser(user)
h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=browser, data={"serial": pc.serial, "code_challenge": "A" * 43, "redirect_port": 40000})
tokens = list(h.AuthToken.objects.select_related("user").order_by("created"))
rows = ss._serialize_active_login_sessions(tokens, current_request=None)
consoles = [r for r in rows if r["console"] is not None]
must(len(rows) == 3 and len(consoles) == 1, f"three live logins (the browser that asked for the code, another browser and the Console), one of them a Console: {len(rows)} {len(consoles)}")
must(consoles[0]["console"] == {"pc_label": "Work PC", "short_serial": pc.serial[:8]}, f"the Console row carries the PC label and the short serial: {consoles[0]['console']}")
must(all(r["id"] != consoles[0]["id"] for r in rows if r["console"] is None) and len([r for r in rows if r["console"] is None]) == 2, "the browsers' rows have console null")
for key in ("id", "user_id", "username", "created_at", "expires_at", "current", "tec_tac_observed", "last_activity_at", "last_seen_at", "last_ip"):
    must(key in consoles[0], f"the existing key {key} is still there")
must("digest" not in str(rows), "no digest in the list")
cc.revoke(user, pc.serial, "lost", can_manage=False)
rows = ss._serialize_active_login_sessions(list(h.AuthToken.objects.select_related("user")), current_request=None)
must(all(r["console"] is None for r in rows), "after the end only the browser's row is left, with console null")
real_model = M.TecTacConsoleSession


class Broken:
    class objects:  # noqa: N801 - a stand-in for a table that cannot be read
        @staticmethod
        def filter(*a, **k):
            raise RuntimeError("table gone")


M.TecTacConsoleSession = Broken
try:
    rows = ss._serialize_active_login_sessions(list(h.AuthToken.objects.select_related("user")), current_request=None)
finally:
    M.TecTacConsoleSession = real_model
must(len(rows) == 2 and all(r["console"] is None for r in rows), "an unreadable Console table does not break the list")

print("console sessions revoke 1.18.56 regression: PASS")
