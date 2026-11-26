#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). examples/console-session-client.py, the stand-in Console, works against Core's real routes.

The client's HTTP function is replaced by a call into the real Django views (no network), then every command runs: keygen, enrol, authorise (the
person's own Knox token), signin (the server proof verifies against the CA key), current, activity, replay (the first send is accepted, the second is
refused), request and sign-out. Also: the file is plain Python with only the standard library and `cryptography`, and keeps no secret but the key file
and the state file.
"""
import ast
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIENT = ROOT / "examples" / "console-session-client.py"

source = CLIENT.read_text(encoding="utf-8")
imports = set()
for node in ast.walk(ast.parse(source)):
    if isinstance(node, ast.Import):
        imports |= {a.name.split(".")[0] for a in node.names}
    elif isinstance(node, ast.ImportFrom) and node.level == 0:
        imports.add(node.module.split(".")[0])
STDLIB = {"__future__", "argparse", "base64", "hashlib", "json", "os", "ssl", "sys", "time", "urllib", "pathlib"}
assert imports - STDLIB == {"cryptography"}, f"standard library plus cryptography only: {imports - STDLIB}"
assert b"\r" not in CLIENT.read_bytes(), "LF line endings"
assert "tectac-console-signin-v1" in source and "tectac-core-signin-v1" in source and "tectac-console-request-v1" in source and "tectac-console-enrol-v1" in source

spec = importlib.util.spec_from_file_location("cs_harness", HERE / "console_sessions_harness.py")
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must = H.must
h = H.boot()
if h is None:
    print("console sessions example client 1.18.56 regression: PASS (source checks only: Django is not installed)")
    sys.exit(0)

cspec = importlib.util.spec_from_file_location("console_session_client", CLIENT)
client = importlib.util.module_from_spec(cspec)
cspec.loader.exec_module(client)

h.reset()
user = h.new_user("engineer")
admin = h.new_user("admin", superuser=True)
h.cc.authorise(admin, user.pk)
code = h.cc.create_enrolment_code(user, H.HOST)["code"]
browser = h.browser(user)
V = h.views
from tec_tac import console_certificate_views as CV  # noqa: E402

ROUTES = {
    "/api/tfd/console-certificates/enrol/": CV.ConsoleCertificateEnrolView, "/api/tfd/console-sessions/authorise/": V.ConsoleSessionAuthoriseView,
    "/api/tfd/console-sessions/token/": V.ConsoleSessionTokenView, "/api/tfd/console-sessions/current/": V.ConsoleSessionCurrentView,
    "/api/tfd/console-sessions/activity/": V.ConsoleSessionActivityView, "/api/tfd/console-sessions/sign-out/": V.ConsoleSessionSignOutView,
}
sent = []


def fake_call(args, host, method, path, body=b"", headers=None):
    headers = dict(headers or {})
    extra = {"HTTP_HOST": host, "REMOTE_ADDR": H.IP}
    for name, value in headers.items():
        key = "HTTP_" + name.upper().replace("-", "_")
        if name.lower() != "content-type":
            extra[key] = value
    sent.append((method, path, headers))
    view = ROUTES[path.split("?")[0]]
    session = browser if headers.get("Authorization") == browser.header else None
    response = h.call(view, method, path, session=session, raw=body, extra=extra) if method == "POST" else h.call(view, method, path, session=session, extra=extra)
    return response.status_code, json.loads(json.dumps(response.data, default=str)), dict(response.items())


client.call = fake_call
tmp = Path(tempfile.mkdtemp(prefix="cs-client-"))
key_file, state_file = str(tmp / "console.pem"), str(tmp / "state.json")


def run(*argv):
    """Run one client command. Returns (exit code, output)."""
    out = io.StringIO()
    old = sys.argv
    sys.argv = ["console-session-client.py", *argv]
    code_ = 0
    try:
        with contextlib.redirect_stdout(out):
            try:
                client.main()
            except SystemExit as exc:
                code_ = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
                if isinstance(exc.code, str):
                    out.write(exc.code)
    finally:
        sys.argv = old
    return code_, out.getvalue()


c, out = run("keygen", "--key", key_file)
must(c == 0 and Path(key_file).is_file(), f"keygen: {out}")
c, out = run("enrol", "--server", H.HOST, "--code", code, "--key", key_file, "--label", "Test PC", "--state", state_file)
must(c == 0 and "Enrolled" in out, f"enrol: {c} {out}")
state = json.loads(Path(state_file).read_text())
must(set(state) == {"host", "key", "server_id", "ca_public_key", "cert", "serial", "pc_label"}, f"the state after enrolment: {sorted(state)}")
must("PRIVATE" not in json.dumps(state), "no private key in the state file")
c, out = run("authorise", "--state", state_file, "--knox", browser.header)
must(c == 0 and "one-time code" in out, f"authorise: {out}")
state = json.loads(Path(state_file).read_text())
c, out = run("signin", "--state", state_file)
must(c == 0 and "server proof verifies" in out, f"signin: {out}")
state = json.loads(Path(state_file).read_text())
must(state["token"] and "pending_code" not in state and "pending_verifier" not in state, "the code and verifier are gone after the sign-in, the token is kept")
must(state["token"] not in out, "the token is not printed")
c, out = run("signin", "--state", state_file)
must(c != 0 and "No code" in out, "a second signin has no code")
for command in ("current", "activity"):
    c, out = run(command, "--state", state_file)
    must(c == 0 and "HTTP 200" in out, f"{command}: {out}")
c, out = run("request", "GET", "/api/tfd/console-sessions/current/?x=1", "--state", state_file)
must(c == 0 and "HTTP 200" in out, f"request with a query: {out}")
c, out = run("replay", "--state", state_file)
must(c == 0 and "PASS: the replay was refused" in out and "proof_replayed" in out, f"replay: {out}")
c, out = run("sign-out", "--state", state_file)
must(c == 0 and "revoked" in out, f"sign-out: {out}")
c, out = run("current", "--state", state_file)
must(c != 0 and "HTTP 401" in out, f"after sign-out the session is refused: {out}")
must(h.models.TecTacConsoleSession.objects.get().revoked_reason == "engineer", "the Core row says engineer")
for _, _, hdrs in sent:
    must(state["token"] not in json.dumps({k: v for k, v in hdrs.items() if k != "Authorization"}), "the token is only ever in the Authorization header")
print("console sessions example client 1.18.56 regression: PASS")
