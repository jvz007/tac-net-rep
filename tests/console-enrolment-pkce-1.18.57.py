#!/usr/bin/env python3
"""Regression: Core 1.18.57 (C2). Enrolment over loopback with PKCE: an optional code_challenge on mine/enrolment-code/ and a matching code_verifier on enrol/.

Two parts. The first needs no Django: migration 0051 is compared with models.py field for field, and the source, the docs and the contract text are
checked by reading them. The second runs real Django on a temporary SQLite file (tests/console_certificates_harness.py) and calls the real views.
"""
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of, captured_text, b64u = harness.must, harness.rows_of, harness.captured_text, harness.b64u


def call_name(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def kwarg(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


# ---- part 1: no Django. Migration 0051 against the model.
models_tree = ast.parse((APP / "models.py").read_bytes().decode("utf-8"))
enrolment = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacConsoleEnrolment")
field = next(s.value for s in enrolment.body if isinstance(s, ast.Assign) and getattr(s.targets[0], "id", "") == "code_challenge")
migration_path = APP / "migrations" / "0051_console_enrolment_pkce.py"
migration_source = migration_path.read_text(encoding="utf-8")
migration = ast.parse(migration_source)
adds = [n for n in ast.walk(migration) if isinstance(n, ast.Call) and call_name(n) == "AddField"]
must(len(adds) == 1, "0051 has exactly one AddField")
add = adds[0]
must(kwarg(add, "model_name").value == "tectacconsoleenrolment" and kwarg(add, "name").value == "code_challenge", "0051 adds code_challenge to the enrolment")
m_field = kwarg(add, "field")
must(call_name(field) == call_name(m_field) == "CharField", "a CharField in both")
for key in ("max_length", "null", "blank", "unique", "default"):
    a, b = kwarg(field, key), kwarg(m_field, key)
    must((ast.unparse(a) if a else None) == (ast.unparse(b) if b else None), f"code_challenge.{key} agrees: {a and ast.unparse(a)} vs {b and ast.unparse(b)}")
must(ast.unparse(kwarg(field, "max_length")) == "43" and ast.unparse(kwarg(field, "default")) == "''" and ast.unparse(kwarg(field, "blank")) == "True", "43 characters, blank, empty default")
must(kwarg(field, "null") is None, "not nullable")
must('("tec_tac", "0050_console_sessions")' in migration_source and migration_source.count("dependencies = [") == 1, "0051 depends on 0050 only")
must(len(list((APP / "migrations").glob("0051_*.py"))) == 1 and len(list((APP / "migrations").glob("0052_*.py"))) == 1 and not list((APP / "migrations").glob("0053_*.py")), "0051 is the migration of this release (0052 is 1.18.58's)")
must(b"\r" not in migration_path.read_bytes(), "LF like 0050")

cc_source = (APP / "console_certificates.py").read_text(encoding="utf-8")
for line in cc_source.splitlines():
    if 'code_hash=""' in line:
        must('code_challenge=""' in line, f"a clear of code_hash without code_challenge: {line.strip()}")
must(cc_source.count('code_challenge=""') >= 5, "authorise, cancel, expiry sweep, CA replace and the burn all clear the challenge")
must("hmac.compare_digest" in cc_source and "verifier_invalid" in cc_source, "the check is constant time and refuses with verifier_invalid")
must('ENROL_KEYS = frozenset({"v", "public_key", "pc_label", "proof"})' in cc_source, "ENROL_KEYS is the unchanged required set")
must('ENROL_OPTIONAL_KEYS = frozenset({"code_verifier"})' in cc_source, "code_verifier is the one optional key")

# ---- the docs and the contract text
docs = (ROOT / "docs" / "console-certificates.md").read_text(encoding="utf-8")
contracts = (APP / "contracts.py").read_bytes().decode("utf-8")
for needle in ("code_challenge", "code_verifier", "verifier_invalid", "S256", "1.18.57", "loopback"):
    must(needle in docs, f"docs/console-certificates.md mentions {needle}")
code_route = contracts.split('"/api/tfd/console-certificates/mine/enrolment-code/"', 1)[1].split('"/api/tfd/console-certificates/enrol/"', 1)[0]
enrol_route = contracts.split('"/api/tfd/console-certificates/enrol/"', 1)[1].split('"/api/tfd/console-certificates/": {', 1)[0]
must("code_challenge" in code_route and "1.18.57" in code_route and "pkce" in code_route, "the code route entry")
must("code_verifier" in enrol_route and "verifier_invalid" in enrol_route and "1.18.57" in enrol_route, "the enrol route entry")
must("base64url(SHA-256(" in (ROOT / "docs" / "console-sessions.md").read_text(encoding="utf-8"), "console-sessions.md defines the same challenge")
must('CAPABILITY_VERSION = "1.0.0"' in (APP / "console_sessions.py").read_text(encoding="utf-8"), "core.console_session stays 1.0.0")
must("core.probe_transport 1.3.0" in contracts, "core.probe_transport stays 1.3.0")

# ---- the example client
client_source = (ROOT / "examples" / "console-session-client.py").read_text(encoding="utf-8")
must("def cmd_pkce" in client_source and "--verifier" in client_source and "code_verifier" in client_source, "the example client has pkce and enrol --verifier")

h = harness.boot()
if h is None:
    print("console enrolment pkce 1.18.57 regression: PASS (source and migration checks only: Django is not installed)")
    sys.exit(0)

from django.apps import apps  # noqa: E402
from django.db.migrations.autodetector import MigrationAutodetector  # noqa: E402
from django.db.migrations.state import ProjectState  # noqa: E402

current = ProjectState.from_apps(apps)
before = current.clone()
before.models[("tec_tac", "tectacconsoleenrolment")].fields.pop("code_challenge")
before.models[("tec_tac", "tectacruntimeconfig")].fields.pop("console_ui_url")  # 1.18.58: 0052 adds it
mig = importlib.import_module("tec_tac.migrations.0051_console_enrolment_pkce").Migration
state = before.clone()
for op in mig.operations:
    op.state_forwards("tec_tac", state)
for op in importlib.import_module("tec_tac.migrations.0052_console_ui_url").Migration.operations:
    op.state_forwards("tec_tac", state)
changes = MigrationAutodetector(state, current)._detect_changes()
must(not {app: ms for app, ms in changes.items() if app == "tec_tac"}, "0051 and the models agree (makemigrations would write nothing)")
must(mig.dependencies == [("tec_tac", "0050_console_sessions")], "0051 depends on 0050 only")

# ---- part 2: behaviour
cc, M, V = h.cc, h.models, h.views
HOST, IP, Console = harness.HOST, harness.IP, h.Console
CODE_URL = "/api/tfd/console-certificates/mine/enrolment-code/"
h.reset()
ADMIN = h.new_user("admin", superuser=True)
SAME_401 = {"detail": "The enrolment code is not valid.", "code": "code_invalid"}


def pkce():
    verifier = b64u(os.urandom(32))
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())


def engineer():
    user = h.new_user()
    cc.authorise(ADMIN, user.pk)
    return user


def ask(user, challenge="__none__", clear=True):
    if clear:
        h.cache.clear()
    data = {} if challenge == "__none__" else {"code_challenge": challenge}
    return h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", CODE_URL, user, data)


def enrol_with(code, verifier=None, console=None):
    console = console or Console()
    body = console.body(code)
    if verifier is not None:
        body["code_verifier"] = verifier
    return h.enrol(code, console, body=body)


def row_of(user):
    return M.TecTacConsoleEnrolment.objects.filter(user_id=user.pk).order_by("-authorised_at").first()


def refusals():
    return rows_of(h, "custom:console-cert-enrol-refused")


# a code with a challenge and the right verifier enrols, with the same bundle keys as before (1.18.58 adds ui_url, additive)
user = engineer()
verifier, challenge = pkce()
r = ask(user, challenge)
must(r.status_code == 200 and set(r.data) == {"code", "code_expires_at", "expires_in_seconds", "host", "server_id", "enrolment_id"}, f"the code answer keeps its keys: {r.status_code} {r.data}")
code = r.data["code"]
must(row_of(user).code_challenge == challenge, "the challenge is stored with the code")
must(challenge not in json.dumps(r.data, default=str) and verifier not in json.dumps(r.data, default=str), "neither challenge nor verifier is in the answer")
ok = enrol_with(code, verifier)
must(ok.status_code == 201 and set(ok.data) == {"v", "host", "server_id", "ca_public_key", "ca_cert", "cert", "serial", "not_after", "engineer", "ui_url"}, f"enrols: {ok.status_code} {ok.data}")
must(row_of(user).state == "used" and row_of(user).code_challenge == "", "used, and the challenge is cleared")
code_rows = rows_of(h, "custom:console-cert-enrol-code")
must(code_rows and code_rows[-1]["metadata"]["pkce"] is True and code_rows[-1]["strict"] is False, "the code row says pkce: true and is not strict")
must(challenge not in json.dumps(code_rows, default=str), "the challenge is not in the audit row")

# a wrong verifier: 401 verifier_invalid, the code is burnt, the enrolment stays open, a new code works
h.rows.clear()
h.cache.clear()
user = engineer()
verifier, challenge = pkce()
code = ask(user, challenge).data["code"]
wrong, _ = pkce()
r = enrol_with(code, wrong)
must(r.status_code == 401 and r.data["code"] == "verifier_invalid", f"wrong verifier: {r.status_code} {r.data}")
must(row_of(user).state == "open" and row_of(user).code_hash == "" and row_of(user).code_challenge == "", "code burnt, challenge gone, enrolment open")
again = enrol_with(code, verifier)
must(again.status_code == 401 and dict(again.data) == SAME_401, "the right verifier with the burnt code is code_invalid")
must(len(refusals()) == 1, f"one refusal row per address per minute: {len(refusals())}")
meta = refusals()[0]["metadata"]
must(meta["reason"] == "verifier_invalid" and meta["engineer_id"] == user.pk and refusals()[0]["actor"].pk == user.pk and refusals()[0]["strict"] is False, "the row sits under the engineer")
text = captured_text(h)
must(wrong not in text and verifier not in text and challenge not in text and code not in text, "no secret in any row or log line")
must(ask(user, pkce()[1]).status_code == 200, "a new code can be asked for on the open enrolment")
v2, c2 = pkce()
code2 = ask(user, c2).data["code"]
h.cache.clear()
must(enrol_with(code2, v2).status_code == 201, "the new code with its verifier enrols")

# a challenge stored but no verifier: refused and burnt
user = engineer()
verifier, challenge = pkce()
code = ask(user, challenge).data["code"]
h.cache.clear()
r = enrol_with(code)
must(r.status_code == 401 and r.data["code"] == "verifier_invalid", f"missing verifier: {r.status_code} {r.data}")
must(row_of(user).state == "open" and row_of(user).code_hash == "", "burnt, still open")

# a verifier with no challenge stored: refused and burnt
user = engineer()
code = ask(user).data["code"]
must(row_of(user).code_challenge == "", "no challenge stored")
h.cache.clear()
r = enrol_with(code, pkce()[0])
must(r.status_code == 401 and r.data["code"] == "verifier_invalid", f"a verifier with nothing to match: {r.status_code} {r.data}")
must(row_of(user).state == "open" and row_of(user).code_hash == "", "burnt, still open")

# no challenge and no verifier: today's behaviour (the command-line path)
user = engineer()
code = ask(user).data["code"]
h.cache.clear()
r = enrol_with(code)
must(r.status_code == 201, f"the CLI path: {r.status_code} {r.data}")
must(rows_of(h, "custom:console-cert-enrol-code")[-1]["metadata"]["pkce"] is False, "the code row says pkce: false")

# a new code without a challenge clears an older challenge
user = engineer()
verifier, challenge = pkce()
ask(user, challenge)
must(row_of(user).code_challenge == challenge, "the challenge is stored")
code = ask(user).data["code"]
must(row_of(user).code_challenge == "", "a code without a challenge clears the older one")
h.cache.clear()
must(enrol_with(code, verifier).data["code"] == "verifier_invalid", "so the old verifier no longer fits the new code")

# malformed challenges: 400 before anything is stored
user = engineer()
good_code = ask(user).data["code"]
hash_before = row_of(user).code_hash
for name, value in (("short", "A" * 42), ("long", "A" * 44), ("bad characters", "A" * 42 + "+"), ("padding", "A" * 42 + "="), ("a number", 12345), ("a list", ["A" * 43]), ("null", None), ("empty", "")):
    r = ask(user, value)
    must(r.status_code == 400 and r.data["code"] == "invalid_request", f"{name}: {r.status_code} {r.data}")
    must(row_of(user).code_hash == hash_before and row_of(user).code_challenge == "", f"{name}: nothing stored, the old code still stands")
h.cache.clear()
r = h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", CODE_URL, user, {"code_challenge": "A" * 43, "extra": 1})
must(r.status_code == 400 and r.data["code"] == "unknown_field", f"an unknown key: {r.status_code} {r.data}")
must(row_of(user).code_hash == hash_before, "an unknown key stores nothing")

# malformed verifiers: 400 refuse-early, the code is not burnt
console = Console()
for name, value in (("short", "A" * 42), ("bad characters", "A" * 42 + "!"), ("a number", 7), ("null", None)):
    h.cache.clear()
    body = console.body(good_code)
    body["code_verifier"] = value
    r = h.enrol(good_code, console, body=body)
    must(r.status_code == 400 and r.data["code"] == "invalid_request", f"{name}: {r.status_code} {r.data}")
    must(row_of(user).code_hash == hash_before, f"{name}: the code is not burnt")
h.cache.clear()
body = console.body(good_code)
body["extra"] = "x"
must(h.enrol(good_code, console, body=body).status_code == 400, "an unknown key is still refused")
h.cache.clear()
must(h.enrol(good_code, console).status_code == 201, "and the untouched code still works afterwards")

# an API key still cannot ask for a code, with or without a challenge
user = engineer()
before_hash = row_of(user).code_hash
h.cache.clear()
r = h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", CODE_URL, user, {"code_challenge": "A" * 43}, auth="api")
must(r.status_code == 403 and r.data["code"] == "interactive_session_required", f"an API key: {r.status_code} {r.data}")
must(row_of(user).code_hash == before_hash and row_of(user).code_challenge == "", "nothing stored for an API key")

# failures count toward the limiter: 10 a minute from one address, then 429; still one refusal row
h.reset()
ADMIN = h.new_user("admin", superuser=True)
statuses = []
for index in range(11):
    user = engineer()
    code = ask(user, pkce()[1], clear=index == 0).data["code"]
    statuses.append(enrol_with(code, pkce()[0]).status_code)
must(statuses[:10] == [401] * 10 and statuses[10] == 429, f"ten failures then the limiter: {statuses}")
must(len(refusals()) == 1, f"one row per minute per address however many failures: {len(refusals())}")

# the database holds no verifier and no code
dump = json.dumps(list(M.TecTacConsoleEnrolment.objects.values()), default=str)
must(verifier not in dump and code not in dump, "no verifier and no code in the database")
print("console enrolment pkce 1.18.57 regression: PASS")
