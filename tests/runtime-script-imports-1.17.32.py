#!/usr/bin/env python3
"""1.17.32 regression: a script that Tactical's `manage.py shell` runs may import only what Tactical's venv has.

1.17.31 shipped tests/tactical-websocket-runtime-1.17.31.py, which imported channels.testing. That module imports daphne.testing, and
Tactical v1.5.2's venv has no daphne (the service called daphne.service runs uvicorn). The script could not run on the dev server. This
test stops that from coming back. It is plain Python with no Django, so it runs on the development PC and in the release gates.

Covered (AST, not text search):
- every tests/*.py whose text contains 'manage.py shell' imports nothing that is neither the standard library (sys.stdlib_module_names),
  a Tactical app, tec_tac, nor a module from TACTICAL_REQUIREMENTS; and it never imports daphne, channels.testing, pytest, pytest_asyncio,
  mock, requests_mock or freezegun;
- scripts/, framwork/, extensions/, bootstrap-modules/, examples/, templates/ and reportsets/ never import daphne or channels.testing;
- the socket script (tests/tactical-websocket-runtime-1.17.34.py since 1.17.34, 1.17.33 and 1.17.32 before) drives the ASGI application with
  asgiref.testing.ApplicationCommunicator, builds a websocket scope, commits its rows and deletes them in a finally block (no transaction
  or rollback, since 1.17.33), and checks 4401 on a reused ticket, 4003 on a foreign Origin and one custom:terminal-start row.

TACTICAL_REQUIREMENTS is read from reference/tacticalrmm/api/tacticalrmm/requirements.txt (v1.5.2), by import name: the pip name in the
file, mapped to the module it installs (django-cors-headers -> corsheaders, nats-py -> nats, pycryptodome -> Crypto, ...), plus the
packages those pull in that Tactical's own code imports (redis from celery[redis], the uvicorn[standard] extras). Keep the list in step
with that file when Tactical moves; the test fails on any name it does not know.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Tactical v1.5.2 requirements.txt, as import names (see the docstring for the mapping).
TACTICAL_REQUIREMENTS = {
    "asgiref", "celery", "kombu", "billiard", "click", "vine", "redis", "hiredis", "certifi", "channels", "channels_redis",
    "cryptography", "django", "corsheaders", "allauth", "django_filters", "knox", "rest_framework", "drf_spectacular",
    "meshctrl", "msgpack", "nats", "packaging", "psutil", "psycopg", "Crypto", "pyotp", "pyparsing", "python_ipware", "qrcode",
    "requests", "six", "sqlparse", "tldextract", "twilio", "urllib3", "uvicorn", "uvloop", "httptools", "watchfiles", "dotenv",
    "websockets", "validators", "zipp", "pandas", "kaleido", "jinja2", "markdown", "plotly", "weasyprint", "ocxsect", "pycparser",
    "dateutil", "pytz", "tzdata", "yaml", "idna", "charset_normalizer",
}

# Tactical v1.5.2's INSTALLED_APPS packages (api/tacticalrmm/tacticalrmm/settings.py) and the project package itself.
TACTICAL_APPS = {
    "accounts", "apiv3", "apiv4", "clients", "agents", "checks", "services", "winupdate", "software", "core", "automation",
    "autotasks", "logs", "scripts", "alerts", "ee", "tacticalrmm",
}

# Tec-Tac's own package.
TEC_TAC = {"tec_tac"}

# Never allowed in a manage.py shell script.
FORBIDDEN_IN_SHELL = {"daphne", "pytest", "pytest_asyncio", "mock", "requests_mock", "freezegun"}
FORBIDDEN_DOTTED = {"channels.testing"}

# Forbidden everywhere the code runs: a daphne or channels.testing import in these folders fails here too.
SCAN_FOLDERS = ("scripts", "framwork", "extensions", "bootstrap-modules", "examples", "templates", "reportsets", "tests")
FORBIDDEN_ANYWHERE = {"daphne"}

SHELL_MARKER = "manage.py shell"
SOCKET_SCRIPT = ROOT / "tests" / "tactical-websocket-runtime-1.17.34.py"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def imports_of(path: Path):
    """(top-level names, dotted names) that a file imports, from its AST. Relative imports are Tec-Tac's own and are skipped."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    tops: set[str] = set()
    dotted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                dotted.add(alias.name)
                tops.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            dotted.add(node.module)
            tops.add(node.module.split(".")[0])
    return tops, dotted


def dotted_hit(dotted: set[str], forbidden: set[str]) -> set[str]:
    return {name for name in dotted for bad in forbidden if name == bad or name.startswith(bad + ".")}


failures: list[str] = []
known = set(sys.stdlib_module_names) | {"__future__"} | TACTICAL_APPS | TEC_TAC | TACTICAL_REQUIREMENTS

# 1. every manage.py shell script in tests/
shell_scripts = sorted(p for p in (ROOT / "tests").glob("*.py") if SHELL_MARKER in p.read_text(encoding="utf-8"))
must(len(shell_scripts) >= 20, f"found {len(shell_scripts)} manage.py shell scripts; expected the 31 of 1.17.32")
for path in shell_scripts:
    tops, dotted = imports_of(path)
    rel = path.relative_to(ROOT).as_posix()
    bad_top = sorted(t for t in tops if t in FORBIDDEN_IN_SHELL)
    bad_dotted = sorted(dotted_hit(dotted, FORBIDDEN_DOTTED | FORBIDDEN_ANYWHERE))
    unknown = sorted(t for t in tops if t not in known)
    if bad_top or bad_dotted:
        failures.append(f"{rel}: forbidden in a shell script: {', '.join(bad_top + bad_dotted)}")
    if unknown:
        failures.append(f"{rel}: not in the standard library, a Tactical app, tec_tac or Tactical's requirements: {', '.join(unknown)}")
print(f"PASS {len(shell_scripts)} manage.py shell scripts checked")

# 2. the rest of the code: no daphne, no channels.testing
scanned = 0
for folder in SCAN_FOLDERS:
    base = ROOT / folder
    if not base.is_dir():
        continue
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        scanned += 1
        _tops, dotted = imports_of(path)
        hit = sorted(dotted_hit(dotted, FORBIDDEN_DOTTED | FORBIDDEN_ANYWHERE))
        if hit:
            failures.append(f"{path.relative_to(ROOT).as_posix()}: imports {', '.join(hit)}, which Tactical's venv does not have")
print(f"PASS {scanned} Python files outside the shell scripts checked for daphne and channels.testing")

# 3. the socket script (named for 1.17.34): what the dev-server run depends on
if SOCKET_SCRIPT.exists():
    text = SOCKET_SCRIPT.read_text(encoding="utf-8")
    tops, dotted = imports_of(SOCKET_SCRIPT)
    must("asgiref.testing" in dotted and "ApplicationCommunicator" in text, "the socket script uses asgiref.testing.ApplicationCommunicator")
    must(dotted_hit(dotted, {"channels.testing", "daphne"}) == set(), "the socket script imports neither channels.testing nor daphne")
    must('"type": "websocket"' in text and "ws_scope" in text, "the socket script builds a websocket scope by hand")
    must("tacticalrmm.asgi" in dotted and "application" in text, "the socket script drives tacticalrmm.asgi.application")
    must("set_rollback" not in text.split('"""', 2)[2] and "transaction.atomic" not in text.split('"""', 2)[2],
         "the socket script runs no transaction and no rollback (database_sync_to_async closes the connection inside one)")
    must("finally:" in text and "remove_probe_rows(" in text and "cache.delete(tw.cache_key(" in text,
         "the socket script deletes its rows and clears its ticket keys in a finally block")
    must('async_to_sync(socket_leg)()' in text, "the socket leg runs under async_to_sync")
    must("4401" in text and "4003" in text, "the socket script checks 4401 and 4003")
    must('"custom:terminal-start"' in text and "starts.count() == 1" in text, "the socket script checks one custom:terminal-start row")
    must("evil.example.invalid" in text and "CORS_ORIGIN_WHITELIST" in text, "the socket script checks a foreign Origin and the split host")
    print("PASS the socket script has the asgiref, scope, cleanup, 4401, 4003 and one-row checks")

if failures:
    raise AssertionError("runtime script imports:\n  " + "\n  ".join(failures))
print("[TEST] PASS runtime script imports 1.17.32")
