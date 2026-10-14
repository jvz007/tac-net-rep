#!/usr/bin/env python3
"""1.17.32 regression (Johan's item 3): the terminal socket accepts Tactical's configured frontend origin, and nothing else new.

Tactical's standard install puts the API on one host and the web UI on another. The browser sends Origin = the UI host, while nginx sends
Host = the API host. Core 1.17.31 accepted only the same host, so every terminal closed 4003 on that layout. 1.17.32 also accepts an
Origin that equals a frontend origin named in Tactical's own CORS_ORIGIN_WHITELIST (and CORS_ALLOWED_ORIGINS when present).

The stubs are the consumer test's (tests/tactical-websocket-consumer-1.17.31.py, which reuses the ticket test's fixtures): the stub of
Tactical's consumer, the stub Django boundary and the real tactical_websocket_consumers.py. The settings come from a stub django.conf
module, which the consumer reads at call time. Nothing here reads a request value for the frontend list.

Covered: the split host (Host api.x.test, Origin https://rmm.x.test, whitelist ['https://rmm.x.test']) is accepted, through origin_allowed
and through connect(), where one watcher starts; a foreign Origin is refused 4003 even with a whitelist; a different scheme is refused;
the default port forms are equal (https://rmm.x.test:443 is https://rmm.x.test) and a non-default port is not; an entry with a path, a
query, a fragment, '*', 'null', a number, a regular expression or a string where a list belongs never matches; an empty or missing
setting gives same-host behaviour only; a settings read that raises gives same-host behaviour only; a value the request supplies in its
own headers (X-Forwarded-Host, X-Frontend-Origin) is not the Host and not whitelisted, so it is refused; no Origin is allowed; a null,
empty or malformed Origin is refused; an Origin with no Host is accepted only when the whitelist names it; CORS_ALLOWED_ORIGINS is read
and CORS_ALLOW_ALL_ORIGINS is ignored. The 4003 text in the contract metadata names the frontend origin.

It must fail on 1.17.31 (the split-host case). tests/tactical-websocket-consumer-1.17.31.py must still pass unchanged.
"""
from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CONSUMER_TEST = HERE / "tactical-websocket-consumer-1.17.31.py"
source = CONSUMER_TEST.read_text(encoding="utf-8")
# Run the consumer test's fixtures only: everything before its first check. That gives the stub consumer, the loaded consumers module,
# connect(), scope_for(), fresh_socket() and run(). Its own checks are not run here.
marker = "1. a valid ticket connects"
cut = source.rfind("\n", 0, source.index(marker)) + 1
H = {"__name__": "ws_origin_fixtures", "__file__": str(CONSUMER_TEST)}
exec(compile(source[:cut], str(CONSUMER_TEST), "exec"), H)  # noqa: S102 - test-only reuse of the consumer test's stubs
must, reset, make_user, mint, CLOSED = (H[k] for k in ("must", "reset", "make_user", "mint", "CLOSED"))
consumers, connect, fresh_socket, run, ws = (H[k] for k in ("consumers", "connect", "fresh_socket", "run", "ws"))

DJANGO_CONF = "django.conf"


def use_settings(**values):
    """Point the consumer's settings read at a stub django.conf with exactly these settings."""
    conf = types.ModuleType(DJANGO_CONF)
    conf.settings = SimpleNamespace(**values)
    sys.modules[DJANGO_CONF] = conf


class BrokenSettings:
    def __getattr__(self, name):
        raise RuntimeError("settings are not configured")


def use_broken_settings():
    conf = types.ModuleType(DJANGO_CONF)
    conf.settings = BrokenSettings()
    sys.modules[DJANGO_CONF] = conf


def headers(host="api.x.test", origin=None, extra=()):
    items = []
    if host is not None:
        items.append((b"host", host.encode("latin-1")))
    if origin is not None:
        items.append((b"origin", origin.encode("latin-1")))
    items.extend(extra)
    return {"headers": items}


async def tidy(consumer):
    await consumer.disconnect(1000)
    await asyncio.sleep(0)
    if consumer._tec_watch is not None:
        consumer._tec_watch.cancel()
        await asyncio.sleep(0)


# ------------------------------------------------------------------------------------------------ 1. the split host
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "split host: Origin in the whitelist is accepted")
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
good = connect(ticket, host="api.x.test", origin="https://rmm.x.test")
must(CLOSED == [] and good.group_name is not None, "split host through connect(): the socket is accepted")
must(good._tec_watch is not None, "split host through connect(): one watcher starts")
run(tidy(good))
reset()

# ------------------------------------------------------------------------------------------------ 2. normal_origin
for raw, want in {
    "https://RMM.x.test:443": "https://rmm.x.test",
    "http://rmm.x.test:80": "http://rmm.x.test",
    "https://rmm.x.test:8443": "https://rmm.x.test:8443",
    "https://rmm.x.test/": "https://rmm.x.test",
    "https://[::1]:8443": "https://[::1]:8443",
}.items():
    must(consumers.normal_origin(raw) == want, f"normal_origin({raw!r}) is {want!r}")
for raw in ["", "null", "*", "https://rmm.x.test/app", "https://rmm.x.test?x=1", "https://rmm.x.test#f", "https://u@rmm.x.test",
            "ftp://rmm.x.test", "rmm.x.test", "https://rmm.x.test:notaport", "https://a b.test", "https://[bad", 443, None,
            "^https://.*\\.x\\.test$"]:
    must(consumers.normal_origin(raw) is None, f"normal_origin({raw!r}) is not a plain origin")

# ------------------------------------------------------------------------------------------------ 3. refusals that stay refused
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
bad = connect(ticket, host="api.x.test", origin="https://evil.example")
must(bad.group_name is None and CLOSED == [4003], "a foreign Origin closes 4003 even with a whitelist")
reset()
must(not consumers.origin_allowed(headers(host="api.x.test", origin="http://rmm.x.test")), "a different scheme is refused")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://evil.example")), "a foreign Origin is refused")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="null")), "an Origin of null is refused")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="")), "an empty Origin is refused")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://[bad")), "a malformed Origin is refused")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test:notaport")), "an Origin with a bad port is refused")

# ------------------------------------------------------------------------------------------------ 4. default ports and case
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test:443")), "https://rmm.x.test:443 equals https://rmm.x.test")
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://RMM.x.test")), "the comparison ignores case")
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test:443"])
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a whitelist entry with the default port equals the bare origin")
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test:8443"])
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a non-default port is a different origin")
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test:8443")), "the same non-default port is accepted")

# ------------------------------------------------------------------------------------------------ 5. entries that never match
for entry in ["https://rmm.x.test/app", "*", "null", 443, "https://rmm.x.test?x=1", "https://rmm.x.test#f", "^https://.*\\.x\\.test$",
              "", None, ["https://rmm.x.test"]]:
    use_settings(CORS_ORIGIN_WHITELIST=[entry])
    must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), f"whitelist entry {entry!r} never matches")
use_settings(CORS_ORIGIN_WHITELIST="https://rmm.x.test")
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a whitelist that is text, not a list, is ignored")
use_settings(CORS_ORIGIN_WHITELIST=443)
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a whitelist that is a number is ignored")
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://anything.x.test")), "a regular expression never matches other origins")

# ------------------------------------------------------------------------------------------------ 6. empty, missing and failing settings
use_settings(CORS_ORIGIN_WHITELIST=[])
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "an empty whitelist gives no frontend origin")
must(consumers.origin_allowed(headers(host="rmm.x.test", origin="https://rmm.x.test")), "an empty whitelist keeps the same-host rule")
use_settings()
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a missing whitelist gives no frontend origin")
must(consumers.origin_allowed(headers(host="rmm.x.test", origin="https://rmm.x.test")), "a missing whitelist keeps the same-host rule")
use_broken_settings()
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test")), "a settings read that raises gives no frontend origin")
must(consumers.origin_allowed(headers(host="rmm.x.test", origin="https://rmm.x.test")), "a settings read that raises keeps the same-host rule")
must(consumers.configured_frontend_origins() == set(), "a settings read that raises reads as an empty list")

# ------------------------------------------------------------------------------------------------ 7. values the request supplies
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://evil.example", extra=[
    (b"x-forwarded-host", b"evil.example"), (b"x-frontend-origin", b"https://evil.example")])),
    "an Origin that only the request's own headers name is refused")
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://rmm.x.test", extra=[(b"x-forwarded-host", b"evil.example")])),
     "a forwarded host header does not change the frontend list")

# ------------------------------------------------------------------------------------------------ 8. no Origin, no Host
use_settings(CORS_ORIGIN_WHITELIST=["https://rmm.x.test"])
must(consumers.origin_allowed({"headers": [(b"host", b"api.x.test")]}), "no Origin is allowed")
must(consumers.origin_allowed({"headers": []}), "no headers at all is allowed (no Origin)")
must(not consumers.origin_allowed({"headers": [(b"origin", b"https://evil.example")]}), "an Origin with no Host and no match is refused")
must(consumers.origin_allowed({"headers": [(b"origin", b"https://rmm.x.test")]}), "an Origin with no Host is accepted when the whitelist names it")

# ------------------------------------------------------------------------------------------------ 9. CORS_ALLOWED_ORIGINS
use_settings(CORS_ORIGIN_WHITELIST=[], CORS_ALLOWED_ORIGINS=["https://ui.x.test"])
must(consumers.origin_allowed(headers(host="api.x.test", origin="https://ui.x.test")), "CORS_ALLOWED_ORIGINS is read when present")
use_settings(CORS_ORIGIN_WHITELIST=[], CORS_ALLOW_ALL_ORIGINS=True)
must(not consumers.origin_allowed(headers(host="api.x.test", origin="https://evil.example")), "CORS_ALLOW_ALL_ORIGINS is ignored")

# ------------------------------------------------------------------------------------------------ 10. the contract text
close_codes = ws.tactical_websocket_contract_metadata()["close_codes"]
must("CORS_ORIGIN_WHITELIST" in close_codes["4003"] and "frontend origin" in close_codes["4003"],
     "the 4003 contract text names the frontend origin in CORS_ORIGIN_WHITELIST")

sys.modules.pop(DJANGO_CONF, None)
print("tactical-websocket-origin-1.17.32: ok")
