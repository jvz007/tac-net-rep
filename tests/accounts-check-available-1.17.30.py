#!/usr/bin/env python3
"""1.17.30 regression (AD-34 condition 4): core.accounts check_available takes invited_by_id, re-checks the inviter and has a Core limit.

Uses the stub harness of tests/accounts-contract-1.17.27.py (its text up to the create_user section runs here, with a stub django.core.cache
that expires keys on a clock the test moves), so the real tec_tac/accounts.py runs against an in-memory user table.

Covered: free, username_taken, email_taken and both answer as in 1.17.29 for an allowed inviter; a missing, inactive, installer-user and
no-can_manage_accounts inviter raises inviter_not_allowed, runs no clash query and is not counted; a superuser inviter is allowed; a bad or bool
invited_by_id raises invalid_input; a refused caller raises caller_not_allowed before any lookup or count; the 31st call in the window raises
rate_limited, another inviter is unaffected, the counter resets after the window, the daily cap holds, a cache that raises gives
rate_check_unavailable and answers nothing; the cache key holds no username or email; no audit row, no write; the version, metadata, contract
row and docs.
"""
# ruff: noqa: F821  (names come from the shared harness that is exec'd below)
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "accounts-contract-1.17.27.py"
_src = HARNESS.read_text(encoding="utf-8")
_head = _src[: _src.index("# ---- create_user: happy path")]
exec(compile(_head, str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

QUERIES: list = []
_real_filter = User.objects.filter


def _counting_filter(**kw):
    QUERIES.append(kw)
    return _real_filter(**kw)


User.objects.filter = _counting_filter  # a spy on every lookup; reads only

NAME, MAIL = "new.person", "new.person@example.co.za"
WINDOW, DAY = accounts.CHECK_WINDOW_LIMIT, accounts.CHECK_DAY_LIMIT


def clash_queries():
    return [q for q in QUERIES if "username__iexact" in q or "email__iexact" in q]


def refuses(code, *args, **kwargs):
    reset()
    return refuses_now(code, *args, **kwargs)


def refuses_now(code, *args, **kwargs):
    QUERIES.clear()
    try:
        accounts.check_available(*args, **kwargs)
    except accounts.AccountsError as exc:
        must(exc.code == code, f"expected {code}, got {exc.code}: {exc.message}")
        return exc
    raise AssertionError(f"expected {code}, the call was answered")


def counters(inviter_id):
    return CACHE.data.get(f"{accounts.CHECK_CACHE_PREFIX}{inviter_id}:window"), CACHE.data.get(f"{accounts.CHECK_CACHE_PREFIX}{inviter_id}:day")


# ---- constants and the new errors ---------------------------------------------------------------------------------------------------------
must((WINDOW, accounts.CHECK_WINDOW_SECONDS, DAY, accounts.CHECK_DAY_SECONDS) == (30, 600, 300, 86400), "30 per 10 minutes, 300 per day")
must(accounts.RateLimited.code == "rate_limited" and accounts.RateCheckUnavailable.code == "rate_check_unavailable", "codes")
must(issubclass(accounts.RateLimited, accounts.AccountsError) and issubclass(accounts.RateCheckUnavailable, accounts.AccountsError), "typed errors")
must("rate_limited" in accounts.ERROR_CODES and "rate_check_unavailable" in accounts.ERROR_CODES, accounts.ERROR_CODES)

# ---- the 1.17.29 answers, for an allowed inviter -------------------------------------------------------------------------------------------
reset()
before = (len(USERS), len(AUDITS), len(MESH_CALLS), DEPTH[0], PENDING[:])
free = accounts.check_available(NAME, MAIL, 3)
must(free.status == "free" and free.username_taken is False and free.email_taken is False, free)
must((len(USERS), len(AUDITS), len(MESH_CALLS), DEPTH[0], PENDING[:]) == before and not AUDITS, "a read: no write, no audit row, no queue")
must(accounts.check_available("TECH", MAIL, 3).status == "username_taken", "username, ignoring case")
must(accounts.check_available(NAME, "TECH@TechXFlow.co.za", 3).status == "email_taken", "email, ignoring case")
both = accounts.check_available("Boss", "BOSS@techxflow.co.za", 3)
must(both.status == "username_taken" and both.username_taken and both.email_taken, "both: username_taken first, both flags")
must(accounts.check_available(NAME, MAIL, invited_by_id=3).status == "free", "keyword form")
must(accounts.check_available(username=NAME, email=MAIL, invited_by_id=15).status == "free", "a superuser inviter is allowed")
must(not hasattr(free, "user_id") and not hasattr(free, "id"), "no id in the answer")
try:
    accounts.check_available(NAME, MAIL)
    raise AssertionError("invited_by_id is required")
except TypeError:
    pass

# ---- the inviter re-check ----------------------------------------------------------------------------------------------------------------
for inviter, label in ((999, "missing"), (12, "inactive"), (13, "installer user"), (14, "no can_manage_accounts"), (10, "technician role"),
                       (16, "no role")):
    exc = refuses("inviter_not_allowed", NAME, MAIL, inviter)
    must(not clash_queries(), f"{label}: no clash query runs")
    must(counters(inviter) == (None, None), f"{label}: not counted against the limit")
    must("jane" not in exc.message and NAME not in exc.message and MAIL not in exc.message, "no name in the message")
    must(not AUDITS, f"{label}: no audit row")
# an inviter demoted since: the role loses the flag
reset()
ROLES[3].can_manage_accounts = False
refuses_now("inviter_not_allowed", NAME, MAIL, 3)

# ---- input and caller order -----------------------------------------------------------------------------------------------------------------
for bad in (True, False, 0, -1, "3", None, 1.5, [3]):
    refuses("invalid_input", NAME, MAIL, bad)
    must(not clash_queries() and counters(3) == (None, None), f"invited_by_id {bad!r}: nothing looked up or counted")
for username, email in (("", MAIL), ("x" * 151, MAIL), ("bad name!", MAIL), (NAME, ""), (NAME, "not-an-email"), (None, MAIL), (NAME, None)):
    refuses("invalid_input", username, email, 3)
    must(counters(3) == (None, None), "bad text is not counted")
for who in (None, SimpleNamespace(module_id="alerts", kind="module", module_version="1.0.0"), SimpleNamespace(module_id="core", kind="module", module_version="1")):
    reset()
    CALLER["value"] = who
    refuses_now("caller_not_allowed", NAME, MAIL, 3)
    refuses_now("caller_not_allowed", NAME, MAIL, 999)  # the caller is judged before the inviter, so a refused caller learns nothing about ids
    must(not QUERIES and counters(3) == (None, None), "a refused caller runs no query and is not counted")
must(ARGS and all(Path(a).name == "accounts.py" for a in ARGS), ARGS)

# ---- the Core limit ------------------------------------------------------------------------------------------------------------------
reset()
for index in range(WINDOW):
    accounts.check_available(f"user{index}", f"user{index}@example.co.za", 3)
must(counters(3)[0][0] == WINDOW and counters(3)[1][0] == WINDOW, counters(3))
exc = refuses_now("rate_limited", NAME, MAIL, 3)
must(not clash_queries(), "the limited call runs no clash query")
must(not any(ch.isdigit() for ch in exc.message) and NAME not in exc.message and "3" not in exc.message.split(), f"no counts or names: {exc.message}")
refuses_now("rate_limited", NAME, MAIL, 3)  # still limited
must(not AUDITS, "a limit hit writes no audit row")
# a different inviter is unaffected
must(accounts.check_available(NAME, MAIL, 15).status == "free", "another inviter is not limited")
# the window resets
CACHE.now += accounts.CHECK_WINDOW_SECONDS + 1
must(accounts.check_available(NAME, MAIL, 3).status == "free", "the counter resets after the window")
must(counters(3)[0][0] == 1, counters(3))
# the daily cap holds across windows
reset()
answered = 0
for _window in range(20):
    for _ in range(WINDOW):
        if answered >= DAY:
            break
        accounts.check_available(NAME, MAIL, 3)
        answered += 1
    CACHE.now += accounts.CHECK_WINDOW_SECONDS + 1
    if answered >= DAY:
        break
must(answered == DAY, answered)
refuses_now("rate_limited", NAME, MAIL, 3)  # a fresh window, but the day is used up
CACHE.now += accounts.CHECK_DAY_SECONDS + 1
must(accounts.check_available(NAME, MAIL, 3).status == "free", "the day resets")

# the cache key holds no username or email
reset()
accounts.check_available("secret.name", "secret.name@example.co.za", 3)
keys = list(CACHE.data)
must(keys and all(k.startswith("tec_tac:accounts:check_available:3:") for k in keys), keys)
must(all("secret" not in k and "@" not in k and "example" not in k for k in keys), keys)

# a cache that raises fails closed and answers nothing
reset()
CACHE.down = True
exc = refuses_now("rate_check_unavailable", NAME, MAIL, 3)
must(not clash_queries(), "a failing counter answers nothing")
must(NAME not in exc.message and MAIL not in exc.message, "no name in the message")
CACHE.down = False
must(accounts.check_available(NAME, MAIL, 3).status == "free", "the cache is back")

# an expiry between add and incr is handled (the key counts as the first call)
reset()


real_incr = CACHE.incr
state = {"first": True}


def racy_incr(key):
    if state["first"]:
        state["first"] = False
        CACHE.data.pop(key, None)  # the key expired between add and incr
    return real_incr(key)


CACHE.incr = racy_incr
must(accounts.check_available(NAME, MAIL, 3).status == "free", "an expired key is not an error")
CACHE.incr = real_incr

# ---- the other contract calls are unchanged ------------------------------------------------------------------------------------------------
reset()
created = accounts.create_user(**invite_args())
must(created.username == "jane.doe" and len(AUDITS) == 1, "create_user is unchanged and not rate limited")
must([r["name"] for r in accounts.list_grantable_roles(USERS[3])] == ["Account Manager", "Auditor", "Technician"], "list_grantable_roles is unchanged")
must(not CACHE.data, "create_user and list_grantable_roles never touch the cache")

# ---- version, metadata, rows, docs ---------------------------------------------------------------------------------------------------------
meta = accounts.accounts_contract_metadata()
must(meta["version"] == "1.2.0" and accounts.CAPABILITY_VERSION == "1.2.0", meta["version"])
must(meta["requires_framework"] == ">=1.17.27 (check_available: >=1.17.30, with invited_by_id)", meta["requires_framework"])
must("invited_by_id" in meta["check_available"] and "can_manage_accounts" in meta["check_available"] and "30 answered calls per 10 minutes" in meta["check_available"], meta["check_available"])
must("300 per day" in meta["limits"] and "AD-34" in meta["limits"] and "AD-34" in meta["accepted_decisions"], meta)
must(meta["check_available_limits"] == {"per_window": 30, "window_seconds": 600, "per_day": 300}, meta)
must("rate_limited" in meta["errors"] and "rate_check_unavailable" in meta["errors"] and meta["errors"] == list(accounts.ERROR_CODES), meta["errors"])
source = (APP / "accounts.py").read_text(encoding="utf-8")
must("AD-34 condition 4" in source.split('"""', 2)[1], "module docstring cites AD-34 condition 4")
must("AD-34 condition 4" in source.split("def check_available", 1)[1].split('"""', 2)[1], "function docstring cites AD-34 condition 4")

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
row = next(r for r in rows if r["area"] == "accounts" and r["name"] == "check_available")
for word in ("invited_by_id", "core.accounts 1.2.0", ">=1.17.30", "AD-34 condition 4", "inviter_not_allowed", "30 answered calls per 10 minutes and 300 per day",
             "rate_limited", "rate_check_unavailable", "stricter", "Johan may relax"):
    must(word in row["purpose"], f"the contract row names {word}")
docs = (ROOT / "docs" / "accounts-contract.md").read_text(encoding="utf-8")
for word in ("core.accounts` 1.2.0", "invited_by_id", "can_manage_accounts", "rate_limited", "rate_check_unavailable", "30 answered calls per 10 minutes and 300 per day",
             "AD-34 condition 4", "keeps its own", "Johan may relax", "1.17.30"):
    must(word in docs, f"docs/accounts-contract.md names {word}")
for code in accounts.ERROR_CODES:
    must(f"`{code}`" in docs, f"docs name the error {code}")

print("accounts check_available 1.17.30: ok")
