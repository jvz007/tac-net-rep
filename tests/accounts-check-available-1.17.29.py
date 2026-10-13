#!/usr/bin/env python3
"""1.17.29 regression: core.accounts check_available (binding entry, User Invite: check_available for username and email).

Uses the stub harness of tests/accounts-contract-1.17.27.py (its text up to the create_user section runs here), so the real
tec_tac/accounts.py runs against an in-memory user table. Covered: free; username taken and email taken, ignoring case; both taken gives
username_taken with both flags; blank, over-long, control-character and malformed input; a caller that is not on the list, is unverified or
is another module raises CallerNotAllowed and runs no query; no audit row, no write, no transaction; the answer holds no user id or name;
the capability exports check_available at 1.2.0 (since 1.17.30, with invited_by_id) with its metadata; the contract row and docs name it; the accepted decisions are cited (AD-31).
"""
# ruff: noqa: F821  (names come from the shared harness that is exec'd below)
from __future__ import annotations

import ast
import re
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


def snapshot():
    return len(USERS), len(AUDITS), len(MESH_CALLS), DEPTH[0], PENDING[:]


# ---- free, taken ---------------------------------------------------------------------------------------------------------------------
reset()
QUERIES.clear()
before = snapshot()
free = accounts.check_available("new.person", "new.person@example.co.za", 3)
must(type(free).__name__ == "Availability" and set(free.__dataclass_fields__) == {"status", "username_taken", "email_taken"}, "frozen result keys")
must(free.status == "free" and free.username_taken is False and free.email_taken is False, free)
must(snapshot() == before and not AUDITS, "a read: no write, no audit row, no queue")
must(QUERIES and all("username__iexact" in q or "email__iexact" in q or "pk" in q for q in QUERIES), QUERIES)  # pk: the inviter re-check (1.17.30)

reset()
r = accounts.check_available("TECH", "new.person@example.co.za", 3)
must(r.status == "username_taken" and r.username_taken is True and r.email_taken is False, r)
reset()
r = accounts.check_available("new.person", "TECH@TechXFlow.co.za", 3)
must(r.status == "email_taken" and r.username_taken is False and r.email_taken is True, r)
reset()
r = accounts.check_available("Boss", "BOSS@techxflow.co.za", 3)
must(r.status == "username_taken" and r.username_taken and r.email_taken, "both taken: username_taken first, both flags")

# ---- no user detail ------------------------------------------------------------------------------------------------------------------
reset()
r = accounts.check_available("tech", "tech@techxflow.co.za", 3)
text = repr(r) + repr(r.__dict__)
must("10" not in {str(v) for v in r.__dict__.values()} and "Tech" not in text and "Two" not in text and "pk" not in text, text)
must(not hasattr(r, "user_id") and not hasattr(r, "id"), "no id")
must(not AUDITS and not MESH_CALLS, "no audit row, no mesh sync")

# ---- input --------------------------------------------------------------------------------------------------------------------------
for username, email in (("", "a@b.co"), ("x" * 151, "a@b.co"), ("bad\x07name", "a@b.co"), ("bad name!", "a@b.co"), ("ok.name", ""),
                        ("ok.name", "not-an-email"), ("ok.name", "a\x07@b.co"), ("ok.name", "x" * 250 + "@b.co"), (None, "a@b.co"), ("ok.name", None), (7, "a@b.co")):
    reset()
    try:
        accounts.check_available(username, email, 3)
    except accounts.InvalidInput as exc:
        must(exc.code == "invalid_input", exc.code)
    else:
        raise AssertionError(f"expected invalid_input for {username!r}, {email!r}")

# ---- caller -------------------------------------------------------------------------------------------------------------------------
for who in (None, SimpleNamespace(module_id="alerts", kind="module", module_version="1.0.0"),
            SimpleNamespace(module_id="core", kind="module", module_version="1.0.0")):
    reset()
    CALLER["value"] = who
    QUERIES.clear()
    try:
        accounts.check_available("tech", "tech@techxflow.co.za", 3)
    except accounts.CallerNotAllowed as exc:
        must(exc.code == "caller_not_allowed", exc.code)
    else:
        raise AssertionError(f"expected caller_not_allowed for {who!r}")
    must(not QUERIES, "a refused caller runs no query")
must(ARGS and all(Path(a).name == "accounts.py" for a in ARGS), ARGS)  # the provider passes its own file to the caller check

# a disabled module: the real helper gives None, which is the unverified case above (tests/caller-identity-core-provider-1.17.27.py)

# ---- capability, metadata, rows, docs ------------------------------------------------------------------------------------------------
meta = accounts.accounts_contract_metadata()
must(meta["version"] == "1.2.0" and accounts.CAPABILITY_VERSION == "1.2.0", meta["version"])  # 1.17.30: invited_by_id
must(meta["operations"] == ["create_user", "list_grantable_roles", "check_available"], meta["operations"])
must(meta["availability_statuses"] == ["username_taken", "email_taken", "free"], meta)
must("AD-31" in meta["accepted_decisions"] and "AD-31" in meta["limits"] and "AD-31" in meta["check_available"], meta)
must("AD-34" in meta["accepted_decisions"] and "AD-34" in meta["check_available"], meta)
must(callable(accounts._PROVIDER.check_available), "provider exports check_available")
caps_src = (APP / "accounts.py").read_text(encoding="utf-8")
must('operations=("create_user", "list_grantable_roles", "check_available")' in caps_src, "registered with the operation")
must("AD-31" in caps_src.split('"""', 2)[1], "module docstring cites AD-31 and condition 5")
must("AD-31 condition 5" in caps_src.split('"""', 2)[1], "module docstring cites AD-31 condition 5")

contracts_tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
core_rows = next(ast.literal_eval(n.value) for n in contracts_tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
row = next(r for r in core_rows if r["area"] == "accounts" and r["name"] == "check_available")
must(row["import_path"] == "tec_tac.accounts" and "core.accounts 1.2.0" in row["purpose"] and "AD-31" in row["purpose"] and "limits each inviter" in row["purpose"], row)

docs = (ROOT / "docs" / "accounts-contract.md").read_text(encoding="utf-8")
for needle in ("check_available", "Availability", "username_taken", "email_taken", "rate limit", "signed-in create step", "AD-31", "condition 5", "1.17.29"):
    must(needle in docs, f"docs/accounts-contract.md names {needle}")

# ---- the accepted decisions are cited (small item, release 1.17.29) --------------------------------------------------------------
contracts_text = (APP / "contracts.py").read_text(encoding="utf-8")
tactical_ops = (ROOT / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
audit_lists = tactical_ops[tactical_ops.index("`audit_lists`"):]
must("AD-32" in audit_lists[:3000], "docs/tactical-operations.md names AD-32 in the audit_lists section")
must("AD-32" in contracts_text and re.search(r"audit_lists[^\n]{0,4000}AD-32|AD-32[^\n]{0,4000}audit_lists", contracts_text), "contract text names AD-32 with audit_lists")
sso = (ROOT / "docs" / "sso-admin.md").read_text(encoding="utf-8")
must("AD-33" in sso, "docs/sso-admin.md names AD-33")

print("accounts check_available 1.17.29: ok")
