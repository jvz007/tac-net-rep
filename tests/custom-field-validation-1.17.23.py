#!/usr/bin/env python3
"""1.17.23 regression: custom-field ids are validated as positive whole numbers before anything is created or saved.

The adapter's own ``int()`` took ``True`` and ``1.5`` as 1, and ``'abc'`` or ``None`` raised a bare ValueError (a 500) inside
``_custom_field_ids`` after the create. ``_clean_custom_fields`` now refuses every id that is not a real int of 1 or more or a string
of ASCII digits that is at least 1, with the plain text 'field_id must be a positive whole number.', and stores the cleaned int
back. create_client, create_site and update_custom_fields share the helper. Runs the real resources.py and resources_adapter.py on
the in-memory Tactical of tests/resource-alert-template-1.17.17.py with the custom-field stand-ins of
tests/resource-create-client-site-1.17.22.py (this test fails on 1.17.22).
"""
from __future__ import annotations

import pathlib

_here = pathlib.Path(__file__).resolve().parent
_base = _here / "resource-create-client-site-1.17.22.py"
_source = _base.read_text(encoding="utf-8")
# the 1.17.22 harness: everything before its first numbered scenario
exec(compile(_source[: _source.index("# 1. the first site's name is used")], str(_base), "exec"), globals())  # noqa: S102 - test-only reuse
H = globals()
must, resources, adapter, Site, Client, User, Role, AUDITS, ctx_for, refused, fresh, FIELD_DEFS, SAVED = (
    H[k] for k in ("must", "resources", "adapter", "Site", "Client", "User", "Role", "AUDITS", "ctx_for", "refused", "fresh", "FIELD_DEFS", "SAVED"))

TEXT = "field_id must be a positive whole number."
BAD_IDS = ["abc", 1.5, True, False, None, 0, -3, [1], {}, "1.5", " 1", "1 ", "-1", "0", "", "\u0663", 2**63, "9" * 40, 2.0, b"1"]

admin = User(Role())


def counting(name):
    """Count calls to an adapter function, so a refusal can be shown to stop before it."""
    real = getattr(adapter, name)
    calls = []

    def wrapper(*a, **k):
        calls.append(1)
        return real(*a, **k)
    setattr(adapter, name, wrapper)
    return calls, lambda: setattr(adapter, name, real)


# ---- create_client: every bad id is a ValidationError, no row, no save, the adapter is not called
for bad in BAD_IDS:
    fresh()
    calls, restore = counting("create_client_row")
    try:
        audits_before = len(AUDITS)
        exc = refused(lambda bad=bad: resources.create_client(name="Probe", site_name="P1", custom_fields=[{"field_id": bad, "value": "x"}], context=ctx_for(admin)),
                      resources.ResourceValidationError)
        must(str(exc) == TEXT, f"{bad!r}: {exc}")
        must(not calls, f"{bad!r}: the adapter was called")
        must(len(AUDITS) == audits_before and not SAVED, f"{bad!r}: no audit row, nothing saved")
        must(not any(r["name"] == "Probe" for r in Client.STORE.values()), f"{bad!r}: nothing created")
    finally:
        restore()

# ---- create_site
for bad in BAD_IDS:
    fresh()
    calls, restore = counting("create_site_row")
    try:
        audits_before = len(AUDITS)
        sites_before = len(Site.STORE)
        exc = refused(lambda bad=bad: resources.create_site(client_id=1, name="Probe", custom_fields=[{"field_id": bad, "value": "x"}], context=ctx_for(admin)),
                      resources.ResourceValidationError)
        must(str(exc) == TEXT, f"{bad!r}: {exc}")
        must(not calls and len(AUDITS) == audits_before and not SAVED and len(Site.STORE) == sites_before, f"{bad!r}: nothing written")
    finally:
        restore()

# ---- update_custom_fields: the same rule, before the adapter reads or writes anything
for bad in BAD_IDS:
    fresh()
    read_calls, restore_read = counting("custom_field_rows")
    write_calls, restore_write = counting("update_custom_field_rows")
    try:
        audits_before = len(AUDITS)
        exc = refused(lambda bad=bad: resources.update_custom_fields("client", 1, values=[{"field_id": bad, "value": "x"}], context=ctx_for(admin)),
                      resources.ResourceValidationError)
        must(str(exc) == TEXT, f"{bad!r}: {exc}")
        must(not read_calls and not write_calls and len(AUDITS) == audits_before and not SAVED, f"{bad!r}: nothing read, saved or audited")
    finally:
        restore_read()
        restore_write()
# a values list that is not a list, or None, is refused too
fresh()
for bad in (None, "x", {"field_id": 1, "value": "x"}):
    refused(lambda bad=bad: resources.update_custom_fields("site", 11, values=bad, context=ctx_for(admin)), resources.ResourceValidationError)

# ---- good ids: 3 and '3' (and a string with a leading zero) succeed; the cleaned int is what the adapter and the audit see
fresh()
FIELD_DEFS[3].hide_in_ui = False
FIELD_DEFS[3].model = "client"
for index, good in enumerate((3, "3", "03")):
    SAVED.clear()
    made = resources.create_client(name=f"Good{index}", site_name="G1", custom_fields=[{"field_id": good, "value": "v"}], context=ctx_for(admin))
    must(any(r[0] == "client" and r[1] == made["id"] and r[2] == 3 for r in SAVED), (good, SAVED))
    must(AUDITS[-1]["metadata"]["custom_field_ids"] == [3], AUDITS[-1])
    must(all(type(i) is int for i in AUDITS[-1]["metadata"]["custom_field_ids"]), "ids are ints in the audit row")
cleaned = resources._clean_custom_fields([{"field_id": "7", "value": "x"}, {"field_id": 8, "value": True}])
must(cleaned == [{"field_id": 7, "value": "x"}, {"field_id": 8, "value": True}] and all(type(c["field_id"]) is int for c in cleaned), cleaned)
must(resources._custom_field_ids(cleaned) == [7, 8], "_custom_field_ids cannot raise on cleaned input")
must(resources._clean_custom_fields(None) is None, "None stays None")

# ---- a duplicate id is still refused by the adapter, and a bad shape by the shape rule
fresh()
refused(lambda: resources.create_client(name="Dup", site_name="D1", custom_fields=[{"field_id": 1, "value": "a"}, {"field_id": "1", "value": "b"}], context=ctx_for(admin)),
        resources.ResourceValidationError)
must(not any(r["name"] == "Dup" for r in Client.STORE.values()), "the duplicate create was rolled back")
refused(lambda: resources.create_client(name="Shape", site_name="S1", custom_fields=[{"field_id": 1}], context=ctx_for(admin)), resources.ResourceValidationError)
refused(lambda: resources.create_client(name="Shape", site_name="S1", custom_fields=[1], context=ctx_for(admin)), resources.ResourceValidationError)

# ---- the caller's list is not changed
mine = [{"field_id": "1", "value": "AC"}]
resources.create_client(name="Mine", site_name="M1", custom_fields=mine, context=ctx_for(admin))
must(mine == [{"field_id": "1", "value": "AC"}], "the caller's list is untouched")

print("[TEST] PASS custom field validation 1.17.23")
