#!/usr/bin/env python3
"""Regression: Core 1.18.58. The runtime setting console_ui_url (the Tec-Tac web address the Engineer Console opens), and migration 0052 against the models.

Real Django on a temporary SQLite file and the real runtime_settings.py view, in the style of console-certificates-setting-1.18.52.py. The migration is
checked two ways: an AST pass that compares it with models.py (always), and, where Django is importable, Django's own autodetector, which must find
nothing left to migrate once 0052's operations are applied to the state before it. The validator accepts https://host, https://host:8443/tec-tac and
refuses http, ftp, user info, a query, a fragment, any other path, more than 300 characters, non-text and bool; null and empty text reset; a person
without superuser gets 403 and a deny row before any value is looked at; a mixed body saves nothing; one strict audit row per change, and a failed
audit write rolls the change back; the serialised value and its default.
"""
import ast
import importlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of = harness.must, harness.rows_of

SETTING = "console_ui_url"

# ---- AST: the migration matches the model (always runs)
models_tree = ast.parse((APP / "models.py").read_bytes().decode("utf-8"))
runtime = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacRuntimeConfig")
field = next(s for s in runtime.body if isinstance(s, ast.Assign) and s.targets[0].id == SETTING).value
must(ast.unparse(field) == "models.CharField(max_length=300, blank=True, default='')", ast.unparse(field))
migration_path = APP / "migrations" / "0052_console_ui_url.py"
source = migration_path.read_text(encoding="utf-8")
tree = ast.parse(source)
adds = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "AddField"]
must(len(adds) == 1, "0052 has exactly one AddField")
kw = {k.arg: ast.unparse(k.value) for k in adds[0].keywords}
must(kw["model_name"] == "'tectacruntimeconfig'" and kw["name"] == "'console_ui_url'", kw)
must(kw["field"] == "models.CharField(blank=True, default='', max_length=300)", kw["field"])
must('("tec_tac", "0051_console_enrolment_pkce")' in source and source.count("dependencies = [") == 1, "0052 depends on 0051 only")
must(len(list((APP / "migrations").glob("0052_*.py"))) == 1 and not list((APP / "migrations").glob("0053_*.py")), "0052 is the only new migration")
must(b"\r" not in migration_path.read_bytes(), "LF like 0051")
must(source.startswith("from django.db import migrations, models"), "the shape of its neighbours")
for forbidden in ("check", "delete", "save", "clean"):
    must(forbidden != SETTING, "no shadowing name")

h = harness.boot()
if h is None:
    print("console ui url setting 1.18.58 regression: PASS (AST branch only: Django is not installed)")
    sys.exit(0)

from django.apps import apps  # noqa: E402
from django.db.migrations.autodetector import MigrationAutodetector  # noqa: E402
from django.db.migrations.state import ProjectState  # noqa: E402

current = ProjectState.from_apps(apps)
before = current.clone()
before.models[("tec_tac", "tectacruntimeconfig")].fields.pop(SETTING)
mig = importlib.import_module("tec_tac.migrations.0052_console_ui_url").Migration
state = before.clone()
for op in mig.operations:
    op.state_forwards("tec_tac", state)
changes = MigrationAutodetector(state, current)._detect_changes()
leftover = {app: [(m.name, [type(o).__name__ + ":" + str(getattr(o, "name", getattr(o, "model_name", ""))) for o in m.operations]) for m in ms] for app, ms in changes.items() if app == "tec_tac"}
must(not leftover, f"0052 and the models disagree (makemigrations would still write): {leftover}")
must(mig.dependencies == [("tec_tac", "0051_console_enrolment_pkce")], "0052 depends on 0051 only")
with h.connection.schema_editor(collect_sql=True, atomic=False) as editor:
    target = before.clone()
    for op in mig.operations:
        op.state_forwards("tec_tac", target)
        op.database_forwards("tec_tac", editor, before, target)
must("console_ui_url" in "\n".join(editor.collected_sql), "the new column")

# ---- the validator
from rest_framework.test import APIRequestFactory, force_authenticate  # noqa: E402
from tec_tac import runtime_settings as rs  # noqa: E402

for good, expected in (
    ("https://rmm.example.com", "https://rmm.example.com/tec-tac/"),
    ("https://rmm.example.com/", "https://rmm.example.com/tec-tac/"),
    ("https://rmm.example.com/tec-tac", "https://rmm.example.com/tec-tac/"),
    ("https://rmm.example.com/tec-tac/", "https://rmm.example.com/tec-tac/"),
    ("https://rmm.example.com:8443/tec-tac", "https://rmm.example.com:8443/tec-tac/"),
    ("https://RMM.Example.com", "https://rmm.example.com/tec-tac/"),
    ("HTTPS://rmm.example.com", "https://rmm.example.com/tec-tac/"),
    ("https://rmm.example.com:443", "https://rmm.example.com/tec-tac/"),
    ("  https://rmm.example.com/tec-tac/  ", "https://rmm.example.com/tec-tac/"),
    ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443/tec-tac/"),
    ("https://10.1.2.3", "https://10.1.2.3/tec-tac/"),
):
    must(rs.validate_console_ui_url(good) == expected, f"{good!r} gives {rs.validate_console_ui_url(good)!r}")
must(rs.validate_console_ui_url(expected) == expected, "a stored value validates to itself")
for blank in ("", "   "):
    must(rs.validate_console_ui_url(blank) == "", f"{blank!r} resets")
for bad in ("http://rmm.example.com", "ftp://rmm.example.com", "rmm.example.com", "//rmm.example.com", "https://", "https:///tec-tac/", "https://user@rmm.example.com",
            "https://user:pw@rmm.example.com", "https://rmm.example.com/tec-tac/?a=1", "https://rmm.example.com?a=1", "https://rmm.example.com/#/console", "https://rmm.example.com#x",
            "https://rmm.example.com/other/", "https://rmm.example.com/tec-tac/extra", "https://rmm.example.com/TEC-TAC/", "https://rmm.example.com//", "https://rmm.example.com:notaport",
            "https://rmm.example.com:99999", "https://rmm example.com", "https://rmm.example.com\\tec-tac", "javascript:alert(1)", "https://rmm.example.com/tec-tac/%2e%2e/",
            "https://" + "a" * 290 + ".com", "https://rmm.example.com/" + "a" * 300, 5, 5.5, True, False, ["https://rmm.example.com"], {"u": "https://rmm.example.com"}, b"https://rmm.example.com"):
    try:
        got = rs.validate_console_ui_url(bad)
    except rs.RuntimeSettingsError:
        continue
    raise AssertionError(f"{bad!r} must be refused, got {got!r}")
must(len(rs.validate_console_ui_url("https://" + "a" * 60 + ".example.com")) <= 300, "a long but valid host is accepted within the limit")
try:
    rs.validate_console_ui_url("https://" + "a" * 285 + ".example.com")
    raise AssertionError("301 characters or more must be refused")
except rs.RuntimeSettingsError:
    pass
exact = "https://" + "a" * (300 - len("https://") - len(".com")) + ".com"
must(len(exact) == 300, "a 300 character input")
try:
    rs.validate_console_ui_url(exact)
    raise AssertionError("an input of 300 characters whose stored form would pass 300 is refused")
except rs.RuntimeSettingsError:
    pass
must(SETTING in rs.RUNTIME_SETTING_NAMES and SETTING in rs._TEXT_SETTINGS and rs.MAX_CONSOLE_UI_URL_LENGTH == 300, "the name is registered as a text setting")

# ---- the route
h.reset()
M = h.models
superuser = h.new_user("root", superuser=True)
manager = h.new_user("manager", perms=("core.runtime_settings.manage",))
factory = APIRequestFactory()


def get():
    request = factory.get("/api/tfd/system/runtime-settings/")
    force_authenticate(request, user=manager)
    return rs.RuntimeSettingsView.as_view()(request)


def patch(user, body):
    h.cache.clear()  # the write throttle is 10 a minute per person
    request = factory.patch("/api/tfd/system/runtime-settings/", body, format="json")
    force_authenticate(request, user=user)
    return rs.RuntimeSettingsView.as_view()(request)


must(get().data[SETTING] == {"value": "", "maximum_length": 300, "default": ""}, f"GET shows the unset value: {get().data[SETTING]}")
must(rs.read_console_ui_url_setting() == "", "unset reads as empty text")
r = patch(superuser, {SETTING: "https://rmm.example.com:8443/tec-tac"})
must(r.status_code == 200 and r.data[SETTING]["value"] == "https://rmm.example.com:8443/tec-tac/", f"{r.status_code} {getattr(r, 'data', '')}")
must(M.TecTacRuntimeConfig.current().console_ui_url == "https://rmm.example.com:8443/tec-tac/" and rs.read_console_ui_url_setting() == "https://rmm.example.com:8443/tec-tac/", "stored normalised")
for bad in ("http://rmm.example.com", "ftp://rmm.example.com", "https://u@rmm.example.com", "https://rmm.example.com/?q=1", "https://rmm.example.com/#f", "https://rmm.example.com/x/",
            "https://" + "a" * 290 + ".com", 5, True, False, 12.5, ["https://rmm.example.com"], {"v": "x"}):
    r = patch(superuser, {SETTING: bad})
    must(r.status_code == 400, f"{bad!r} is refused with 400, not {r.status_code}")
must(M.TecTacRuntimeConfig.current().console_ui_url == "https://rmm.example.com:8443/tec-tac/", "a refusal changes nothing")
for reset_value in (None, "", "  "):
    patch(superuser, {SETTING: "https://rmm.example.com"})
    r = patch(superuser, {SETTING: reset_value})
    must(r.status_code == 200 and r.data[SETTING]["value"] == "" and M.TecTacRuntimeConfig.current().console_ui_url == "", f"{reset_value!r} resets: {r.status_code}")

# audit: one strict row per change, none for an unchanged value, a failed audit write rolls back
h.rows.clear()
patch(superuser, {SETTING: "https://rmm.example.com"})
changes = [x for x in h.rows if x.get("object_id") == SETTING]
must(len(changes) == 1 and changes[0]["action"] == "modify" and changes[0]["object_type"] == "runtime_settings" and changes[0]["strict"] is True, "one strict row for a change")
must(changes[0]["before"] == {SETTING: ""} and changes[0]["after"] == {SETTING: "https://rmm.example.com/tec-tac/"}, "the row holds before and after")
h.rows.clear()
patch(superuser, {SETTING: "https://RMM.example.com/tec-tac"})
must(not [x for x in h.rows if x.get("object_id") == SETTING], "the same address in another spelling writes no row")
patch(superuser, {SETTING: None})
h.fail_audit = True
r = patch_failed = None
try:
    r = patch(superuser, {SETTING: "https://rmm.example.com"})
except h.audit.AuditWriteError as exc:  # the strict audit failure propagates and the transaction rolls back
    patch_failed = exc
h.fail_audit = False
must((patch_failed is not None or r.status_code >= 500) and M.TecTacRuntimeConfig.current().console_ui_url == "", "a failed audit write rolls the change back")

# non-superuser: 403 with a deny row, before the value is looked at
h.rows.clear()
r = patch(manager, {SETTING: "http://not-valid"})
must(r.status_code == 403 and len(rows_of(h, "deny")) == 1, f"a manage-only holder gets 403 (not 400) and one deny row: {r.status_code}")
must(rows_of(h, "deny")[0]["object_id"] == SETTING and rows_of(h, "deny")[0]["metadata"] == {"reason": "superuser_required"}, "the deny row")
must("http://not-valid" not in repr(h.rows), "no value in the deny row")
timeout_before = M.TecTacRuntimeConfig.current().module_register_timeout_seconds
r = patch(manager, {"module_register_timeout_seconds": timeout_before + 10, SETTING: "https://rmm.example.com"})
must(r.status_code == 403, "a mixed body is refused")
must(M.TecTacRuntimeConfig.current().module_register_timeout_seconds == timeout_before and M.TecTacRuntimeConfig.current().console_ui_url == "", "a mixed body saves nothing")
r = patch(superuser, {"module_register_timeout_seconds": timeout_before + 10, SETTING: "https://rmm.example.com"})
must(r.status_code == 200 and r.data[SETTING]["value"] == "https://rmm.example.com/tec-tac/" and r.data["module_register_timeout_seconds"]["value"] == timeout_before + 10, "a superuser may change both")
must(patch(superuser, {}).status_code == 400 and patch(superuser, {"nonsense": 1}).status_code == 400, "an empty body and an unknown key stay 400")
must(get().data["console_certificate_validity_days"]["value"] == 365, "the other settings are untouched")

# a stored value that does not validate is shown as unset, never raised
for stored in ("http://rmm.example.com/tec-tac/", "https://rmm.example.com/other/", "garbage"):
    M.TecTacRuntimeConfig.objects.update(console_ui_url=stored)
    must(get().data[SETTING]["value"] == "", f"a tampered {stored!r} is shown as unset")

print("console ui url setting 1.18.58 regression: PASS")
