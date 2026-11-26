#!/usr/bin/env python3
"""Regression: Core 1.18.52 (C3). The certificate validity setting, and migration 0049 against the models.

Real Django on a temporary SQLite file and the real runtime_settings.py view. The migration is checked two ways: an AST pass that compares it
with models.py field for field (always), and, where Django is importable, Django's own autodetector, which must find nothing left to migrate
once 0049's operations are applied to the state before them. (`manage.py makemigrations --check` itself needs Tactical's other apps and cannot
run on this PC.) Also pins the 1.18.44 lesson: no field named check, delete, save or clean.
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

SHADOWED = {"check", "save", "delete", "clean", "full_clean", "validate_unique", "validate_constraints", "refresh_from_db", "from_db", "pk", "objects"}
NEW_MODELS = ("TecTacConsoleCA", "TecTacConsoleCertificate", "TecTacConsoleEnrolment")


def call_name(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def kwarg(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


# ---- AST: the migration matches the models field for field (always runs)
models_tree = ast.parse((APP / "models.py").read_bytes().decode("utf-8"))
classes = {n.name: n for n in models_tree.body if isinstance(n, ast.ClassDef)}
model_fields = {}
for name in NEW_MODELS:
    cls = classes[name]
    fields = {}
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute) and getattr(stmt.value.func.value, "id", "") == "models":
            fields[stmt.targets[0].id] = stmt.value
    must(not (set(fields) & SHADOWED), f"{name} has a field that shadows a Model attribute: {set(fields) & SHADOWED}")
    for forbidden in ("check", "delete", "save", "clean"):
        must(forbidden not in fields, f"{name}.{forbidden} must not be a field name")
    model_fields[name] = fields
migration = ast.parse((APP / "migrations" / "0049_console_certificates.py").read_text(encoding="utf-8"))
created = {}
for node in ast.walk(migration):
    if isinstance(node, ast.Call) and call_name(node) == "CreateModel":
        name = kwarg(node, "name").value
        created[name] = {e.elts[0].value: e.elts[1] for e in kwarg(node, "fields").elts}
must(set(created) == set(NEW_MODELS), f"0049 creates the three models: {sorted(created)}")
# Later migrations may add fields to these models (0051 adds the PKCE challenge in 1.18.57): fold their AddField in, so the check is "0049 plus later".
for later in ("0051_console_enrolment_pkce.py",):
    later_tree = ast.parse((APP / "migrations" / later).read_text(encoding="utf-8"))
    for node in ast.walk(later_tree):
        if isinstance(node, ast.Call) and call_name(node) == "AddField":
            target = {m.lower(): m for m in NEW_MODELS}.get(kwarg(node, "model_name").value)
            if target:
                created[target][kwarg(node, "name").value] = kwarg(node, "field")
for name in NEW_MODELS:
    must(set(created[name]) - {"id"} == set(model_fields[name]) - {"id"}, f"{name}: 0049 and models.py agree on the fields")
    for field, call in model_fields[name].items():
        if field == "id":
            continue
        m_call = created[name][field]
        must(call_name(call) == call_name(m_call), f"{name}.{field}: the same field type in the migration")
        for key in ("max_length", "null", "blank", "unique"):
            a, b = kwarg(call, key), kwarg(m_call, key)
            must((ast.unparse(a) if a else None) == (ast.unparse(b) if b else None), f"{name}.{field}.{key} agrees: {a and ast.unparse(a)} vs {b and ast.unparse(b)}")
tail = ast.unparse(migration)
for needle in ("tectac_console_ca_one_active", "tectac_console_enrol_one_open", "tectac_concert_user_idx", "tectac_concert_ca_idx", "console_certificate_validity_days",
               "0048_result_checks", "core_console_ca", "core_console_certificate", "core_console_enrolment"):
    must(needle in tail, f"0049 mentions {needle}")
must("swappable_dependency" not in tail and "AUTH_USER_MODEL" not in tail, "no user foreign key, so no swappable dependency")
for model in ("TecTacConsoleCertificate",):
    must("PROTECT" in ast.unparse(model_fields[model]["ca"]), "the certificate's CA link is PROTECT")
runtime = classes["TecTacRuntimeConfig"]
must(any(isinstance(s, ast.Assign) and s.targets[0].id == "console_certificate_validity_days" for s in runtime.body if isinstance(s, ast.Assign)), "the runtime config has the setting column")

h = harness.boot()
if h is None:
    print("console certificates setting 1.18.52 regression: PASS (AST branch only: Django is not installed)")
    sys.exit(0)

# ---- Django's autodetector: 0049 applied to the state before it leaves nothing to migrate
from django.apps import apps  # noqa: E402
from django.db.migrations.autodetector import MigrationAutodetector  # noqa: E402
from django.db.migrations.state import ProjectState  # noqa: E402

current = ProjectState.from_apps(apps)
before = current.clone()
for name in ("tectacconsolecertificate", "tectacconsoleca", "tectacconsoleenrolment"):
    before.remove_model("tec_tac", name)
before.models[("tec_tac", "tectacruntimeconfig")].fields.pop("console_certificate_validity_days")
before.models[("tec_tac", "tectacruntimeconfig")].fields.pop("console_ui_url")  # 1.18.58: 0052 adds it
mig = importlib.import_module("tec_tac.migrations.0049_console_certificates").Migration
state = before.clone()
for op in mig.operations:
    op.state_forwards("tec_tac", state)
# 1.18.57: 0051 adds the PKCE challenge column to the enrolment; apply it too, so only a real disagreement is left over
for op in importlib.import_module("tec_tac.migrations.0051_console_enrolment_pkce").Migration.operations:
    op.state_forwards("tec_tac", state)
# 1.18.58: 0052 adds console_ui_url to the runtime configuration
for op in importlib.import_module("tec_tac.migrations.0052_console_ui_url").Migration.operations:
    op.state_forwards("tec_tac", state)
changes = MigrationAutodetector(state, current)._detect_changes()
leftover = {app: [(m.name, [type(o).__name__ + ":" + str(getattr(o, "name", getattr(o, "model_name", ""))) for o in m.operations]) for m in ms] for app, ms in changes.items() if app == "tec_tac"}
must(not leftover, f"0049 and the models disagree (makemigrations would still write): {leftover}")
must(mig.dependencies == [("tec_tac", "0048_result_checks")], "0049 depends on 0048 only")

# the SQL it makes has the partial unique indexes
sql_state = before.clone()
with h.connection.schema_editor(collect_sql=True, atomic=False) as editor:
    for op in mig.operations:
        target = sql_state.clone()
        op.state_forwards("tec_tac", target)
        op.database_forwards("tec_tac", editor, sql_state, target)
        sql_state = target
sql = "\n".join(editor.collected_sql)
must("core_console_ca" in sql and "core_console_certificate" in sql and "core_console_enrolment" in sql, "the three tables")
must("tectac_console_ca_one_active" in sql and "tectac_console_enrol_one_open" in sql and "WHERE" in sql, "the partial unique constraints are real")
must("console_certificate_validity_days" in sql, "the new column")

# ---- the setting through the real view
from rest_framework.test import APIRequestFactory, force_authenticate  # noqa: E402
from tec_tac import runtime_settings as rs  # noqa: E402

h.reset()
M = h.models
superuser = h.new_user("root", superuser=True)
manager = h.new_user("manager", perms=("core.runtime_settings.manage",))
SETTING = "console_certificate_validity_days"
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


must(get().data[SETTING] == {"value": 365, "minimum": 1, "maximum": 730, "default": 365}, f"GET shows the setting: {get().data[SETTING]}")
for good in (1, 30, 730, 365):
    r = patch(superuser, {SETTING: good})
    must(r.status_code == 200 and r.data[SETTING]["value"] == good, f"{good} is accepted: {r.status_code} {getattr(r, 'data', '')}")
must(rs.get_console_certificate_validity_days() == 365, "the last value is read back")
for bad in (0, -1, 731, 10000, True, False, 12.5, "30", None, [30], {"v": 30}):
    r = patch(superuser, {SETTING: bad})
    must(r.status_code == 400, f"{bad!r} is refused with 400, not {r.status_code}")
must(rs.get_console_certificate_validity_days() == 365 and M.TecTacRuntimeConfig.current().console_certificate_validity_days == 365, "a refusal changes nothing (null does not reset)")

# audit: a strict row per change, none for an unchanged value
h.rows.clear()
patch(superuser, {SETTING: 90})
changes = [r for r in h.rows if r.get("object_id") == SETTING]
must(len(changes) == 1 and changes[0]["action"] == "modify" and changes[0]["object_type"] == "runtime_settings" and changes[0]["strict"] is True, "one strict row for a change")
must(changes[0]["before"] == {SETTING: 365} and changes[0]["after"] == {SETTING: 90}, "the row holds before and after")
h.rows.clear()
patch(superuser, {SETTING: 90})
must(not [r for r in h.rows if r.get("object_id") == SETTING], "no row for an unchanged value")

# non-superuser: 403 with a deny row, checked before the value
h.rows.clear()
r = patch(manager, {SETTING: 0})
must(r.status_code == 403 and len(rows_of(h, "deny")) == 1, f"a manage-only holder gets 403 (not 400) and one deny row: {r.status_code}")
must(rows_of(h, "deny")[0]["object_id"] == SETTING and rows_of(h, "deny")[0]["metadata"] == {"reason": "superuser_required"}, "the deny row")
timeout_before = M.TecTacRuntimeConfig.current().module_register_timeout_seconds
r = patch(manager, {"module_register_timeout_seconds": timeout_before + 10, SETTING: 30})
must(r.status_code == 403, "a mixed body is refused")
must(M.TecTacRuntimeConfig.current().module_register_timeout_seconds == timeout_before and rs.get_console_certificate_validity_days() == 90, "a mixed body saves nothing")
r = patch(superuser, {"module_register_timeout_seconds": timeout_before + 10, SETTING: 60})
must(r.status_code == 200 and r.data[SETTING]["value"] == 60 and r.data["module_register_timeout_seconds"]["value"] == timeout_before + 10, "a superuser may change both")
must(len([x for x in h.rows if x.get("action") == "modify"]) >= 2, "one row per changed setting")
must(patch(superuser, {}).status_code == 400 and patch(superuser, {"nonsense": 1}).status_code == 400, "an empty body and an unknown key stay 400")

# an unreadable or out-of-range stored value reads 365
for stored in (0, 731, 5000):
    M.TecTacRuntimeConfig.objects.update(console_certificate_validity_days=stored)
    must(rs.get_console_certificate_validity_days() == 365, f"a stored {stored} reads 365")
    must(get().data[SETTING]["value"] == 365, f"and is shown as 365 ({stored})")
real_current = M.TecTacRuntimeConfig.current
M.TecTacRuntimeConfig.current = classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("database down")))
try:
    must(rs.get_console_certificate_validity_days() == 365, "a failing read gives 365 and never raises")
finally:
    M.TecTacRuntimeConfig.current = real_current
M.TecTacRuntimeConfig.objects.update(console_certificate_validity_days=730)
must(rs.get_console_certificate_validity_days() == 730, "730 is the ceiling and is allowed")

# it affects new certificates only
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("ten")
M.TecTacRuntimeConfig.objects.update_or_create(singleton=1, defaults={SETTING: 10})
_u, _c, _code, r = h.full_flow(admin, engineer, pc_label="Short")
cert = M.TecTacConsoleCertificate.objects.get(serial=r.data["serial"])
must(abs(((cert.not_after - cert.created_at).total_seconds()) - 10 * 86400) < 120, "a new certificate lasts the configured days")
M.TecTacRuntimeConfig.objects.update(console_certificate_validity_days=200)
must(M.TecTacConsoleCertificate.objects.get(pk=cert.pk).not_after == cert.not_after, "an issued certificate is not changed")

print("console certificates setting 1.18.52 regression: PASS")
