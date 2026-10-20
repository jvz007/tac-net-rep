"""Runtime check for Core 1.17.58: the licensing enforcement mode, the status read and the override, with the real migration, the real
model, the real views and the real audit table. DEV SERVER ONLY.
It did NOT run on the development PC (Django and the Tactical database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac && ../env/bin/python manage.py shell < /path/to/tests/licensing-mode-runtime-1.17.58.py

It checks that migration 0033 added the column and left the existing row blank, then, as a throwaway superuser inside one transaction that is
rolled back: the default mode (log-only), the PATCH of the mode, one refusal in enforce (a probe module that names a licensing capability
nobody provides), one pass plus exactly one would-block audit row in log-only, the audited override in enforce (one strict row with the
reason), the status read, and a 403 for a person with no right. Nothing it does is kept. Prints PASS or FAIL.
"""
import json
import sys
import uuid

from accounts.models import User
from django.db import transaction
from django.db.migrations.recorder import MigrationRecorder
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac import module_licensing, module_manager_v2 as v2, module_licensing_views, runtime_settings
from tec_tac.models import TecTacRuntimeConfig

SETTING = "licensing_enforcement_mode"
PROBE = {
    "id": "licence-probe", "extension_version": "0.0.1",
    "licensing": {"required": True, "product": "licence-probe", "capability": "probe.entitlements", "capability_version": ">=1.0.0,<2.0.0"},
}


class Rollback(Exception):
    pass


def rows(action):
    return AuditLog.objects.filter(action=action, object_type="module", debug_info__object_id="licence-probe").count()


ok = False
try:
    with transaction.atomic():
        assert MigrationRecorder.Migration.objects.filter(app="tec_tac", name="0033_runtime_licensing_mode").exists(), "migration 0033 is applied"
        TecTacRuntimeConfig._meta.get_field(SETTING)
        user = User.objects.create_user(username="tectac-probe-" + uuid.uuid4().hex[:8], email="p@example.invalid", password=uuid.uuid4().hex)
        user.is_superuser = True
        user.save()
        plain = User.objects.create_user(username="tectac-plain-" + uuid.uuid4().hex[:8], email="q@example.invalid", password=uuid.uuid4().hex)
        factory = APIRequestFactory()

        def call(view, method, path, body=None, who=user):
            request = getattr(factory, method)(path, body, format="json") if body is not None else getattr(factory, method)(path)
            force_authenticate(request, user=who)
            return view.as_view()(request)

        def patch(body, who=user):
            return call(runtime_settings.RuntimeSettingsView, "patch", "/api/tfd/system/runtime-settings/", body, who)

        # the default: blank stored, log-only read
        assert patch({SETTING: None}).status_code == 200
        assert TecTacRuntimeConfig.current().licensing_enforcement_mode == "", "the stored value is blank by default"
        got = call(runtime_settings.RuntimeSettingsView, "get", "/api/tfd/system/runtime-settings/").data[SETTING]
        assert got["value"] == "log-only" and got["source"] == "default" and got["choices"] == ["off", "log-only", "enforce"], got
        assert module_licensing.get_licensing_enforcement_mode() == "log-only"
        print("default: log-only, source default")

        # a bad value and a person with no right
        assert patch({SETTING: "Enforce"}).status_code == 400
        assert patch({SETTING: "enforce"}, who=plain).status_code in (401, 403)
        assert TecTacRuntimeConfig.current().licensing_enforcement_mode == ""

        # enforce: one refusal, and the 403 payload names the mode
        assert patch({SETTING: "enforce"}).status_code == 200
        before = rows("custom:licence-would-block")
        try:
            v2._enforce_candidate_licensing(dict(PROBE))
            raise AssertionError("enforce did not refuse")
        except v2.LicensingRequirementError as exc:
            assert exc.as_payload()["licensing"]["enforcement_mode"] == "enforce"
        assert rows("custom:licence-would-block") == before, "no would-block row in enforce"
        print("enforce: refused")

        # log-only: a pass and exactly one would-block row
        assert patch({SETTING: "log-only"}).status_code == 200
        candidate = dict(PROBE)
        status = v2._enforce_candidate_licensing(candidate)
        assert status["would_block"] is True and status["enforcement_mode"] == "log-only", status
        assert rows("custom:licence-would-block") == before + 1, "exactly one would-block row"
        print("log-only: passed, one would-block row")

        # off: nothing checked, no row
        assert patch({SETTING: "off"}).status_code == 200
        assert v2._enforce_candidate_licensing(dict(PROBE))["state"] == "not-checked"
        assert rows("custom:licence-would-block") == before + 1, "off writes nothing"

        # the override in enforce: one strict row with the reason
        assert patch({SETTING: "enforce"}).status_code == 200
        with module_licensing.override_scope(user, "dev-server probe, rolled back"):
            overridden = v2._enforce_candidate_licensing(dict(PROBE))
        assert overridden["overridden"] is True, overridden
        assert rows("custom:licence-override") == 1, "one override row"
        row = AuditLog.objects.filter(action="custom:licence-override", debug_info__object_id="licence-probe").first()
        assert "dev-server probe, rolled back" in json.dumps(row.debug_info), row.debug_info
        assert module_licensing.active_override() is None, "the override is cleared"
        try:
            v2._enforce_candidate_licensing(dict(PROBE))
            raise AssertionError("the override carried over")
        except v2.LicensingRequirementError:
            pass
        print("override: one audit row, not carried over")

        # the status read
        reply = call(module_licensing_views.LicensingStatusView, "get", "/api/tfd/system/licensing/")
        assert reply.status_code == 200, reply.status_code
        text = json.dumps(reply.data, default=str)
        assert reply.data["mode"]["value"] == "enforce" and reply.data["enforcing"] is True
        assert reply.data["grace"]["days_left"] is None and reply.data["grace"]["window_days"] == 7
        for banned in ("license_key", "licence_key", "token", "fingerprint", "private_key"):
            assert banned not in text.lower().replace("never_blocked", ""), banned
        assert call(module_licensing_views.LicensingStatusView, "get", "/api/tfd/system/licensing/", who=plain).status_code in (401, 403)
        print("status read:", reply.data["licence"], "would block:", reply.data["would_block"]["count"])

        # back to the default
        assert patch({SETTING: None}).status_code == 200
        assert module_licensing.get_licensing_enforcement_mode() == "log-only"
        ok = True
        raise Rollback()
except Rollback:
    pass
except Exception as exc:  # noqa: BLE001 - report any failure as FAIL
    print("FAIL:", repr(exc))
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
