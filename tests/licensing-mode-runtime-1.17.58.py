"""Runtime check for Core 1.17.58, signed in the way Core expects since 1.17.59. DEV SERVER ONLY.
It did NOT run on the development PC (Django and the Tactical database are not installed there).

Run it on the dev server with:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac && ../env/bin/python manage.py shell < /path/to/tests/licensing-mode-runtime-1.17.58.py

PASS means the script printed PASS as its last line and no step printed FAIL. FAIL prints the step that broke, then FAIL.
Send that step back. A run inside the same minute as an earlier run can hit the settings write throttle (10 PATCH a minute):
the step then says 429. Wait a minute and run it again.

What it does: it checks that migration 0033 is applied, then, as a throwaway superuser and a throwaway plain person inside ONE
transaction that is rolled back, it checks the default mode (log-only), every PATCH of the mode and the GET after it, a bad value (400),
a person with no right (exactly 403), one refusal in enforce (a probe module that names a licensing capability nobody provides), one pass
plus exactly one would-block audit row in log-only, the audited override in enforce, the status read (superuser 200, plain person exactly
403, no key, token, fingerprint or private key text) and the agent list sort (sort_by=hostname&sort_dir=desc, and a bad sort_by is a 400).
A closing step counts outside the transaction that the throwaway people, their tokens, their session rows and the probe audit rows are
gone. Nothing it does is kept.

Sign-in (the 1.17.59 fix): each throwaway person gets a real Knox token (knox.models.AuthToken.objects.create) that is sent as the
header ``Authorization: Token <raw>``. force_authenticate is NOT used, so Tactical's real knox TokenAuthentication authenticates the
request and Core's session guard sees the same digest in request.auth and in the header, as it does for a browser. Each person also
has a totp_key, because Core refuses a Knox token from a non-SSO person with no authenticator (mfa_enrollment_required). The
fallback, if Knox's real authentication proves awkward here, would be force_authenticate(request, user=who, token=<the AuthToken
instance>) plus the same header. Not needed so far; this file uses the real authentication.
"""
import json
import sys
import uuid

from accounts.models import User
from django.db import transaction
from django.db.migrations.recorder import MigrationRecorder
from knox.models import AuthToken
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory
from tec_tac import module_licensing, module_manager_v2 as v2, module_licensing_views, runtime_settings
from tec_tac.models import TecTacRuntimeConfig, TecTacSessionAudit, TecTacSessionTrust
from tec_tac.resource_views import ResourceListView

SETTING = "licensing_enforcement_mode"
SETTINGS_PATH = "/api/tfd/system/runtime-settings/"
LICENSING_PATH = "/api/tfd/system/licensing/"
PROBE = {
    "id": "licence-probe", "extension_version": "0.0.1",
    "licensing": {"required": True, "product": "licence-probe", "capability": "probe.entitlements", "capability_version": ">=1.0.0,<2.0.0"},
}


class Rollback(Exception):
    pass


STEP = ["start"]
NAMES = []


def step(name):
    STEP[0] = name
    print("step:", name)


def rows(action):
    return AuditLog.objects.filter(action=action, object_type="module", debug_info__object_id="licence-probe").count()


def why(reply):
    """Status and body of a reply, for an assert message."""
    body = getattr(reply, "data", None)
    return "status %s, body %s" % (reply.status_code, json.dumps(body, default=str)[:400])


def throwaway(label, email, superuser):
    name = "tectac-%s-%s" % (label, uuid.uuid4().hex[:8])
    NAMES.append(name)
    person = User.objects.create_user(username=name, email=email, password=uuid.uuid4().hex)
    person.is_superuser = superuser
    person.totp_key = "TECTACRUNTIMEPROBE" + uuid.uuid4().hex[:8]  # any non-empty text (50 characters at most): Core refuses a Knox person with none
    person.save()
    return person


ok = False
before_tokens = before_trust = before_probe_rows = None
try:
    before_tokens = AuthToken.objects.count()
    before_trust = TecTacSessionTrust.objects.count()
    before_probe_rows = AuditLog.objects.filter(object_type="module", debug_info__object_id="licence-probe").count()
    with transaction.atomic():
        step("migration 0033 is applied and the column exists")
        assert MigrationRecorder.Migration.objects.filter(app="tec_tac", name="0033_runtime_licensing_mode").exists(), "migration 0033 is not applied (run manage.py migrate tec_tac)"
        TecTacRuntimeConfig._meta.get_field(SETTING)

        step("create the throwaway superuser, the plain person and their Knox tokens")
        user = throwaway("probe", "p@example.invalid", True)
        plain = throwaway("plain", "q@example.invalid", False)
        TOKENS = {person.pk: AuthToken.objects.create(person)[1] for person in (user, plain)}
        assert all(TOKENS.values()), "Knox gave no raw token"
        factory = APIRequestFactory()

        def call(view, method, path, body=None, who=user):
            """One request, signed in with the person's real Knox token. No force_authenticate."""
            extra = {"HTTP_AUTHORIZATION": "Token " + TOKENS[who.pk]}
            if body is not None:
                request = getattr(factory, method)(path, body, format="json", **extra)
            else:
                request = getattr(factory, method)(path, **extra)
            return view(request)

        settings_view = runtime_settings.RuntimeSettingsView.as_view()
        licensing_view = module_licensing_views.LicensingStatusView.as_view()
        agents_view = ResourceListView.as_view(resource_type="agent")
        PATCHES = [0]  # the superuser's PATCH calls: the settings write throttle allows 10 a minute, so 9 at most

        def patch(body, who=user):
            if who is user:
                PATCHES[0] += 1
                assert PATCHES[0] <= 9, "the test itself made more than 9 PATCH calls for one person; the write throttle would stop it"
            reply = call(settings_view, "patch", SETTINGS_PATH, body, who)
            assert reply.status_code != 429, "429 at step %r: the settings write throttle stopped the run; wait a minute (%s)" % (STEP[0], why(reply))
            return reply

        def read_setting():
            reply = call(settings_view, "get", SETTINGS_PATH)
            assert reply.status_code == 200, "GET runtime-settings at step %r: %s" % (STEP[0], why(reply))
            return reply.data[SETTING]

        step("default: PATCH null, then the stored value is blank and the read is log-only")
        reply = patch({SETTING: None})
        assert reply.status_code == 200, "PATCH null: " + why(reply)
        assert TecTacRuntimeConfig.current().licensing_enforcement_mode == "", "the stored value is not blank after PATCH null"
        got = read_setting()
        assert got["value"] == "log-only" and got["source"] == "default" and got["choices"] == ["off", "log-only", "enforce"], "default GET: %s" % got
        assert module_licensing.get_licensing_enforcement_mode() == "log-only", "the default mode is not log-only"
        print("default: log-only, source default")

        step("a bad value is a 400 and stores nothing")
        reply = patch({SETTING: "Enforce"})
        assert reply.status_code == 400, "PATCH 'Enforce' must answer 400: " + why(reply)
        assert TecTacRuntimeConfig.current().licensing_enforcement_mode == "", "a bad value was stored"
        assert read_setting()["source"] == "default", "a bad value changed the source"

        step("a person with no right gets exactly 403 and nothing is stored")
        reply = patch({SETTING: "enforce"}, who=plain)
        assert reply.status_code == 403, "PATCH by a plain person must answer exactly 403: " + why(reply)
        assert TecTacRuntimeConfig.current().licensing_enforcement_mode == "", "the plain person's PATCH was stored"

        step("PATCH enforce, then GET shows enforce")
        reply = patch({SETTING: "enforce"})
        assert reply.status_code == 200, "PATCH enforce: " + why(reply)
        got = read_setting()
        assert got["value"] == "enforce" and got["source"] == "set" and got["choices"] == ["off", "log-only", "enforce"], "GET after enforce: %s" % got

        step("enforce refuses a probe module and the payload names the mode")
        before = rows("custom:licence-would-block")
        try:
            v2._enforce_candidate_licensing(dict(PROBE))
            raise AssertionError("enforce did not refuse the probe module")
        except v2.LicensingRequirementError as exc:
            assert exc.as_payload()["licensing"]["enforcement_mode"] == "enforce", "the refusal payload names the wrong mode: %s" % exc.as_payload()
        assert rows("custom:licence-would-block") == before, "a would-block row was written in enforce"
        print("enforce: refused")

        step("PATCH log-only, GET shows log-only, one pass and exactly one would-block row")
        reply = patch({SETTING: "log-only"})
        assert reply.status_code == 200, "PATCH log-only: " + why(reply)
        got = read_setting()
        assert got["value"] == "log-only" and got["source"] == "set", "GET after log-only: %s" % got
        status = v2._enforce_candidate_licensing(dict(PROBE))
        assert status["would_block"] is True and status["enforcement_mode"] == "log-only", "log-only status: %s" % status
        assert rows("custom:licence-would-block") == before + 1, "log-only did not write exactly one would-block row"
        print("log-only: passed, one would-block row")

        step("PATCH off, GET shows off, nothing checked and no row")
        reply = patch({SETTING: "off"})
        assert reply.status_code == 200, "PATCH off: " + why(reply)
        got = read_setting()
        assert got["value"] == "off" and got["source"] == "set", "GET after off: %s" % got
        assert v2._enforce_candidate_licensing(dict(PROBE))["state"] == "not-checked", "off still checked the probe module"
        assert rows("custom:licence-would-block") == before + 1, "off wrote a row"

        step("the override in enforce: one strict row with the reason, not carried over")
        reply = patch({SETTING: "enforce"})
        assert reply.status_code == 200, "PATCH enforce for the override: " + why(reply)
        with module_licensing.override_scope(user, "dev-server probe, rolled back"):
            overridden = v2._enforce_candidate_licensing(dict(PROBE))
        assert overridden["overridden"] is True, "the override did not apply: %s" % overridden
        assert rows("custom:licence-override") == 1, "the override did not write exactly one row"
        row = AuditLog.objects.filter(action="custom:licence-override", debug_info__object_id="licence-probe").first()
        assert "dev-server probe, rolled back" in json.dumps(row.debug_info), "the override row misses the reason: %s" % row.debug_info
        assert module_licensing.active_override() is None, "the override was not cleared"
        try:
            v2._enforce_candidate_licensing(dict(PROBE))
            raise AssertionError("the override carried over to the next check")
        except v2.LicensingRequirementError:
            pass
        print("override: one audit row, not carried over")

        step("the status read as the superuser")
        reply = call(licensing_view, "get", LICENSING_PATH)
        assert reply.status_code == 200, "GET system/licensing as the superuser: " + why(reply)
        text = json.dumps(reply.data, default=str)
        assert reply.data["mode"]["value"] == "enforce" and reply.data["mode"]["source"] == "set", "licensing mode shown: %s" % reply.data.get("mode")
        assert reply.data["enforcing"] is True, "enforcing is not true in enforce mode"
        assert reply.data["grace"]["days_left"] is None and reply.data["grace"]["window_days"] == 7, "grace: %s" % reply.data["grace"]
        for banned in ("license_key", "licence_key", "token", "fingerprint", "private_key"):
            assert banned not in text.lower().replace("never_blocked", ""), "the licensing status carries %r" % banned

        step("the status read as the plain person is exactly 403")
        reply = call(licensing_view, "get", LICENSING_PATH, who=plain)
        assert reply.status_code == 403, "GET system/licensing as a plain person must answer exactly 403: " + why(reply)
        print("status read: superuser 200, plain person 403, would block:", json.loads(text)["would_block"]["count"])

        step("the agent list sorts by host name, descending")
        reply = call(agents_view, "get", "/api/tfd/resources/agents/?sort_by=hostname&sort_dir=desc")
        assert reply.status_code == 200, "GET resources/agents sort_by=hostname&sort_dir=desc: " + why(reply)
        assert isinstance(reply.data, dict) and isinstance(reply.data.get("items"), list) and "count" in reply.data and "page" in reply.data, "the agent list is not a paged body: " + why(reply)
        names = [str(item.get("hostname") or "").lower() for item in reply.data["items"]]
        if len(names) >= 2:
            assert not (names == sorted(names) and len(set(names)) > 1), "host names came back ascending with sort_dir=desc: %s" % names
        print("agents sorted:", len(names), "on this page")

        step("a bad sort_by is a 400 with invalid_resource_request")
        reply = call(agents_view, "get", "/api/tfd/resources/agents/?sort_by=bogus")
        assert reply.status_code == 400, "GET resources/agents sort_by=bogus must answer 400: " + why(reply)
        assert reply.data.get("code") == "invalid_resource_request", "the 400 carries the wrong code: " + why(reply)

        step("back to the default")
        reply = patch({SETTING: None})
        assert reply.status_code == 200, "PATCH null at the end: " + why(reply)
        got = read_setting()
        assert got["value"] == "log-only" and got["source"] == "default", "GET after the final null: %s" % got
        assert module_licensing.get_licensing_enforcement_mode() == "log-only", "the mode did not go back to log-only"
        step("rolling back")
        raise Rollback()
except Rollback:
    try:
        step("closing: nothing was kept (counted outside the transaction)")
        assert not User.objects.filter(username__in=NAMES).exists(), "a throwaway person was kept"
        assert AuthToken.objects.count() == before_tokens, "a Knox token was kept: %s before, %s after" % (before_tokens, AuthToken.objects.count())
        assert TecTacSessionTrust.objects.count() == before_trust, "a session row was kept"
        assert not TecTacSessionTrust.objects.filter(username__in=NAMES).exists(), "a throwaway person's session row was kept"
        assert not TecTacSessionAudit.objects.filter(username__in=NAMES).exists(), "a throwaway person's session audit row was kept"
        assert not AuditLog.objects.filter(username__in=NAMES).exists(), "an audit row of a throwaway person was kept"
        assert AuditLog.objects.filter(object_type="module", debug_info__object_id="licence-probe").count() == before_probe_rows, "a probe audit row was kept"
        ok = True
    except Exception as exc:  # noqa: BLE001 - report any failure as FAIL
        print("FAIL at step %r: %r" % (STEP[0], exc))
except Exception as exc:  # noqa: BLE001 - report any failure as FAIL
    print("FAIL at step %r: %r" % (STEP[0], exc))
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
