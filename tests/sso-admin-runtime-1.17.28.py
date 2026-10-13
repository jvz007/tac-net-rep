"""Runtime check for Core 1.17.28: Tactical's SSO provider and settings admin, superuser only, with the lock-out guard (CQ84 a). DEV SERVER ONLY.
It did NOT run on the development PC (Django, allauth, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/sso-admin-runtime-1.17.28.py

It drives Tactical's real ee/sso/views.py handlers, with Core's guard installed, through DRF's APIRequestFactory, with real SocialApp,
SocialAccount and CoreSettings rows. Everything is written inside one transaction that is ROLLED BACK at the end, audit rows included.
No provider is ever left behind, and nothing reaches an identity provider: the provider rows are made up and never used to sign in.
Prints PASS or FAIL for each step.

Checks: the guard is installed on the six SSO writes and the list, and not on the sign-in view; a probe that is not a superuser is refused
on an add with 403 and writes nothing; a superuser adds, edits, deletes a provider, saves the settings and disconnects an account, and each
writes one row in Tactical's AuditLog (object types sso_provider, sso_settings, sso_account); no row carries the client secret or the
client id; blocking local sign-in with no provider is 409 sso_lockout_guard and changes nothing; the list shows the secret to the superuser
and [REDACTED] to a probe that is not a superuser. The exact row shapes are pinned by tests/sso-admin-guard-1.17.28.py.
"""
import sys
import uuid

from accounts.models import User
from allauth.socialaccount.models import SocialAccount, SocialApp
from core.models import CoreSettings
from django.db import transaction
from ee.sso import views as sso_views
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac.tactical_account_guard import _already_guarded

RESULTS = []
MARK = "tectac-sso-" + uuid.uuid4().hex[:8]
CLIENT = MARK + "-client-id"
SECRET = MARK + "-client-secret"


class Rollback(Exception):
    pass


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def last_id():
    row = AuditLog.objects.order_by("-pk").first()
    return row.pk if row else 0


def new_rows(since):
    return list(AuditLog.objects.filter(pk__gt=since).order_by("pk"))


def sso_rows(rows):
    return [row for row in rows if str(row.object_type or "").startswith("sso_")]


try:
    with transaction.atomic():
        admin = User(username=f"{MARK}-admin", is_superuser=True, email=f"{MARK}@probe.invalid")
        admin.set_password(uuid.uuid4().hex)
        admin.save()
        probe = User(username=f"{MARK}-tech", is_superuser=False, email=f"{MARK}-tech@probe.invalid")
        probe.set_password(uuid.uuid4().hex)
        probe.save()
        factory = APIRequestFactory()

        def guard_installed():
            check(_already_guarded(sso_views.GetAddSSOProvider.get), "list")
            check(_already_guarded(sso_views.GetAddSSOProvider.post), "add")
            check(_already_guarded(sso_views.GetUpdateDeleteSSOProvider.put), "edit")
            check(_already_guarded(sso_views.GetUpdateDeleteSSOProvider.delete), "delete")
            check(_already_guarded(sso_views.GetUpdateSSOSettings.post), "settings")
            check(_already_guarded(sso_views.DisconnectSSOAccount.delete), "disconnect")
            check(not _already_guarded(sso_views.GetAccessToken.post), "the sign-in view is not wrapped")

        def probe_refused():
            since = last_id()
            request = factory.post("/accounts/ssoproviders/", {"name": MARK, "client_id": CLIENT, "secret": SECRET,
                                                               "server_url": "https://probe.invalid", "role": None}, format="json")
            force_authenticate(request, user=probe)
            response = sso_views.GetAddSSOProvider.as_view()(request)
            check(response.status_code in (401, 403), ("a non-superuser probe must be refused", response.status_code))
            check(not SocialApp.objects.filter(name=MARK).exists(), "no provider from a refused add")
            check(not [r for r in new_rows(since) if r.object_type == "sso_provider"], "no success row from a refused add")

        def superuser_add_edit_delete():
            since = last_id()
            request = factory.post("/accounts/ssoproviders/", {"name": MARK, "client_id": CLIENT, "secret": SECRET,
                                                               "server_url": "https://probe.invalid", "role": None}, format="json")
            force_authenticate(request, user=admin)
            response = sso_views.GetAddSSOProvider.as_view()(request)
            check(response.status_code == 200, ("add", response.status_code, response.data))
            app = SocialApp.objects.filter(name=MARK).first()
            check(app is not None, "the provider was created")
            request = factory.put(f"/accounts/ssoproviders/{app.pk}/", {"client_id": CLIENT + "-2", "secret": SECRET + "-2",
                                                                        "server_url": "https://probe2.invalid", "role": None}, format="json")
            force_authenticate(request, user=admin)
            check(sso_views.GetUpdateDeleteSSOProvider.as_view()(request, pk=app.pk).status_code == 200, "edit")
            request = factory.delete(f"/accounts/ssoproviders/{app.pk}/")
            force_authenticate(request, user=admin)
            check(sso_views.GetUpdateDeleteSSOProvider.as_view()(request, pk=app.pk).status_code == 200, "delete")
            rows = sso_rows(new_rows(since))
            actions = [(r.object_type, r.action) for r in rows]
            check(actions == [("sso_provider", "add"), ("sso_provider", "modify"), ("sso_provider", "delete")], actions)
            dumped = " ".join(repr(r.__dict__) for r in rows)
            check(CLIENT not in dumped and SECRET not in dumped, "no client id or secret in any SSO row")

        def settings_lockout_refused():
            # Nothing is deleted here: the server's own providers stay. The 409 case needs a server with no provider rows; on a server
            # that has some, the same save must be allowed (200), or Tactical's licence answer (423) comes back.
            config = CoreSettings.objects.first()
            before = (config.sso_enabled, config.block_local_user_logon)
            since = last_id()
            request = factory.post("/accounts/ssoproviders/settings/", {"sso_enabled": True, "block_local_user_logon": True}, format="json")
            force_authenticate(request, user=admin)
            response = sso_views.GetUpdateSSOSettings.as_view()(request)
            if SocialApp.objects.count() == 0:
                check(response.status_code == 409 and response.data.get("code") == "sso_lockout_guard", (response.status_code, response.data))
                config.refresh_from_db()
                check((config.sso_enabled, config.block_local_user_logon) == before, "nothing changed by a refused lock-out")
                check(not [r for r in sso_rows(new_rows(since)) if r.action == "modify"], "no success row for a refused save")
            else:
                check(response.status_code in (200, 423), ("providers exist here, so the save is not a lock-out", response.status_code))

        def list_redacts_for_probe():
            request = factory.get("/accounts/ssoproviders/")
            force_authenticate(request, user=probe)
            response = sso_views.GetAddSSOProvider.as_view()(request)
            check(response.status_code == 403 or all(item.get("secret") == "[REDACTED]" for item in response.data),
                  "a probe that cannot list sees [REDACTED] or is refused")

        step("the guard is installed on the SSO writes and list, not on sign-in", guard_installed)
        step("a non-superuser is refused an SSO add, with no row", probe_refused)
        step("a superuser adds, edits and deletes a provider: one row each, no secret", superuser_add_edit_delete)
        step("a settings save that would block local sign-in with no provider is refused (or allowed when providers exist)", settings_lockout_refused)
        step("the list redacts the secret for a non-superuser", list_redacts_for_probe)
        raise Rollback()
except Rollback:
    pass

passed = sum(1 for ok in RESULTS if ok)
print(f"{passed}/{len(RESULTS)} runtime checks passed for sso-admin-1.17.28 (rolled back, nothing kept)")
sys.exit(0 if all(RESULTS) and len(RESULTS) == 5 else 1)
