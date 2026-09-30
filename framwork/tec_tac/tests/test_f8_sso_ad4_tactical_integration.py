"""F8 / AD-4 SSO integration regression using Django's throwaway test database.

Run only through Django's test runner, for example::

    python manage.py test tec_tac.tests.test_f8_sso_ad4_tactical_integration

Django creates and destroys a separate test database before this TestCase runs.
The test never runs as a standalone script and must never point at a live Tactical
or Tec-Tac database.

Accepted decision AD-4:
- only an account actually linked to SSO is exempt from Tec-Tac's local TOTP step;
- the resulting Tactical Knox credential still passes through Tec-Tac session security;
- the Tec-Tac session creation is audited;
- Tactical refuses password dashboard sign-in for that SSO-linked account.
"""
from __future__ import annotations

import json
from importlib.util import find_spec
from unittest import SkipTest

from django.db import connection
from django.test import Client, TestCase
from django.urls import Resolver404, resolve

from accounts.models import User
from allauth.socialaccount.models import SocialAccount
from knox.models import AuthToken
from tacticalrmm.utils import get_core_settings

from tec_tac.models import TecTacSessionAudit, TecTacSessionTrust


class F8SsoAd4TacticalIntegrationTests(TestCase):
    """Exercise Tactical's real SSO/token views and Tec-Tac's real UI context view."""

    password = "TecTac-F8-Test-Only!123"
    username = "tectac_f8_sso_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # This regression depends on Tactical's EE SSO package and a PostgreSQL
        # test database. CI environments without either dependency skip cleanly;
        # they must never fall back to a live database.
        try:
            ee_sso_available = find_spec("ee.sso") is not None
        except (ImportError, ModuleNotFoundError):
            ee_sso_available = False
        if not ee_sso_available:
            raise SkipTest("Tactical EE SSO package is not available in this test runtime")
        if connection.vendor != "postgresql":
            raise SkipTest("F8 AD-4 integration regression requires Django's PostgreSQL test database")

        # Fail closed if this class is ever invoked outside Django's test DB.
        expected_test_name = str(connection.creation._get_test_db_name())
        active_name = str(connection.settings_dict.get("NAME") or "")
        if active_name != expected_test_name:
            raise RuntimeError(
                "F8 AD-4 regression refused to run outside Django's throwaway test database "
                f"(active={active_name!r}, expected={expected_test_name!r})"
            )

        # A build without Tactical's SSO route should be skipped, not redirected
        # to a live server or approximated with a stub.
        try:
            resolve("/accounts/ssoproviders/token/")
        except Resolver404:
            raise SkipTest("Tactical EE SSO token route is not installed in this test runtime")

    def setUp(self):
        self.user = User.objects.create_user(
            username=self.username,
            email="tectac-f8@invalid.local",
            password=self.password,
        )
        SocialAccount.objects.create(
            user=self.user,
            provider="openid_connect",
            uid="tectac-f8-oidc",
            extra_data={"sub": "tectac-f8-oidc"},
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_sso_user)
        self.assertFalse(getattr(self.user, "totp_key", None))

        # Tactical's own setting is a fixture in the throwaway test DB only.
        core_settings = get_core_settings()
        core_settings.sso_enabled = True
        core_settings.save(update_fields=["sso_enabled"])

    @staticmethod
    def _json(response):
        try:
            return response.json()
        except Exception as exc:  # pragma: no cover - assertion diagnostic only
            body = response.content.decode("utf-8", errors="replace")
            raise AssertionError(
                f"expected JSON response, got status={response.status_code} body={body[:500]!r}"
            ) from exc

    def test_sso_token_enters_tec_tac_without_local_totp_and_password_login_is_refused(self):
        browser = Client(
            REMOTE_ADDR="192.0.2.81",
            HTTP_USER_AGENT="TecTac-F8-TestDatabase",
        )

        # Represent the state django-allauth creates after the external provider
        # has authenticated the browser. Token issuance remains Tactical's real
        # SessionAuthentication-only endpoint; no Knox token is fabricated.
        browser.force_login(self.user)
        session = browser.session
        session["account_authentication_methods"] = [
            {"method": "socialaccount", "provider": "openid_connect"}
        ]
        session.save()

        # AD-4: no Tec-Tac authenticator code is supplied or requested here.
        token_response = browser.post(
            "/accounts/ssoproviders/token/",
            data=json.dumps({}),
            content_type="application/json",
            REMOTE_ADDR="192.0.2.81",
            HTTP_USER_AGENT="TecTac-F8-TestDatabase",
        )
        token_data = self._json(token_response)
        self.assertEqual(token_response.status_code, 200, token_data)
        self.assertEqual(token_data.get("username"), self.username)
        self.assertEqual(token_data.get("provider"), "openid_connect")
        knox_token = str(token_data.get("token") or "")
        self.assertTrue(knox_token, token_data)
        self.assertEqual(AuthToken.objects.filter(user=self.user).count(), 1)

        # Tactical invalidates the temporary Django SSO session after exchanging
        # it for the Knox credential.
        self.assertFalse(browser.session.get("_auth_user_id"))

        # Use the real Tactical Knox token at Tec-Tac's normal authenticated
        # boundary. This must create exactly one trust row and session audit row.
        core_client = Client(
            HTTP_AUTHORIZATION=f"Token {knox_token}",
            REMOTE_ADDR="192.0.2.81",
            HTTP_USER_AGENT="TecTac-F8-TestDatabase",
        )
        context_response = core_client.get("/api/tfd/ui/context/")
        context_data = self._json(context_response)
        self.assertEqual(context_response.status_code, 200, context_data)
        self.assertEqual(context_data.get("user", {}).get("username"), self.username)

        trusts = TecTacSessionTrust.objects.filter(user=self.user)
        self.assertEqual(trusts.count(), 1)
        trust = trusts.get()
        self.assertEqual(trust.username, self.username)
        self.assertTrue(trust.knox_digest)
        self.assertFalse(trust.revoked)

        audits = TecTacSessionAudit.objects.filter(
            username=self.username,
            event_type="session_created",
        )
        self.assertEqual(audits.count(), 1)
        self.assertEqual(audits.get().session_id, trust.id)

        # Tactical's own local sign-in path must refuse an SSO-linked account,
        # even when the submitted password is correct.
        password_client = Client(
            REMOTE_ADDR="192.0.2.82",
            HTTP_USER_AGENT="TecTac-F8-TestDatabase",
        )
        password_response = password_client.post(
            "/v2/checkcreds/",
            data=json.dumps({"username": self.username, "password": self.password}),
            content_type="application/json",
            REMOTE_ADDR="192.0.2.82",
        )
        self.assertEqual(password_response.status_code, 400)
        self.assertEqual(self._json(password_response), "Bad credentials")
        self.assertEqual(AuthToken.objects.filter(user=self.user).count(), 1)
