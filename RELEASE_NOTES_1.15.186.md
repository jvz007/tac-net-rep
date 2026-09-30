# Core 1.15.186

## F8 SSO acceptance closure (AD-4) — isolated Django test database

- Replaces the rejected live-server F8 regression with `tec_tac.tests.test_f8_sso_ad4_tactical_integration`, a real `django.test.TestCase` that can run only through Django's test runner.
- Django creates and destroys a separate throwaway test database for the regression. The test fails closed if it is ever invoked against the configured live database.
- Tactical/allauth users, SSO links and the temporary `sso_enabled` value are test fixtures in that isolated database only.
- The regression still exercises Tactical's real `POST /accounts/ssoproviders/token/`, uses the Knox token returned by Tactical at Tec-Tac's real `GET /api/tfd/ui/context/`, and proves exactly one Tec-Tac trust row and one `session_created` audit row are created.
- It also proves an SSO-linked account receives the SSO Knox token without a Tec-Tac authenticator-code step and that Tactical's real `/v2/checkcreds/` refuses the account's correct password.
- Environments without Tactical EE SSO or a PostgreSQL Django test database skip the integration regression with a clear reason. They never fall back to a live database.

No production authentication behavior changed.

Unsigned source delivery.
