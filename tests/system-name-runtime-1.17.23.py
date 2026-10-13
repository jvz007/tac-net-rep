"""Runtime check for Core 1.17.23: the system name setting, the real migration and the real PATCH. DEV SERVER ONLY.
It did NOT run on the development PC (Django and the Tactical database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac && ../env/bin/python manage.py shell < /path/to/tests/system-name-runtime-1.17.23.py

It checks that migration 0027 left the existing row with a value, then runs the real RuntimeSettingsView PATCH as a throwaway
superuser inside one transaction that is rolled back: a good name, a colon (400), the otpauth issuer, the null reset and the audit
rows. Prints PASS or FAIL.
"""
import sys
import uuid

from accounts.models import User
from django.db import transaction
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac import runtime_settings, views
from tec_tac.models import TecTacRuntimeConfig


class Rollback(Exception):
    pass


ok = False
try:
    with transaction.atomic():
        config = TecTacRuntimeConfig.current()
        assert config.system_name, "the migration left a value"
        user = User.objects.create_user(username="tectac-probe-" + uuid.uuid4().hex[:8], email="p@example.invalid", password=uuid.uuid4().hex)
        user.is_superuser = True
        user.save()
        factory = APIRequestFactory()

        def patch(body):
            request = factory.patch("/api/tfd/system/runtime-settings/", body, format="json")
            force_authenticate(request, user=user)
            return runtime_settings.RuntimeSettingsView.as_view()(request)

        assert patch({"system_name": "Probe IT"}).status_code == 200
        assert runtime_settings.get_system_name() == "Probe IT"
        assert patch({"system_name": "a:b"}).status_code == 400
        assert runtime_settings.get_system_name() == "Probe IT"
        request = factory.get("/")
        request.user = user
        user.totp_key = "JBSWY3DPEHPK3PXP"
        uri = views._tec_tac_totp_uri(request)
        assert uri.startswith("otpauth://totp/Probe%20IT:"), uri
        assert patch({"system_name": None}).status_code == 200
        assert runtime_settings.get_system_name() == "Tec-Tac"
        rows = AuditLog.objects.filter(object_type="runtime_settings", debug_info__object_id="system_name").count()
        print("audit rows for system_name:", rows)
        assert rows >= 2
        ok = True
        raise Rollback()
except Rollback:
    pass
except Exception as exc:  # noqa: BLE001 - report any failure as FAIL
    print("FAIL:", repr(exc))
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
