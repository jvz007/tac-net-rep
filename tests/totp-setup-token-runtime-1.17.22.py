"""Runtime check for Core 1.17.22: the setup token still enrols after Knox auto refresh. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Knox and Tactical's database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/totp-setup-token-runtime-1.17.22.py

It makes a throwaway user, issues a real Knox token with a 180 second life (as Tactical's checkcreds does), calls an authenticated
request twice so Knox auto refresh stretches the expiry, then checks that _is_short_lived_knox_setup_token still answers True and
that the old expiry-minus-created rule answered False. Everything runs in one transaction that is rolled back. Prints PASS or FAIL.
"""
import sys
import uuid
from datetime import timedelta

from accounts.models import User
from django.db import transaction
from django.test import RequestFactory
from knox.auth import TokenAuthentication
from knox.models import AuthToken
from tec_tac import views


class Rollback(Exception):
    pass


ok = False
try:
    with transaction.atomic():
        user = User.objects.create_user(username="tectac-probe-" + uuid.uuid4().hex[:8], email="p@example.invalid", password=uuid.uuid4().hex)
        user.totp_key = ""
        user.save()
        instance, token = AuthToken.objects.create(user=user, expiry=timedelta(seconds=180))
        results = []
        for _ in range(2):
            request = RequestFactory().get("/", HTTP_AUTHORIZATION="Token " + token)
            auth_user, auth = TokenAuthentication().authenticate(request)
            request.user, request.auth = auth_user, auth
            seconds = (auth.expiry - auth.created).total_seconds()
            results.append((views._is_short_lived_knox_setup_token(request), 0 < seconds <= 300, seconds))
        print("results (new rule, old rule, expiry-created seconds):", results)
        ok = all(new for new, _old, _s in results)
        raise Rollback()
except Rollback:
    pass
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
