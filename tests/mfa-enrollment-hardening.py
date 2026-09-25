#!/usr/bin/env python3
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
views = (ROOT / "framwork/tec_tac/views.py").read_text()
session = (ROOT / "framwork/tec_tac/session_security.py").read_text()
urls = (ROOT / "framwork/tec_tac/urls.py").read_text()

ast.parse(views)
ast.parse(session)

assert 'class TotpEnrollmentView(APIView):' in views
assert 'permission_classes = [IsAuthenticated]' in views
assert '_is_short_lived_knox_setup_token(request)' in views
assert 'request.user.check_password(password)' in views
assert 'select_for_update().get(pk=request.user.pk)' in views
assert 'user.totp_key = secret' in views
assert 'auth.delete()' in views
assert '"one_time": True' in views
assert 'mfa_enrollment_seed_issued' in views
assert 'mfa_enrollment_proof_failed' in views
assert 'class TotpQrView(APIView):' in views
assert '"totp_qr_retired"' in views
assert 'pyotp.TOTP(request.user.totp_key).provisioning_uri' not in views
assert '"mfa_enrollment_required"' in session
assert 'request_knox_digest(request)' in session
assert 'path("auth/totp/enrollment/"' in urls
print("mfa enrollment hardening regression: PASS")
