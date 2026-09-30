#!/usr/bin/env python3
"""Portable guard for the F8/AD-4 Django test-database regression."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "framwork" / "tec_tac" / "tests" / "test_f8_sso_ad4_tactical_integration.py"
s = p.read_text(encoding="utf-8")

required = [
    "from django.test import Client, TestCase",
    "class F8SsoAd4TacticalIntegrationTests(TestCase)",
    "connection.creation._get_test_db_name()",
    'resolve("/accounts/ssoproviders/token/")',
    '"/accounts/ssoproviders/token/"',
    '"/api/tfd/ui/context/"',
    '"/v2/checkcreds/"',
    'event_type="session_created"',
    "self.assertTrue(self.user.is_sso_user)",
    "self.assertEqual(token_response.status_code, 200",
    "self.assertEqual(context_response.status_code, 200",
    "self.assertEqual(password_response.status_code, 400)",
    "throwaway test database",
]
for item in required:
    assert item in s, f"F8 AD-4 test-database regression missing {item!r}"

for forbidden in [
    "django.setup()",
    "transaction.atomic",
    "from django.db import transaction",
    "import psycopg",
    "import psycopg2",
    ".cursor(",
    ".raw(",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE FROM ",
    "run inside an installed",
    "installed Tactical/Tec-Tac",
]:
    assert forbidden.lower() not in s.lower(), (
        f"F8 regression must run only under Django's isolated test database: {forbidden!r}"
    )

assert "if active_name != expected_test_name" in s, "F8 test must fail closed outside Django's test DB"
assert "raise SkipTest" in s, "F8 test must skip when EE SSO/Postgres test prerequisites are unavailable"
assert "force_authenticate" not in s, "F8 closure must authenticate through Tactical's real HTTP views"

print("[TEST] PASS F8 AD-4 Django throwaway test-database acceptance 1.15.186-1")
