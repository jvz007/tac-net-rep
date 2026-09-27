"""Root-owned Tec-Tac account security policy.

The Tactical/Django process may read this policy but never writes it directly.
Changes are delegated to the root-owned system-update helper so account
administrators cannot enable/disable the superuser-account guard by editing a
Tactical-writable file.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

POLICY_ROOT = Path("/etc/tec-tac/policy")
POLICY_FILE = POLICY_ROOT / "account-security-policy.json"
SYSTEM_UPDATE_HELPER = Path("/usr/local/sbin/tec-tac-system-update")


class AccountSecurityPolicyError(RuntimeError):
    pass


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled", ""}:
        return False
    raise AccountSecurityPolicyError("protect_superuser_accounts must be true or false.")


def get_policy() -> dict:
    enabled = False
    updated_at = None
    updated_by = None
    if POLICY_FILE.is_file():
        try:
            payload = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AccountSecurityPolicyError(f"Account security policy is unreadable: {exc}") from exc
        if not isinstance(payload, dict) or int(payload.get("schema", 0) or 0) != 1:
            raise AccountSecurityPolicyError("Account security policy schema is invalid.")
        enabled = _coerce_bool(payload.get("protect_superuser_accounts", False))
        updated_at = payload.get("updated_at")
        updated_by = payload.get("updated_by")
    return {
        "schema": 1,
        "protect_superuser_accounts": enabled,
        "default": False,
        "root_owned": True,
        "updated_at": updated_at,
        "updated_by": updated_by,
    }


def protection_enabled(*, fail_closed: bool = True) -> bool:
    try:
        return bool(get_policy()["protect_superuser_accounts"])
    except AccountSecurityPolicyError:
        # A corrupt/missing-on-disk policy must never silently weaken an
        # explicitly configured protection boundary. Missing is handled by
        # get_policy() as the documented default-off state.
        return bool(fail_closed)


def set_policy(enabled, *, updated_by: str = "") -> dict:
    protect = _coerce_bool(enabled)
    actor = str(updated_by or "").strip()
    if actor and not re.fullmatch(r"[A-Za-z0-9@._-]{1,150}", actor):
        raise AccountSecurityPolicyError("updated_by contains unsupported characters.")
    if not SYSTEM_UPDATE_HELPER.is_file():
        raise AccountSecurityPolicyError(f"Privileged policy helper is unavailable at {SYSTEM_UPDATE_HELPER}.")
    command = [
        "sudo", "-n", str(SYSTEM_UPDATE_HELPER),
        "--set-account-security-policy",
        "true" if protect else "false",
    ]
    if actor:
        command.append(actor)
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
    except subprocess.CalledProcessError as exc:
        raise AccountSecurityPolicyError((exc.stderr or "Privileged account security policy update failed.").strip()) from exc
    except subprocess.TimeoutExpired as exc:
        raise AccountSecurityPolicyError("Privileged account security policy update timed out.") from exc
    try:
        payload = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise AccountSecurityPolicyError("Privileged account security policy helper returned invalid output.") from exc
    if not isinstance(payload, dict):
        raise AccountSecurityPolicyError("Privileged account security policy helper returned invalid policy data.")
    return get_policy()
