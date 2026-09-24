"""Shared Tec-Tac package/update trust acceptance policy.

The policy is intentionally global: the same minimum trust level applies to
Framework/UI System Updates and module package installation. Component/module
specific rules may still be stricter, but they can never weaken this floor.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

CONFIG_FILE = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
DEFAULT_POLICY_ROOT = Path("/var/lib/tec-tac/policy")
POLICY_FILENAME = "update-trust-policy.json"

LEVELS = (
    "unsigned",
    "signed_development",
    "signed_production",
    "secure_signed",
)
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}
LEVEL_LABELS = {
    "unsigned": "Unsigned",
    "signed_development": "Signed Development",
    "signed_production": "Signed Production",
    "secure_signed": "Secure Signed",
}


class TrustPolicyError(RuntimeError):
    pass


def _config_values() -> dict[str, str]:
    values: dict[str, str] = {}
    if CONFIG_FILE.is_file():
        try:
            for raw in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        except OSError:
            pass
    return values


def policy_root() -> Path:
    cfg = _config_values()
    return Path(os.environ.get("TEC_TAC_POLICY_ROOT") or cfg.get("TEC_TAC_POLICY_ROOT") or DEFAULT_POLICY_ROOT)


def policy_path() -> Path:
    return policy_root() / POLICY_FILENAME


def _normalize_level(value: object) -> str:
    level = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if level not in LEVEL_RANK:
        raise TrustPolicyError("Invalid update trust level. Expected unsigned, signed_development, signed_production, or secure_signed.")
    return level


def get_policy() -> dict:
    path = policy_path()
    level = "unsigned"
    updated_at = None
    updated_by = None
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TrustPolicyError(f"Update trust policy is unreadable: {exc}") from exc
        if not isinstance(data, dict) or int(data.get("schema", 0) or 0) != 1:
            raise TrustPolicyError("Update trust policy schema is invalid.")
        level = _normalize_level(data.get("minimum_level"))
        updated_at = data.get("updated_at")
        updated_by = data.get("updated_by")
    return {
        "schema": 1,
        "minimum_level": level,
        "minimum_label": LEVEL_LABELS[level],
        "levels": [{"id": item, "label": LEVEL_LABELS[item], "rank": LEVEL_RANK[item]} for item in LEVELS],
        "applies_to": ["system_updates", "modules"],
        "updated_at": updated_at,
        "updated_by": updated_by,
        "environment_isolation": True,
    }


def set_policy(level: str, *, updated_by: str | None = None, updated_at: str | None = None) -> dict:
    normalized = _normalize_level(level)
    root = policy_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / POLICY_FILENAME
    payload = {
        "schema": 1,
        "minimum_level": normalized,
        "updated_at": updated_at,
        "updated_by": str(updated_by) if updated_by else None,
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    return get_policy()


def classify_trust(trust: dict | None) -> str:
    trust = trust if isinstance(trust, dict) else {}
    if not bool(trust.get("signed")):
        return "unsigned"
    if not bool(trust.get("trusted")):
        # Invalid/untrusted signatures are not a lower accepted tier. They fail
        # before policy evaluation in the signature verifier.
        raise TrustPolicyError("Signed package is not trusted.")
    environment = str(trust.get("publisher_environment") or trust.get("release_environment") or "").strip().lower()
    assurance = str(trust.get("assurance") or "").strip().lower()
    if assurance in {"secure", "secure_signed", "high_assurance"}:
        if environment != "production":
            raise TrustPolicyError("Secure Signed requires a production publisher environment.")
        return "secure_signed"
    if environment == "production":
        return "signed_production"
    if environment == "development":
        return "signed_development"
    raise TrustPolicyError(f"Signed package publisher environment {environment or 'unknown'} cannot be mapped to an acceptance tier.")


def acceptance(trust: dict | None, *, minimum_level: str | None = None) -> dict:
    policy = get_policy()
    minimum = _normalize_level(minimum_level or policy["minimum_level"])
    actual = classify_trust(trust)
    accepted = LEVEL_RANK[actual] >= LEVEL_RANK[minimum]
    return {
        "minimum_level": minimum,
        "minimum_label": LEVEL_LABELS[minimum],
        "actual_level": actual,
        "actual_label": LEVEL_LABELS[actual],
        "accepted": accepted,
    }


def require_accepted(trust: dict | None, *, minimum_level: str | None = None, subject: str = "Package") -> dict:
    result = acceptance(trust, minimum_level=minimum_level)
    if not result["accepted"]:
        raise TrustPolicyError(
            f"{subject} trust level {result['actual_label']} is below the configured minimum {result['minimum_label']}."
        )
    return result
