"""Core accounts contract (Core 1.17.27): create a Tactical user from an accepted invite, list the roles an inviter may grant, and (1.17.29) say whether a username or email is free.

Binding entry "accounts contracts for User Invite" (reviews/requests/core.md). A server module such as User Invite must not write
Tactical's User model or call Tactical's roles route (AD-6). This module is that path, and it is the only place Core creates a
Tactical account for a module.

Core decides, whoever calls and whatever the module says:

* The caller is an enabled module named in CALLERS, verified from the call stack (AD-26, CQ87). Nothing is passed in, so the
  module cannot choose its own identity or its own purpose.
* The inviter (``invited_by_id``) is read again from the database at acceptance. It must exist, be active, not be an installer user
  and still hold Tactical's ``can_manage_accounts``.
* A superuser role is refused by ``create_user`` while CQ86 is open. A role that does not exist is refused too.
* The username and email are free, ignoring case. The password passes Django's validators with Tactical's own
  AUTH_PASSWORD_VALIDATORS, run against an unsaved user so the similarity check works.
* Core never sets a TOTP key, so the first-sign-in two-factor set-up (Core 1.17.22) takes over.
* The user, the role lookup and one strict Core audit row are in one transaction. A failed audit write rolls the user back.
* Tactical's Mesh permission sync runs once, after the commit, as Tactical's own view does.

The module still checks the invite token and the emailed code before it calls. Core does not, and says so in docs/accounts-contract.md.
That is an accepted limit (AD-31 condition 5, Johan, 14 October 2026). The caller check itself is AD-31 conditions 1 and 2.

``check_available`` (1.17.29) is a read for the create step of an invitation. It has the same caller rule as ``create_user`` and answers taken or
free for a username and an email, and nothing else about any user. Core cannot see whether a person is signed in, so the module calls it only from
the signed-in create step and rate-limits it (docs/accounts-contract.md).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from accounts.models import Role, User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction

from .audit import record, service_audit_actor
from .caller_identity import calling_module_for_core_provider
from .rbac import is_effective_superuser, tactical_permission_flags

logger = logging.getLogger("tec_tac.accounts")

CAPABILITY_ID = "core.accounts"
CAPABILITY_VERSION = "1.1.0"
CALLERS = ("userinvite",)  # Core decides this list (AD-26 condition 5); a module cannot add itself
PURPOSE = "accept-invite"  # the only purpose; a caller cannot choose it
MANAGE_FLAG = "can_manage_accounts"  # the flag Tactical's own POST /accounts/users/ needs; no second gate (AD-5)
USERNAME_MAX = 150
EMAIL_MAX = 254
NAME_MAX = 150
AUDIT_OBJECT_TYPE = "user"
AUDIT_MESSAGE = "Tactical user created from an accepted invite."
ERROR_CODES = (
    "invalid_input", "username_taken", "email_taken", "weak_password", "role_not_found", "role_not_grantable",
    "inviter_not_allowed", "caller_not_allowed", "accounts_permission_required", "audit_failed",
)


class AccountsError(Exception):
    """A refusal from core.accounts. ``code`` is stable; the message is plain English and never holds a password or an email."""

    code = "accounts_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidInput(AccountsError):
    code = "invalid_input"


class UsernameTaken(AccountsError):
    code = "username_taken"


class EmailTaken(AccountsError):
    code = "email_taken"


class WeakPassword(AccountsError):
    code = "weak_password"


class RoleNotFound(AccountsError):
    code = "role_not_found"


class RoleNotGrantable(AccountsError):
    code = "role_not_grantable"


class InviterNotAllowed(AccountsError):
    code = "inviter_not_allowed"


class CallerNotAllowed(AccountsError):
    code = "caller_not_allowed"


class AccountsPermissionDenied(AccountsError):
    code = "accounts_permission_required"


class AuditFailed(AccountsError):
    code = "audit_failed"


@dataclass(frozen=True)
class CreatedUser:
    """What create_user returns: ids and the username only. Never a password, a hash or an email."""

    user_id: int
    username: str
    role_id: int


@dataclass(frozen=True)
class Availability:
    """What check_available returns. ``status`` is exactly ``username_taken``, ``email_taken`` or ``free``. No id, name or other user field."""

    status: str
    username_taken: bool
    email_taken: bool


def _verified_caller():
    """The enabled module on CALLERS that called this function, or CallerNotAllowed. Fails closed."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None or identity.module_id not in CALLERS:
        raise CallerNotAllowed("This caller may not use the accounts service.")
    return identity


def _text(value, label: str, *, maximum: int, allow_blank: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_blank) or len(value) > maximum:
        raise InvalidInput(f"{label} must be text of up to {maximum} characters.")
    if any(ord(ch) < 32 for ch in value):
        raise InvalidInput(f"{label} may not contain control characters.")
    return value


def _positive_id(value, label: str) -> int:
    # A bool is an int in Python, so True would be id 1. Refuse it, like any other non-int.
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InvalidInput(f"{label} must be a whole number above zero.")
    return value


def _username(value) -> str:
    username = _text(value, "The username", maximum=USERNAME_MAX)
    try:
        UnicodeUsernameValidator()(username)
    except DjangoValidationError:
        raise InvalidInput("The username may use only letters, numbers and the characters @ . + - _.") from None
    return username


def _email(value) -> str:
    email = _text(value, "The email address", maximum=EMAIL_MAX)
    try:
        validate_email(email)
    except DjangoValidationError:
        raise InvalidInput("Enter a valid email address.") from None
    return email


def _inviter_allowed(invited_by_id: int) -> None:
    """Re-read the inviter now, not as they were when the invite was sent (AD-13 owner re-check)."""
    inviter = User.objects.filter(pk=invited_by_id).first()
    if inviter is None or not inviter.is_active or inviter.is_installer_user:
        raise InviterNotAllowed("The person who sent this invite can no longer create accounts.")
    if not tactical_permission_flags(inviter, (MANAGE_FLAG,))[MANAGE_FLAG]:
        raise InviterNotAllowed("The person who sent this invite can no longer create accounts.")


def _grantable_role(role_id: int):
    role = Role.objects.select_for_update().filter(pk=role_id).first()
    if role is None:
        raise RoleNotFound("That role no longer exists.")
    if role.is_superuser:
        # CQ86 is open: a superuser role is never given through an invite. Johan decides whether that changes.
        raise RoleNotGrantable("A superuser role cannot be given through an invite.")
    return role


def _clashes(username: str, email: str) -> tuple[bool, bool]:
    """(username taken, email taken), ignoring case. The one lookup that create_user and check_available share, so they cannot drift."""
    return (
        User.objects.filter(username__iexact=username).exists(),
        User.objects.filter(email__iexact=email).exists(),
    )


def _check_free(username: str, email: str) -> None:
    username_taken, email_taken = _clashes(username, email)
    if username_taken:
        raise UsernameTaken("That username is already taken.")
    if email_taken:
        raise EmailTaken("That email address already has an account.")


def _check_password(password: str, *, username: str, email: str, first_name: str, last_name: str) -> None:
    # Unsaved, so UserAttributeSimilarityValidator can compare the password with the name and email being set.
    candidate = User(username=username, email=email, first_name=first_name, last_name=last_name)
    try:
        validate_password(password, user=candidate)
    except DjangoValidationError as exc:
        # Django's messages describe the rule and never repeat the password.
        raise WeakPassword("The password is too weak. " + " ".join(exc.messages)) from None


def _write_audit(caller, *, user, role, invited_by_id: int) -> None:
    """One strict Core row. The actor is a Core service actor named for the verified caller (Core writes it, the module does not)."""
    try:
        record(
            actor=service_audit_actor(module_id="core", service=PURPOSE, identity=f"{caller.module_id}.{PURPOSE}"),
            module_id="core",
            action="add",
            object_type=AUDIT_OBJECT_TYPE,
            object_id=str(user.pk),
            message=AUDIT_MESSAGE,
            metadata={
                "role_id": role.pk,
                "invited_by_id": invited_by_id,
                "caller_module": caller.module_id,
                "purpose": PURPOSE,
                "totp_set": False,
            },
            strict=True,
        )
    except Exception as exc:
        raise AuditFailed("The account was not created because the audit record could not be written.") from exc


def _sync_mesh_permissions() -> None:
    try:
        from core.tasks import sync_mesh_perms_task

        sync_mesh_perms_task.delay()
    except Exception:
        logger.exception("Tactical Mesh permission sync could not be queued after an invite account was created.")


def create_user(*, username, email, first_name, last_name, role_id, password, invited_by_id) -> CreatedUser:
    """Create a Tactical user for an accepted invite. Typed errors (AccountsError subclasses) and nothing is created on a refusal.

    Callable only by a verified caller on CALLERS. ``invited_by_id`` is the person who sent the invite. The module checks the invite
    token and the emailed code first; Core does not.
    """
    caller = _verified_caller()
    username = _username(username)
    email = _email(email)
    first_name = _text(first_name, "The first name", maximum=NAME_MAX, allow_blank=True)
    last_name = _text(last_name, "The last name", maximum=NAME_MAX, allow_blank=True)
    role_id = _positive_id(role_id, "The role")
    invited_by_id = _positive_id(invited_by_id, "The inviter")
    if not isinstance(password, str):
        raise InvalidInput("The password must be text.")
    try:
        with transaction.atomic():
            _inviter_allowed(invited_by_id)
            role = _grantable_role(role_id)
            _check_free(username, email)
            _check_password(password, username=username, email=email, first_name=first_name, last_name=last_name)
            user = User.objects.create_user(username, email, password)
            user.first_name = first_name
            user.last_name = last_name
            user.role = role
            user.save()
            _write_audit(caller, user=user, role=role, invited_by_id=invited_by_id)
            transaction.on_commit(_sync_mesh_permissions)
    except IntegrityError:
        # A row written between the check and the insert (a race). Name the clash the same way the check does.
        if User.objects.filter(username__iexact=username).exists():
            raise UsernameTaken("That username is already taken.") from None
        raise EmailTaken("That email address already has an account.") from None
    return CreatedUser(user_id=user.pk, username=user.username, role_id=role.pk)


def check_available(username, email) -> Availability:
    """Is this username or email free? A read for the signed-in create step of an invitation (1.17.29, capability core.accounts 1.1.0).

    Same verified caller rule as create_user (CallerNotAllowed), and the same case-insensitive lookups. When both clash, ``status`` is
    ``username_taken``, the order create_user uses, and both flags are true. No audit row, no write, no transaction, and nothing about the
    matching user is returned. Core cannot see whether a person is signed in: the module calls this only from the signed-in step and rate-limits it.
    """
    _verified_caller()
    username = _username(username)
    email = _email(email)
    username_taken, email_taken = _clashes(username, email)
    status = "username_taken" if username_taken else "email_taken" if email_taken else "free"
    return Availability(status=status, username_taken=username_taken, email_taken=email_taken)


def list_grantable_roles(inviter) -> list[dict]:
    """The roles the signed-in inviter may grant: [{id, name, is_superuser}], ordered by name then id.

    An effective superuser sees every role; anyone else sees the roles that are not superuser roles. Denied (accounts_permission_required)
    without Tactical's can_manage_accounts, for an unauthenticated user, an installer user or a user with no role.
    """
    _verified_caller()
    if not tactical_permission_flags(inviter, (MANAGE_FLAG,))[MANAGE_FLAG]:
        raise AccountsPermissionDenied("You need Tactical's permission to manage accounts to see the roles you may grant.")
    roles = Role.objects.order_by("name", "id")
    if not is_effective_superuser(inviter):
        roles = roles.filter(is_superuser=False)
    return [
        {"id": row["id"], "name": row["name"], "is_superuser": bool(row["is_superuser"])}
        for row in roles.values("id", "name", "is_superuser")
    ]


def accounts_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.accounts",
        "operations": ["create_user", "list_grantable_roles", "check_available"],
        "availability_statuses": ["username_taken", "email_taken", "free"],
        "check_available": (
            "check_available(username, email) -> Availability(status, username_taken, email_taken); same verified caller rule as create_user; "
            "case-insensitive; a read with no audit row; returns no user detail. The module calls it only from the signed-in create step and rate-limits it (AD-31)."
        ),
        "accepted_decisions": ["AD-31"],
        "limits": "Core does not verify the invite token or the emailed code; the module does (AD-31 condition 5, an accepted limit).",
        "callers": list(CALLERS),
        "purpose": PURPOSE,
        "errors": list(ERROR_CODES),
        "superuser_roles": "refused by create_user while CQ86 is open; list_grantable_roles lists them to an effective superuser only",
        "creates_totp_key": False,
        "audit": {"module_id": "core", "action": "add", "object_type": AUDIT_OBJECT_TYPE, "strict": True, "rows_per_success": 1},
        "requires_framework": ">=1.17.27 (check_available: >=1.17.29)",
    }


class _CoreAccountsProvider:
    create_user = staticmethod(create_user)
    list_grantable_roles = staticmethod(list_grantable_roles)
    check_available = staticmethod(check_available)


_PROVIDER = _CoreAccountsProvider()


def register_core_accounts_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Tactical accounts for an accepted invite and the roles an inviter may grant, for verified callers only.",
        operations=("create_user", "list_grantable_roles", "check_available"),
        metadata=accounts_contract_metadata(),
    )
