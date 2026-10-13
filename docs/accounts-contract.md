# Accounts contract: create a user from an accepted invite, and the roles an inviter may grant

**Status:** Public Core developer contract, added in Core 1.17.27 (binding entry "accounts contracts for User Invite")
**Python:** `tec_tac.accounts.create_user`, `tec_tac.accounts.list_grantable_roles`
**Capability:** `core.accounts` 1.0.0, owner `core`
**Needs:** `requires.framework >=1.17.27`
**Who may call:** the `userinvite` module only (Core checks; see "Who may call")

## Why this exists

User Invite creates a Tactical account when someone accepts an invite. Until 1.17.27 it wrote Tactical's User model itself and read
Tactical's `/accounts/roles/` route. A server module must not do either (catalog note, AD-6). This contract is the path instead.

Core does the account work, so the same checks apply however the account is made: the password rules, the duplicate checks, the role's
rules, the superuser protection, the inviter check and the audit row.

## Who may call

Core verifies the calling module from the call stack (AD-26, CQ87). The module passes nothing in to name itself.

- The caller must be the code of an installed, enabled, non-legacy module on Core's allow-list. Today the list is `userinvite`.
- Any other caller gets `caller_not_allowed` and nothing is written. That includes a Core frame, a library frame, a generated frame, a
  disabled module and a call from code that is not inside a module.
- The allow-list is in Core (`CALLERS` in `tec_tac/accounts.py`). A module cannot add itself to it.

Because the public invite page is signed out, there is no signed-in user to check. Authority for `create_user` rests on three things:
the verified calling module, the purpose Core fixes (`accept-invite`), and the inviter re-check below. The module must still verify the
invite token and the emailed code before it calls. Core does not check those and never trusts the module's word about them.

## `create_user`

```python
from tec_tac.capabilities import get_capability

accounts = get_capability("core.accounts")
created = accounts.create_user(
    username="jane.doe",
    email="jane@example.co.za",
    first_name="Jane",
    last_name="Doe",
    role_id=7,
    password="a long passphrase the invitee chose",
    invited_by_id=3,  # the Tactical user id of the person who sent the invite
)
created.user_id, created.username, created.role_id
```

It returns a frozen `CreatedUser(user_id, username, role_id)`. It returns no password, no hash and no email.

Core checks, in this order:

1. The caller is on the allow-list (`caller_not_allowed`).
2. The inputs have the right types and limits (`invalid_input`). A bool is refused as a number. Username and email may not contain control
   characters. The username uses Django's username rule. First and last name may be blank, up to 150 characters.
3. The inviter is re-read from the database, now, not as they were when the invite was sent (`inviter_not_allowed`). The inviter must exist,
   be active, not be an installer user and still hold Tactical's `can_manage_accounts`. A superuser or a role superuser passes.
4. The role exists (`role_not_found`) and is not a superuser role (`role_not_grantable`). See "Superuser roles" below.
5. The username and the email are free, ignoring case (`username_taken`, `email_taken`). A database clash found on insert gives the same
   codes.
6. The password passes Django's password validators with Tactical's own `AUTH_PASSWORD_VALIDATORS` (`weak_password`). The validators run
   against a user that is not saved yet, so the check that the password is not too close to the name or email works. Messages describe the
   rule and never repeat the password.

Then, in one transaction:

- Tactical creates the user the way its own add-user does, with the password hashed. The names are set, and the role is set.
- Core never sets a TOTP key. The first sign-in then asks the user to set up two-factor sign-in (Core 1.17.22).
- Core writes one strict audit row. If that write fails, the user is rolled back (`audit_failed`).
- After the commit, Tactical's Mesh permission sync runs once, as Tactical's own view does.

### Errors

Every refusal raises a subclass of `tec_tac.accounts.AccountsError` with a stable `.code` and a plain-English `.message`. The message never
holds a password or an email.

| Code | Meaning |
| --- | --- |
| `invalid_input` | A value has the wrong type, is too long, has control characters, or is a bool or a non-positive number. |
| `username_taken` | The username is already used, ignoring case. |
| `email_taken` | The email is already used, ignoring case. |
| `weak_password` | The password fails Tactical's validators. |
| `role_not_found` | No role has that id. |
| `role_not_grantable` | The role is a superuser role. Refused while CQ86 is open. |
| `inviter_not_allowed` | The inviter is missing, inactive, an installer user or no longer holds `can_manage_accounts`. Nothing is created. |
| `caller_not_allowed` | The caller is not an enabled module on the allow-list. Nothing is created. |
| `audit_failed` | The Core audit row could not be written. Nothing is created. |

A refused call creates nothing and writes no success row.

### Audit row

One strict Core row per success, with:

- module `core`, action `add`, object type `user`, object id the new user's id;
- the actor is a Core service actor, named `<caller>.accept-invite` (for example `userinvite.accept-invite`). Core writes the row for the
  verified caller, so the module does not write it;
- the message "Tactical user created from an accepted invite.";
- metadata `role_id`, `invited_by_id`, `caller_module`, `purpose` (`accept-invite`) and `totp_set` (false).

The row never holds a password, a hash, a username or an email.

## `list_grantable_roles`

```python
roles = accounts.list_grantable_roles(request.user)
# [{"id": 7, "name": "Technician", "is_superuser": False}, ...]
```

- The rows are ordered by name, then id. Each row carries exactly `id`, `name` and `is_superuser`. No permission flags and no scope lists.
- An effective superuser (a Django superuser or a superuser role) sees every role. Anyone else sees the roles that are not superuser roles.
- The inviter must be authenticated, not an installer user and hold `can_manage_accounts`. Otherwise the call raises
  `accounts_permission_required` and returns nothing (AD-12).
- Same caller rule as `create_user`.

User Invite should hide rows with `is_superuser` true from its role picker until CQ86 is answered, because `create_user` refuses them.

## Superuser roles

While CQ86 is open, `create_user` refuses a superuser role for every inviter, including a superuser (`role_not_grantable`). The safest choice
was taken; Johan decides whether an invite may ever give a superuser role. The choices are in `reviews/questions/core.md`.

## What is not set

- No TOTP key (see above).
- No password is stored in a Core table or returned.
- No email is sent. The module sends its own invite and code mail through Global Settings (AD-30).

## Compatibility

Additive in 1.17.27. Nothing in `modules/` used `core.accounts` before this release. A module finds it with
`has_capability("core.accounts")`, and it needs `requires.framework >=1.17.27`.

Tactical's own `/accounts/users/` and `/accounts/roles/` routes are unchanged. Core's guard on them (`tactical_account_guard`) is unchanged.
