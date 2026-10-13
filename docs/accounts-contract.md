# Accounts contract: create a user from an accepted invite, and the roles an inviter may grant

**Status:** Public Core developer contract, added in Core 1.17.27 (binding entry "accounts contracts for User Invite")
**Python:** `tec_tac.accounts.create_user`, `tec_tac.accounts.list_grantable_roles`, `tec_tac.accounts.check_available` (1.17.29, `invited_by_id` since 1.17.30)
**Capability:** `core.accounts` 1.2.0, owner `core`
**Needs:** `requires.framework >=1.17.27` (`check_available`: `>=1.17.30`, with `invited_by_id`)
**Decisions:** AD-31 (the caller check, and condition 5, the accepted limit that Core does not verify the invite token); AD-34 condition 4 (`check_available` inviter re-check and Core limit)
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
invite token and the emailed code before it calls. Core does not check those and never trusts the module's word about them. This is an
accepted limit (AD-31 condition 5, Johan, 14 October 2026). Johan may later ask for a Core-issued one-time invite proof.

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

## `check_available` (since 1.17.29, inviter and limit since 1.17.30)

```python
answer = accounts.check_available("jane.doe", "jane@example.co.za", invited_by_id=request.user.pk)
answer.status, answer.username_taken, answer.email_taken
```

It tells the create step of an invitation whether the username or the email is already used, so the inviter hears it before the invite is sent.

- It returns a frozen `Availability(status, username_taken, email_taken)`. `status` is exactly `username_taken`, `email_taken` or `free`.
  When both clash, `status` is `username_taken`, the order `create_user` uses, and both flags are true.
- The match ignores case, with the same lookups as `create_user` (one shared helper, so they cannot drift).
- Same caller rule as `create_user`: only the verified, enabled `userinvite` module. Anyone else gets `caller_not_allowed` and no query runs.
- The inputs are cleaned as in `create_user`. A blank, over-long, control-character or malformed value raises `invalid_input`.
- `invited_by_id` is required (1.17.30). It is checked like `create_user`'s: a bool or a number that is not above zero raises `invalid_input`.
- Core re-reads the inviter and re-checks `can_manage_accounts`, as `create_user` does. A missing, inactive or installer-user inviter, or one who no
  longer holds the flag, raises `inviter_not_allowed`. No lookup runs and the call is not counted against the limit.
- Core limits each inviter to **30 answered calls per 10 minutes and 300 per day** (a Django cache counter per inviter id, counted only after the
  inviter check passes; the key holds no username or email). The next call raises `rate_limited`. If the counter cannot be read the call raises
  `rate_check_unavailable` and answers nothing. A limit hit writes a warning to the log and no audit row. The numbers are Core's choice and Johan may change them.
- Order of checks: verified caller, input cleaning, inviter re-check, rate limit, lookup.
- It is a read. It writes no audit row, no record and opens no transaction.
- It returns no user id, no name and no other field of the matching user. A taken answer is all it gives.

Core cannot see whether a person is signed in. So the module still binds `check_available` to the signed-in create step of an invitation,
never calls it from a signed-out page, and keeps its own rate limit next to Core's. Core's inviter re-check and limit (AD-34 condition 4) make
guessing account names slow and traceable to an inviter who holds `can_manage_accounts`. This stricter form is stricter than the open form by the
main session's choice on 14 October 2026 (CQ92 b); Johan may relax it to the plain signature.

## What is not set

- No TOTP key (see above).
- No password is stored in a Core table or returned.
- No email is sent. The module sends its own invite and code mail through Global Settings (AD-30).

## Compatibility

Additive in 1.17.27. Nothing in `modules/` used `core.accounts` before this release. 1.17.29 (capability 1.1.0) adds `check_available`, also
additive: `create_user` and `list_grantable_roles` behave exactly as before. 1.17.30 (capability 1.2.0, still major 1) gives `check_available` a required
`invited_by_id`, the inviter re-check and Core's limit, and two error codes (`rate_limited`, `rate_check_unavailable`). No module in `modules/` calls
`check_available` yet (User Invite 0.9.0 does not), so nothing breaks; a caller written for 1.17.29's two-argument form must pass the inviter. A module finds it with
`has_capability("core.accounts")`, and it needs `requires.framework >=1.17.27`.

Tactical's own `/accounts/users/` and `/accounts/roles/` routes are unchanged. Core's guard on them (`tactical_account_guard`) is unchanged.
