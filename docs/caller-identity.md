# Verified calling-module identity: which module's code is calling

**Status:** Public Core developer contract, added in Core 1.17.21 (Johan CQ65 a, AD-26)
**Python:** `tec_tac.caller_identity.calling_module`
**Capability:** `core.caller_identity` 1.0.0, owner `core`
**Needs:** `requires.framework >=1.17.21`

## Why this exists

A provider module sometimes needs to know who is calling it. `globalsettings.email` is the first case: it should send mail for alerts, for the
report manager and for script execution, and for nobody else. Until 1.17.21 the caller named itself in an argument or a context dict, and
nothing checked the name.

`calling_module` answers from the call itself. The caller passes nothing in, so the caller cannot choose the answer.

## How a provider uses it

```python
from tec_tac.capabilities import has_capability

def send_message(...):
    if not has_capability("core.caller_identity"):
        raise PermissionError("Caller identity is not available.")
    from tec_tac.caller_identity import calling_module

    caller = calling_module(provider_module_id="globalsettings")
    if caller is None or caller.module_id not in ALLOWED_CALLERS:
        raise PermissionError("This caller is not allowed.")
```

`calling_module(*, provider_module_id)` returns a frozen `CallerIdentity(module_id, kind, module_version)` or `None`.

- `kind` is always `"module"`. The identity names signed modules only. Core is never a caller (AD-26 condition 2), so no answer is ever
  Core.
- `None` means refuse. A provider must treat it that way.

Call `calling_module` from the provider's own code, in the function the other module calls or in a plain helper it calls. A decorator, a
library or generated code between that function and `calling_module` is a gap, and the answer is `None` (see rule 3 below).

## How Core decides

Core walks the Python stack upward from the code that called `calling_module`. It judges each frame by the real path of its code file
(symbolic links and `..` are resolved, and case is normalised on Windows).

1. The frame that called `calling_module` must be inside the provider's own folder. The provider's frames that follow one another directly
   are skipped, so the provider can call this from any depth of its own code.
2. The first frame after the provider's frames is the caller, and only that frame. When it is inside the folder of an installed module, and
   that module is an extension, is not legacy and is enabled right now, the answer is that module. Core reads the enabled state on every call
   and never caches it.
3. Anything else in that position gives `None`, and Core does not look at the frames above it. No gap is skipped (AD-26 condition 3):
   - a frame in a disabled, legacy or unreadable module;
   - a frame inside the `tec_tac` package: the Scheduler's executor, the row-lookup call, signal dispatch, `send_p1_email` and the `send`,
     `have`, `mark`, `recent`, `audit` and `configured` callables it runs, `sweep_failed_jobs` and its seams, and `priority_mail` (Tactical's
     sender). Core is never a caller;
   - a frame with a generated file name (`<string>`, `<lambda>` built with `eval` or `compile`);
   - a standard-library, Django, DRF, Celery or other third-party frame.

   So a module's callable that Core or a library runs (a Scheduler handler, a row lookup, a signal receiver, a `functools.partial` of a
   provider function) is that module only when its own code frame calls the provider directly. A Scheduler handler written as a plain
   function in the module that calls the provider is identified. A thread a module started is identified when the module's own function
   calls the provider, not when the provider function itself is the thread's target.

Any error reading the module registry or the module state gives `None` (fail closed). If the provider is not an installed extension, the answer
is `None` too.

## The limits

These are part of the contract. A provider must not assume more.

- **Core is never a caller.** No Core frame, entry point or path answers Core. A module that gets Core to run its callable (a Scheduler
  handler, a Tactical row lookup, a signal receiver, a `functools.partial` of a provider function) is that module only when its own frame
  calls the provider directly. A Core, library or generated frame in between gives `None`, and the provider refuses. Core publishes no
  function that calls a provider on behalf of another module. (Three review rounds of 1.17.21 found ways to pose as Core through a trusted
  Core entry, so Johan removed Core as a caller on 11 October 2026.)
- **Through another module's code, the caller is that module.** A module that calls another module's code is seen as the module whose code makes
  the call. So an allow-list of modules is only as strong as every allowed module's callback surface. An allowed module that runs callables
  other modules hand it (a hook list it runs, a signal it sends) can be made to call the provider for them, when its own frame makes that
  call. A provider allows only modules whose code it trusts that far.
- **Forged file names are hostile code.** Code that forges its own file name (`compile()` with another module's path) is hostile code. Signed-module
  review stays the defence.
- **Module, not person.** Identity says which module's code is calling, not which person is behind the call. A provider still checks the
  person, or the service purpose, itself.

## What does not change

`ResourceAccessContext`, `trusted_service_context`, `build_operation_context` and `notices.publish` behave as before. Nothing that was accepted is
refused by this release. A provider opts in by calling `calling_module`.

Core's own Priority 1 notice email does not go through caller identity. From 1.17.25 it goes through Tactical's own sender (the AD-28
amendment): `module_failure_notices.send_p1_email` calls `priority_mail.send_one`, which calls Tactical's `CoreSettings.send_mail` in
process, to the administrators only. Core is never a caller of a module's contract, it does not go through Global Settings (AD-26
condition 2), and it never reads the SMTP password. It has no SMTP client of its own. From 1.17.26 an administrator may let this email use a mail
server on a private network (AD-30). From 1.17.28 that is withdrawn (AD-30 amendment): every sender, Core's own included, uses the
public-address check only, so no call-stack test decides a mail path any more (`module_frame_on_stack` is removed).

## Server modules (1.17.26 note)

`calling_module` keys on the enabled extension's folder, not on its category. A signed module with `category: "server"` (User Invite is the
first) is verified exactly like a core or premium module while it is installed, an extension, not legacy and enabled. A provider that
allows it by id gets its identity, and AD-30 lets such a module send mail through Global Settings on that basis. Pinned by
`tests/caller-identity-server-module-1.17.26.py`.

## Core as a provider (1.17.27 note)

A Core provider, such as `core.accounts` (`docs/accounts-contract.md`), also needs to know which module is calling it. Its signed-out
caller has no session to check. For that, Core has a private, Core-internal helper, `tec_tac.caller_identity.calling_module_for_core_provider(*,
provider_file)`. It is not a public contract: it is not in the contract export and no module may import it. It works from the same rules as
`calling_module`. Every frame in the provider's own file is skipped, and the first other frame must be the code of an enabled, non-legacy
extension, or the answer is `None`. Core is still never identified as a caller (AD-26 condition 2). `calling_module` and the
`core.caller_identity` 1.0.0 contract are unchanged by 1.17.27. Since 1.17.48 a second private helper, `core_provider_caller_checked(*, provider_file, cache_seconds=0)`, returns a small result with `identity` and `unverifiable` so that a provider can tell a foreign caller from a failed read of the module list or state; `calling_module_for_core_provider` is a thin wrapper over the same walk and still answers `None` for both. A failed read in the opt-in snapshot is kept for 1 second (`FAILED_READ_SECONDS`), not the whole window. The public `calling_module` stays uncached and unchanged. Pinned by `tests/caller-identity-core-provider-1.17.27.py`.

Since Core 1.17.30, AD-34 extends AD-31 condition 2 (a Core provider may verify its module caller) from `core.accounts` to two more Core
providers: `core.resources` (`trusted_service_context(global_access=False)`, the module `userinvite` only, actor named the same) and
`core.audit` (a deny row from a server module, see `docs/module-audit.md`). Each calls the same private helper with its own `__file__`.
So a Core provider may verify its module caller in `core.accounts`, `core.resources` and `core.audit`, and nowhere else without Johan's
sign-off in chat (AD-34 condition 2). The helper stays private and `core.caller_identity` stays at 1.0.0. Pinned by
`tests/resource-service-context-1.17.30.py` and `tests/audit-server-module-deny-1.17.30.py`.

Core 1.17.37 added `core.module_preferences` as the fourth. Core 1.17.47 adds `core.event_jobs` as the fifth (AD-31 condition 2, AD-34
condition 2, AD-36): `EventJobPublisher.publish` verifies that the first frame above it is the code of the enabled module that owns the job.
This provider alone passes the private helper an opt-in `cache_seconds` (5): the module list and each enabled flag come from a process-local
snapshot kept that long, because the publish runs on every Tactical alert save. A failed read is kept for the same window and the caller is
refused. The frame walk is never cached, and at the default of 0 nothing is cached, so the other providers still read the state on every
call. The public `calling_module` is never cached (AD-26: enabled state is read on every call). Pinned by `tests/event-jobs-caller-1.17.47.py`.

## Feature detection

`has_capability("core.caller_identity")` is true from Core 1.17.21. The capability metadata lists the limits above in `limits`, gives
`kinds: ["module"]` and `core_is_caller: false`.
Tests: `tests/caller-identity-1.17.21.py`.
