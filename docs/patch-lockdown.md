# Patch lockdown: Tactical's own patch policy, off while Advanced Patch Management runs (core.patch_lockdown 1.0.0, Core 1.17.68)

When Advanced Patch Management (APM) is installed and honoured, an update you set to Ignore stays ignored. Tactical's own patch policy no longer approves it behind APM's back.

Johan asked for this on 21 October 2026: "the tactical patch policy must be disabled when APM is installed so that this doesn't happen." It was R-36. It replaces the warning that Core showed for a scheduled install since 1.17.66.

This page is for administrators and for module developers. It says what Core does, what it leaves alone, and how it fails.

## What went wrong before

Tactical's install call (`winupdate/views.py` `InstallWindowsUpdates.post`, and `winupdate/tasks.py` `bulk_install_updates_task`) first calls `agent.approve_updates()`. That method sets every not-yet-installed update to Approve when the endpoint's own patch policy approves its severity. It skips only updates already at Approve. So an update that APM set to Ignore was flipped back and installed. Tactical's two scheduled tasks, `auto_approve_updates_task` and `check_agent_update_schedule_task`, did the same on their own timetable.

## When it is active

`patch_lockdown.active()` is True only while a replacement of the core module `patching` is honoured right now. Core reads that from the module replacement state (AD-20, `tactical_operations._honoured_pairs()`), at most every 30 seconds. If Core cannot read the state, the answer is False and Core logs it once. A read fault never switches Tactical's patching off.

## What Core does while it is active

Three guards. None writes Tactical data.

1. **Tactical's own switches.** At start-up, in every process (web and Celery), Core sets `TRMM_DISABLE_APPROVE_UPDATES_TASK` and `TRMM_DISABLE_WINUPDATES_INSTALL_TASK` to True. These are documented Tactical settings. Core never sets one to False. If an administrator already set one, Core leaves it alone, even when that value keeps a Tactical task on. Enabling or disabling a module already reloads the web workers and restarts Celery, so these are read again and nothing needs a restart by hand.
2. **The approve is inert.** Core wraps `Agent.approve_updates` (the same pattern as the account guard). While active it returns without approving anything. Otherwise it calls Tactical's own method unchanged. So the install call no longer flips an update back.
3. **Status.** The capability `core.patch_lockdown` 1.0.0 answers `status()`:

| Key | Meaning |
|---|---|
| `active` | A replacement of Windows Patching is honoured right now. |
| `honoured_module` | The module's id, or None. |
| `tasks_off` | Both Tactical switches are True in this process. |
| `approve_guard_installed` | The guard on `Agent.approve_updates` is installed in this process. |

A premium replacement can drop its own "does not apply APM decisions" warning when `active` and `approve_guard_installed` are both True.

## What it does not block

The declared operations that APM registers (`scan`, `install`, `set-update-action`, `reset-patch-policy`, `add-patch-policy`, `edit-patch-policy`, `delete-patch-policy`) still run through Core's executor as the signed-in person. So do the system actions. The install still sends what is already approved. APM's own decisions are what Tactical installs.

For a scheduled install by the honoured replacement, Core's confirmation text and audit row no longer carry the re-approve warning while the lockdown is active and the guard is installed in the process that shows or sends it. Windows Patching's own install keeps the warning. The audit row says `patch_lockdown: active` when it replaces the warning.

## When it stops

The moment the replacement is no longer honoured, `active()` answers False (within 30 seconds) and Tactical's own approve works again. The two switches are read at the start of each process, so they go back with the restart that the module enable or disable already causes.

## How it fails

| Case | Result |
|---|---|
| The replacement state cannot be read | Inactive. Tactical keeps its own patching. One log line. |
| The guard cannot be installed (for example Tactical changed the method) | Tactical keeps working unchanged. `approve_guard_installed` is False. One log line. Core's warning stays. |
| A settings object refuses a write | Fails open. `tasks_off` is False. |
| The lockdown code fails at start-up | Logged. Tactical starts as it always did. |

## Audit

The Scheduler tick writes one row, `custom:tactical-patch-lockdown` (object type `tactical_patch_lockdown`), only when the state differs from the newest such row. It is not strict and never raises. It names three states, and every row carries `state` and `honoured_module`:

| State | When | What the row says |
|---|---|---|
| `on` | A replacement is honoured and the lockdown is in effect in the tick's process: Tactical's two switches are off, or the approve guard is installed. The metadata also carries `tasks_off` and `approve_guard`, so you can see which part is in effect. A switch an administrator had already set counts as in effect, although Core did not set it. | Tactical's own patch policy is switched off while the module replaces Windows Patching. |
| `held` | A replacement is honoured but nothing was switched off. For example applying failed in that process (the method was missing, or the settings object refused the write), or Core has the switch turned off. The metadata carries `reason` (`not_applied`, or `decision_not_recorded` when Core has it turned off). | Tactical's own patch policy is still on, and why. |
| `off` | No replacement is honoured. | Tactical's own patch policy works again. After a `held` row it says instead that the lockdown had changed nothing. |

## What is not built

- Refusing Tactical's own native `winupdate/` and `automation/patchpolicy/` mutating routes. This needs more Tactical view wrappers. The three guards above already stop the harm. A follow-up release can do it if Johan still wants Tactical's own screens blocked. Tec-Tac's own routes to those groups are already owner-gated (AD-20).
- Any write to Tactical's `WinUpdatePolicy` rows, a rule push, or a reboot with a result. They need a Tactical write outside AD-13 and AD-19. Question CQ203 asks Johan for the clause.

## Honest limits

- This is a named exception to checklist A2 and rule 1.7, which say Core touches Tactical only for authentication and accounts, plus the AD-13 background actions. Johan asked for it, and it is flagged for human review.
- Modules run in the same process as Core. Code that deliberately reaches into Core's private state is outside what this stops.
- An administrator who sets a Tactical switch to False on purpose keeps that task running. Core does not override an administrator.

> **On when its conditions hold (AD-41).** Johan signed the lockdown on 21 October 2026 ("1) signed"), and `patch_lockdown.DECISION_RECORDED` is True. The lockdown is ON only while an honoured replacement of `patching` is installed, and does nothing otherwise. Its conditions stay in force: it fails open, it never overrides an administrator's value, it never writes Tactical data, and it reads the replacement state at most every 30 seconds. A question about whether to sign it (CQ206) is answered by AD-41. Setting the flag to False is the one switch that turns the whole lockdown back into a no-op.
>
> `status()['active']` still means only that a replacement is honoured. A `held` audit row means a replacement is honoured but nothing was switched off in that process.
