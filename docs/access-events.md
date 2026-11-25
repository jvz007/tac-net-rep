# Access events (Core-internal, Core 1.18.51)

Core marks which people are affected when access changes. It never says what changed.

This is **Core-internal. It is not a capability.** Core 1.18.50 offered it to modules as `core.access_events` 1.0.0. The 1.18.50 review found that this gave every module a read of other people's changes without a signed decision. Core 1.18.51 withdraws it: nothing is registered, the two contract rows and the public Signal are gone, and no module may connect to, read or raise access events. No module in `modules/` used them. Johan decided on 25 November 2026 that modules may listen only in a declared form (the manifest names it, the review checks the reason, the admin sees it at install). That form is built the first time a module needs it; until then there is none (`reviews/questions/core.md`).

## What Core keeps

| Name | What it is |
|---|---|
| `_access_changed` | A private Django `Signal`. Core has no consumer of it today. Receivers get `user_ids` (a frozenset of Tactical user ids) and `reason`. |
| `changed_at(user_id)` | The time (seconds since the epoch) of the newest change for one person, or `None`. Reads the shared Django cache, so Core's tunnel relay (another process) can ask. |
| `notify_access_changed(user_ids, reason)` | Used by Core's receivers on Tactical's models. |
| `mark_changed(user_ids)` | Used by `probe_tunnel.update_site` when an owner moves a probe to another site. No signal. |

`reason` is one of:

| Reason | When |
|---|---|
| `role_permissions` | A role is saved or deleted, or a Tec-Tac extension permission of a role is saved or deleted. |
| `role_scope` | A role's client or site list changes (either side of the many-to-many: from the role, or from the client or site). |
| `user_changed` | A user's role, active flag, superuser flag or dashboard block changes. A save that names other fields only (a `last_login` save, a preference) does not fire. |
| `user_removed` | A user is deleted. |

A newly created role, user or permission row fires nothing: nobody holds it yet.

## How it works

1. A receiver on Tactical's models finds the people affected (the users of the role, or the one user).
2. `notify_access_changed(user_ids, reason)` caps the list at 5000, writes one cache marker per person (`tec-tac:access:chg:<id>`, the time, kept 6 hours) and sends the private signal with `send_robust`. A faulty receiver never stops the others and never stops Tactical's own save. Inside a transaction the work runs when it commits, so a re-check never reads state that is not saved yet.
3. The m2m receiver also clears Tactical's `role_<name>` cache key. Tactical caches a role for 600 seconds and clears the key when the role is saved, but its editor sets the client and site lists after that save.

The signal fires in the process that saved the change (a web worker or a Celery worker). A websocket worker is a different process, so it never sees the signal. It reads the marker from the cache instead.

## Who uses it

Core's tunnel relay (`core.probe_transport` 1.2.0) reads the marker as Core's own. Each Console socket reads its own person's marker every 5 seconds. A marker newer than the last one it saw brings the 5-minute re-check forward to that tick, and the re-check decides. A real loss of the probe's site ends the session within about 5 to 10 seconds. The owner of the tunnel (`networkprobe`) needs nothing for this.

## What is enforced

Each function checks its caller from the call stack. It judges the first frame outside `access_events.py` by real file path:

| Function | Accepts only |
|---|---|
| `notify_access_changed` | Django's own signal dispatcher (`django/dispatch/dispatcher.py`), which is how Core's model receivers run. |
| `mark_changed` | `probe_tunnel.update_site`. |
| `changed_at` | `probe_tunnel.access_changed_at`. |

Any other caller is refused. That includes a module's code, and also a library frame such as `threading` or a `functools.partial` that Core's Scheduler runs for a module. A refusal changes nothing: a writer returns 0, the reader returns `None`, nothing is written or sent. A refused writer logs one warning a minute at most, so a loop cannot flood the log. If the check itself cannot be completed, the call is refused. The 5-minute re-check stays as the backstop.

## What is not enforced

Ordinary calls from module code are refused by caller. Hostile code is a different matter. Code that reaches private underscore names, forges a file name, calls Django's own model signals itself or writes the shared cache key directly is not stopped here. Signed-module review is the defence for that, the same limit as `docs/caller-identity.md`.

## What it does not cover

* Changes that fire no Django signal (`queryset.update`, raw SQL).
* A deleted site or client.

The tunnel keeps its 5-minute re-check as the backstop for those.
