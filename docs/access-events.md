# Access events (core.access_events 1.0.0, Core 1.18.50)

Core tells modules which people are affected when access changes. It never says what changed.

You need framework 1.18.50 or later. Check `has_capability('core.access_events')` first.

## What you get

| Name | What it is |
|---|---|
| `tec_tac.access_events.access_changed` | A Django `Signal`. Receivers get `user_ids` (a frozenset of Tactical user ids) and `reason`. |
| `tec_tac.access_events.changed_at(user_id)` | The time (seconds since the epoch) of the newest change for one person, or `None`. Reads the shared Django cache, so any process can ask. |

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
2. `notify_access_changed(user_ids, reason)` caps the list at 5000, writes one cache marker per person (`tec-tac:access:chg:<id>`, the time, kept 6 hours) and sends `access_changed` with `send_robust`. A faulty receiver never stops the others and never stops Tactical's own save. Inside a transaction the work runs when it commits, so a re-check never reads state that is not saved yet.
3. The m2m receiver also clears Tactical's `role_<name>` cache key. Tactical caches a role for 600 seconds and clears the key when the role is saved, but its editor sets the client and site lists after that save.

The signal fires in the process that saved the change (a web worker or a Celery worker). A websocket worker is a different process, so it never sees the signal. It reads `changed_at` from the cache instead.

## Who uses it

Core's tunnel relay (`core.probe_transport` 1.2.0). Each Console socket reads its own person's marker every 5 seconds. A marker newer than the last one it saw brings the 5-minute re-check forward to that tick, and the re-check decides. A real loss of the probe's site ends the session within about 5 to 10 seconds.

## What it does not cover

* Changes that fire no Django signal (`queryset.update`, raw SQL).
* A deleted site or client.

Keep a periodic re-check as the backstop for those. The tunnel keeps its 5-minute one.

## Rules for a module

* Connect your receiver from `AppConfig.ready()`. Re-read the person's access yourself; the signal only says who.
* Do not rely on the signal alone for a security decision. It is a hint to look sooner.
* A module cannot raise the signal. `notify_access_changed` and `mark_changed` are Core's own.
* Store nothing from the signal beyond what your own feature needs.
