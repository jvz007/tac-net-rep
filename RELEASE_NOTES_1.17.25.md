# Tec-Tac Framework 1.17.25

This release tightens the "end every login session" button, makes moving a site follow Tactical's own rule, and lets Core send its one Priority 1 email through Tactical's own mail sender. It also closes the two Lows held from the 1.17.24 review.

Capability: `core.resources` goes from 1.7.0 to 1.8.0. It is still major 1. The move rule changes (Johan, CQ79), so the minor number moves with the documented rule. No record key or keyword changes.

Date: 13 October 2026.

## Module-facing changes

These change what a caller gets. Read them before you upgrade a module that calls Core.

- **`POST /api/tfd/access/sessions/revoke-all/` now ends the caller's own session by default.** `include_current` defaults to `true` (Johan, CQ76: "yes it should"). A caller that relied on the 1.17.24 default must now send `include_current: false` to keep its own session. Nothing in `modules/` or `workspace/ui` calls the route, so nothing breaks today. The response keys do not change.
- **Moving a site follows Tactical's rule (`core.resources` 1.8.0, CQ79).** A limited role may now move a site into a client it holds no grant on. Before, Core refused that with a 404. Tactical's Edit site checks only the Edit sites permission and the source site's scope, so Core does the same (Johan: "keep it the same as Tactical"). This loosens the 1.17.24 rule on purpose. A side effect to know about: a role that sees a client only through a site grant can now move its own site into that client.
- **A missing destination client gives a 400, not a 404.** The model's own foreign-key check answers, as Tactical does.
- **A same-client update now needs the site's write scope.** A caller who can read a site but cannot write it gets the same 404 as every other write. Before, a same-client update returned the site with a 200 (held Low, see below).
- **Core's Priority 1 email (AD-28 amendment).** Core now sends one email per failed module job to the Tec-Tac administrators, through Tactical's own sender. Core has no module contract for this. It is Core's own notice. It is on from this release wherever Tactical's email is set up and the mail server's name points at a public address (see below).

## Closes

In `reviews/requests/core.md`:

- "From Johan's answers to CQ76 to CQ79 (13 October 2026), binding for the next Core release" (CQ76 b, CQ79, with the two held Lows).
- "Core's Priority 1 email through Tactical's own sender (Johan chose (c), 13 October 2026; AD-28 amendment)".
- "Priority 1 email for module failures: use `globalsettings.email`" is superseded. The AD-28 amendment says Core does not go through Global Settings, so the request is closed, not built.
- The held Low "Revoke-all keeps no session if the caller's trust row has no bound digest".
- The held Low "Same-client site update returns before the write-scope check".

In `reviews/requests/ui.md`, two corrections go to the UI (see below): the Login sessions page (CO17) and the Edit site dialog (CO25).

## What changed

### End every login session: the caller's own session (CQ76, held Low)

- `include_current` defaults to `true`. An explicit `include_current: false` keeps the caller's own session. A non-boolean value, `null` included, is still refused `400`.
- With `include_current: false` Core spares two things: the caller's Knox token (its digest is not deleted), and the caller's own trust row (not revoked). A legacy trust row with no bound digest is spared by its primary key, so a live token is never left behind a revoked row. This is the held Low.
- `current_kept` is true only when both the token and the trust row were actually spared. It is never just the value of `include_current`. When nothing is spared (no digest known, or no row) it is false.
- The audit event (`all_login_sessions_revoked`) and the strict Core row (`custom:revoke-all-sessions`) carry `current_kept` next to `include_current`. Both still carry counts and flags only.
- The response keys are unchanged: `revoked_tokens`, `revoked_sessions`, `users`, `current_kept`.
- The Python function takes a new optional keyword, `current_session` (the caller's trust row, `request.tec_tac_session`). The view passes it.
- The contract text (`contracts.py`) and `docs/session-security.md` say the new default and what `current_kept` means. The caller is signed out by default, and the response is still delivered to that caller.

### Moving a site follows Tactical's rule (CQ79, held Low)

- `update_site` no longer checks a grant on the destination client. The source site's write scope still decides, and Edit sites still applies.
- The source site's write scope is checked before the same-client return, so a read-only caller gets the same `resource_not_found` refusal as every other write.
- Kept as before: the last site of a client cannot leave (400), a name clash in the destination is a 409, the same client is a no-op with no row (once the write scope holds), agents follow the site, and the audit row carries `client_changed`, `from_client_id`, `to_client_id` and `agents_moved` (ids and a count only).
- `create_site` keeps its own client grant check. Tactical's add-site rule is a different rule, and this release does not ask for it to change.
- `docs/resource-directory.md` ("Move a site") and the contract text in `resources.py` and `contracts.py` describe the new rule and name the loosening.

### Core's Priority 1 email through Tactical's sender (AD-28 amendment)

Johan chose option (c) on 13 October 2026. Core may call Tactical's own `CoreSettings.send_mail` in process, for its own Priority 1 notice (a failed module job), and for nothing else. The new file is `framwork/tec_tac/priority_mail.py`. It is the only place Core touches Tactical's mail.

- **Fields read.** Core reads `email_is_configured` (Tactical's own property: a yes or no), and `smtp_host`, the mail server's name, and nothing else. Core never reads the SMTP password, the port, the from address or the user name. The one field it reads is `smtp_host`, and this is why: Tactical connects to that name with its own code, so Core must judge where the name points before Tactical connects. Core holds no SMTP client, no second mail system and no fallback.
- **Off when not configured.** With Tactical's email not set up, nothing is sent and no row is written. The failure is still recorded in the app. Once email is set up, the failures from the last seven days are sent.
- **Who gets it.** The Tec-Tac administrators (active effective superusers with an address). The requester gets the email only when that person is an administrator. The requester always gets the in-app notice. One entry per address, case-insensitive, at most 20 per job. This is the reading of CQ80 that Core took (option (a), the narrower one). If Johan wants the requester emailed too, it is a one-line change.
- **Public-address check.** The name must resolve, and every address it resolves to must be public. Refused: an empty name, a name that does not resolve, loopback, link-local, unspecified, multicast, private (10.x, 192.168.x, 172.16 to 31), carrier-grade (100.64/10), the cloud metadata addresses (169.254.169.254, 169.254.170.2, 100.100.100.200, fd00:ec2::254), and an IPv4 address embedded in an IPv6 one (IPv4-mapped, NAT64, 6to4) when that IPv4 address is refused. The rule follows globalsettings' address check, but Core writes its own copy. Core imports nothing from a module. The check runs only when there is something to send.
- **A refusal.** Nothing is sent. The recipients are marked as tried, so the next tick does not repeat it. One count-only audit row is written. The in-app notice stays.
- **Addresses.** An address with a space, comma, semicolon, angle bracket, quote, control character, a missing or doubled `@`, non-ASCII text, or more than 254 characters is refused before it reaches the sender. Tactical joins recipients into one To header, so a comma would add a recipient. A refused address is not marked, and it sends nothing.
- **Hourly cap.** 20 emails in any rolling hour, counted from the existing marker rows (no migration). It is read once per sweep and spent across jobs. Over the cap, nothing is sent, nothing is marked, no row is written, and the count is logged at WARNING. A later hour sends the held failures, inside the seven-day window.
- **One message per recipient.** Each call is `send_mail(subject, body, override_recipients=[one address], test=True)`. `test=True` makes Tactical report a failed send instead of swallowing it and answering "ok". Tactical's returned text is discarded. It can name the host or the account, so it is never logged, returned or stored. The first failed send stops the job's loop and marks the rest as tried. A broken server is not retried every minute.
- **Audit.** One count-only row per job that reached the sender or the host check. Action `custom:priority-mail`, object type `module_job_email`, object id the job id, service provenance for Core. Metadata: `recipients`, `sent`, `refused`, `outcome` (`sent`, `refused` or `failed`), `code` (`mail_host_refused`, `send_failed` or `none`) and `requested_by` (`scheduler`). Never an address, a host, a subject, a body, Tactical's text or a password. The write is best effort (not strict), and a failed write is logged.
- **What is removed.** The 1.17.15 `_mail_settings()` (which returned None), the `_smtp_send` sender, and the `EmailMessage` builder. Core has no `smtplib` or `ssl` use left.
- **Subject and body.** Printable ASCII only, with no carriage return or line feed in the subject and no path in either.

## Accepted trade-offs and known gaps

- **Name re-resolved by Tactical.** Core checks the name, and Tactical resolves it again when it connects. A name that changes its answer between the two lookups is not covered (AD-28 trade-off). There is no certificate pinning, because Tactical connects with its own code.
- **Tactical's debug log.** When a send fails, Tactical's own DebugLog keeps the send's text. Core cannot stop that (AD-28 trade-off).
- **Private mail relays get the in-app notice only.** A Tactical server that sends through an internal relay (10.x, 192.168.x) is refused by the public-address check. Its administrators see the in-app notice and one count-only audit row. A setting to allow a private relay for this sender is not built. It waits on Johan (reviews/questions/core.md, CQ81).
- **Old failures and the window.** An email about a failure older than seven days is never sent.
- **CQ77 (answered, no change).** Assigning a client or site policy keeps Tactical's rule: the same write rule as a rename, with the policy ids in the audit row. It does not need `can_manage_automation_policies`.
- **CQ78 (known gap).** The session theme, held by Core for the signed-in session (1.17.24), is additive and stays as it is. Johan asked us to note it as a known gap and to make minor fixes later.

## Checks

Ran on this PC (Python 3.12, no Django):

- `tests/session-revoke-all-1.17.25.py` (new), `tests/session-revoke-all-1.17.24.py` (updated to the new default), `tests/resource-move-site-1.17.25.py` (new), `tests/resource-move-site-1.17.24.py` (updated), `tests/resource-directory-foundation.py` (updated pins and the move rule), `tests/resource-alert-template-1.17.17.py` (version pin), `tests/resource-policy-fields-1.17.24.py` (version pins), `tests/priority-mail-1.17.25.py` (new), `tests/module-failure-notices-email-1.17.15.py` (rewritten for the new sender), `tests/caller-identity-1.17.21.py` (seams adapted; every identity assertion kept), `tests/module-failure-notices-1.17.14.py` (unchanged, still passes).

Not run here, and why:

- The three dev-server runtime scripts: `tests/session-revoke-all-runtime-1.17.24.py` (updated to the new default), `tests/priority-mail-runtime-1.17.25.py` (new). Django, Knox and the Tactical database are not installed on this PC, so they could not run. They run only through Tactical's `manage.py shell` on the dev server.
- The PostgreSQL move test and the Tactical save hook test (`tests/resource-policy-runtime-1.17.24.py`). Both need the dev server too.
- `tests/release-integrity.sh` runs on this PC only with a `python3` shim (see the report).

## Dev-server step

After the release is built and signed, run on the dev server (dev branch, Core 1.17.25): `tests/session-revoke-all-runtime-1.17.24.py`, `tests/priority-mail-runtime-1.17.25.py` and `tests/resource-policy-runtime-1.17.24.py` through `manage.py shell`. Then export a fresh public contract into `docs/contracts`. The `core.resources` 1.8.0 rule appears only in the generated export.

## Files

- `framwork/tec_tac/priority_mail.py` (new): Tactical's sender, the public-address check, the address rule.
- `framwork/tec_tac/module_failure_notices.py`: the email half rewritten on the new sender, the cap, the audit row and the admin audience. The toast half is unchanged.
- `framwork/tec_tac/session_security.py`, `session_security_views.py`: the revoke default, the spared rows, `current_kept`.
- `framwork/tec_tac/resources.py`, `contracts.py`: the move rule, the write-scope check, `CONTRACT_VERSION` 1.8.0.
- `docs/session-security.md`, `docs/resource-directory.md`, `docs/caller-identity.md`, `docs/module-replacement.md`.
- `docs/releases/RELEASE_NOTES_1.17.24.md`: the 1.17.24 notes, moved from the root.
