# Tec-Tac Framework 1.17.98

Date: 2 November 2026. Round 5 (this rebuild) changes how System Update treats the source checkouts: they stay Tactical-owned and clean, and root installs only from a verified staging copy. See "Fixed after review (round 5)" at the end; it replaces the seal and hand-back of rounds 1 to 4. The online update check now costs far fewer GitHub requests: a branch refresh sends one, the stable release is checked on its own, results are saved by commit, and Core stops asking while GitHub's limit is exhausted. The source checkout no longer trips Git's "dubious ownership" refusal, and the rollback installer shows the real reason when its version check fails.

Closes: Johan's request of 2 November 2026 ("with the next core build, include the github ratelimit optimization", spec `docs/core-github-rate-limit-optimization.txt`), the `reviews/requests/core.md` entries "Core: GitHub update-check rate-limit optimisation" and "Core: the system updater misreports a Git refusal as uncommitted tracked changes" (test server tt01), the rollback `NameError: framework_version` from tt01, and the held Low of the 1.15.115-1 review ("Escaped quotes in the new assert messages are stripped by the inner bash -lc").

## What changed and why

1. **One GitHub transport, `github_get_json` (rate limit A).**
   * Every metadata call (releases/latest, commits/<tag>, branches/<ref>, the branch list, file contents) goes through it, on top of the unchanged token and redirect rules (`_github_headers`, `_github_open`).
   * Order: a fresh saved answer needs no request. A stale one is revalidated with `If-None-Match`; a 304 only refreshes `checked_at` and returns the saved body, a 200 saves body, ETag and Last-Modified. A transport failure (network, timeout) with a saved answer raises `GithubUnreachableError` carrying that answer (1.17.98-4): callers show it as stale with the error set and never record it as a fresh check. A 401, or a 403 that is not a rate limit, is an error and is never saved as a success.
   * Every response, 304 and errors included, updates the rate-limit telemetry (`limit`, `remaining`, `used`, `reset`, `reset_at`, `resource`, `authenticated`, `observed_at`, `limited`). `authenticated` is only whether an Authorization header was sent. The token is never saved, logged or returned.
   * A 403 or 429 with `remaining` 0 or a `Retry-After` raises `GithubRateLimitError` (code `github_rate_limit_exceeded`, detail "GitHub API rate limit exhausted.", `reset_at`, `cached_data_available`). The saved answer is kept and shown with a warning. While the saved reset time is in the future Core sends nothing; the same error comes back from the saved state.
   * **Single flight.** A refresh takes a lock file in the cache folder (`fcntl.flock` across uWSGI workers, plus a thread lock). The first caller sends the request; the others wait up to 20 seconds and read what it saved. A lock that cannot be taken fails closed to the saved answer, never to a second request. Every write to the cache file happens under a short cache lock so workers do not lose each other's updates.
   * **Suppression.** A forced branch refresh inside 20 seconds of the last network check, and a forced release refresh inside 45 seconds, return the saved answer with `refresh {network_request: false, reason: "recently_refreshed"}`.
   * **Cache file schema 2**, additive over schema 1: `components` and `branches` stay; new `branch_sources`, `commit_metadata`, `release_verification` and `github {rate_limit, etags}`. A schema 1 file is read as it is and saved as schema 2 by the next write. A corrupt or wrong-shape file reads as empty and is rewritten. The ETag copies are trimmed to the fields Core reads and capped at 64 entries.
   * `github_rate_limit` is in the online status answer and in `GET /api/tfd/system/updates/`, read from the saved copy only. The job routes and `system_status` never call GitHub.
2. **A branch refresh costs one request, the release is independent (rate limit B).**
   * A branch refresh sends `GET /branches/<ref>` (conditional) and compares the head with the installed provenance commit. It never fetches the stable release. Under a branch source the release is read from the saved copy and shown with `cache.stale` until `refresh=release` or `all`.
   * The VERSION file at a commit is read only when no installed commit is known, saved by `repo:sha` with no expiry (content at a commit never changes) and reused.
   * The signature preview (two contents calls) is saved by repository, release commit and a fingerprint of the trust policy and publisher keys. A policy or key change re-checks it. Network errors are never saved. The preview is display only: staging still ends in `inspect_archive` (signed tree, publisher, `framework.update` / `ui.update` permission) and the root helper verifies again, unchanged.
   * A page load with a fresh cache sends no request. A stale page load sends at most one conditional request per component (a release source whose release changed needs the commit and signature calls as well). Framework plus UI branch refresh: 2 requests in total.
3. **`refresh` parameter and a stage pinned to the shown commit (rate limit C).**
   * `GET /api/tfd/system/updates/online/?refresh=none|branch|release|all`. `none` is the default. An invalid value is 400. `force=true` stays: for a branch source it means `refresh=branch`, for a release source `refresh=release`, never `all`.
   * New answer keys: `refresh {network_request, reason, requested}`, `github_rate_limit`, and when GitHub's limit is exhausted `github_rate_limit_error` with the saved answer and HTTP 200. With nothing saved the route answers HTTP 429 with the same body and `cached_data_available: false`. The branch list and the stage route map the error the same way.
   * `POST /api/tfd/system/updates/online/stage/` accepts an optional `commit` (40 hex). It must equal the saved branch head or the saved release commit the check showed; Core then makes no metadata call and downloads exactly that commit. A mismatch or no saved check answers 409 `{code: "stale_candidate", detail}`. Core never installs another commit silently. Without `commit` nothing changes. The recorded `source.commit` is the pinned SHA.
4. **System updater source checkout (`scripts/system-update-helper.py`).**
   * `_git` passes `-c safe.directory=<path>` only for the two configured source paths (`TEC_TAC_FRAMEWORK_SOURCE`, `TEC_TAC_UI_SOURCE`), never `*` and never another path.
   * **Fail-closed hardening**, because root now runs Git in a tree the Tactical account can write to: Git runs with `core.hooksPath=/dev/null`, `core.fsmonitor=false`, `core.attributesFile=/dev/null`, no user or system Git config, no prompts. The directory and `.git` must belong to the Tactical account or root, or the helper refuses before any Git call with the owner found, the owner expected and the `chown` command. A checkout whose `.git/config` sets a filter, include, external program or pager, or whose `.git/info/attributes` is not empty, is refused too.
   * `prepare_source_checkout` tells exit 1 of `git diff --quiet` (changes) from any other exit (a Git error): the message carries Git's own text, for example "detected dubious ownership". For changes it lists the dirty tracked paths (`git status --porcelain --untracked-files=no`), at most 20, control characters removed, ending "Restore or review these changes before updating."
   * (Replaced in round 5: nothing is handed back any more, because root no longer writes into the checkout.) At the end of the job (success, failure and rollback alike) files root created in a Tactical-owned checkout, `.git` included, go back to the Tactical account. It walks that one checkout, never follows a link, never touches `/opt/tec-tac`. A root-owned checkout stays root-owned. The runtime tree stays root-owned.
5. **Rollback installer: no more `NameError: framework_version` (`install.sh`).** `run_verify_step` put the check code inside `bash -lc "... shell -c \"${code}\""`, so every double quote in a check ended the quoting. `c["framework_version"]` reached Python as `c[framework_version]`, and a version mismatch (which only happens on a rollback) raised `NameError` instead of the real assertion. The code now travels as a positional argument (`bash -lc 'cd "$1" && "$2" "$3" shell -c "$4"' _ ...`), so no character of it is parsed by a second shell. `runuser`, `timeout`, masking, exit 79 and the marker are unchanged. All 13 checks were reviewed: two (contract catalog, Core Resource Directory) used quoted keys, the rest are unaffected.
   * **What this does not fix.** The installer that runs during a rollback is the one inside the old backup. A rollback to a version before 1.17.98 still runs the old `install.sh` with the old quoting, which cannot be changed from here. The real reason the version assertion fails on a rollback on tt01 is still unknown. It shows as a readable "framework version mismatch: expected X, got Y" once a rollback to 1.17.98 or later is run.
6. **Text.** `contracts.py` route rows for the three update routes (`refresh`, `github_rate_limit`, `github_rate_limit_error`, `commit`, 409, 429, the 1.17.98 cache rules). `docs/system-update-signed-releases.md` gained a short section. The 1.17.97 release note moved to `docs/releases/`.

## Module-facing changes

None. Checked in `modules/`: no module calls `system_update`, `updates/online`, `system/updates` or the update source routes (the only text hit, `cybercns` `reports.py`, is an unrelated `online_status` asset field). New query value, new body key and new answer keys are all optional or additive, `force=true` still works, and a schema 1 cache file is upgraded in place. The public contract text for three Core routes changed, so a fresh export is needed (`reviews/requests/core.md`, "Core 1.17.98").

## Tests

* New: `tests/github-rate-limit-1.17.98.py` (fresh cache = 0 calls, stale = exactly 1 conditional call, 304 and 200 paths, token never in the cache, telemetry, answer or logs, 403 and 429 exhaustion with the stale cache kept and 0 calls before the reset, 401 and plain 403 never cached, 8 threads and 10 rapid forced refreshes, a lock that cannot be taken, schema 1 upgrade and corrupt rebuild, `refresh` values and the `force` alias, VERSION and signature preview saved by commit and by trust fingerprint, stage pinned to a commit and `stale_candidate`, 0 GitHub calls from the job routes and `system_status`, the view and contract text, the token file rules with stubs for `pwd` and `stat`).
* New: `tests/system-update-source-checkout-1.17.98.py` (helper loaded with `ast` and stubs: the exact `safe.directory`, the hardening flags, Git error versus changes, the dirty list, owners, config refusals, ownership restored and `/opt/tec-tac` never touched, `run_job` hands the checkout back in the closing `finally`).
* New: `tests/installer-rollback-verify-1.17.98.py` (the real `run_verify_step` under bash with a stub Python: all 13 strings arrive byte for byte and compile, the contract check reports the real assertion on a version mismatch, helper `INSTALLER_VERIFY_STEPS` equals the install.sh labels, a rollback run goes through every step).
* Changed where behaviour intentionally changed: `tests/update-source-1.17.2.py`, `1.17.3.py`, `1.17.4.py` (a branch refresh no longer forces the release, `force=True` becomes `refresh="all"` where both are wanted, the VERSION at a commit has no expiry, a cache write failure no longer becomes `release_error`, the new answer keys), `tests/system-update-redirect-1.17.73.py` (the call sites are `github_get_json`, `_github_content_bytes` and `_download_to_stage`), `tests/system-update-refused-1.17.43.py` and `tests/system-update-rollback-verify-warning-1.17.96.py` (stub for `restore_source_owner`).

## Checks on the test server (Johan)

After the update (`reviews/requests/core.md`, "Core 1.17.98"):

1. `stat -c '%U %n' /opt/tec-tac-src/framework /opt/tec-tac-src/framework/.git` (and `ui`). **Expected:** the Tactical account or root. If not, the update stops before any Git call with the `chown` command in the message. **FAIL:** the update starts anyway.
2. Open System updates twice in a row, then press Refresh twice. **Expected:** `GET .../updates/online/` shows `refresh.network_request: false` on the page loads, one request on the first Refresh and `recently_refreshed` on the second. **FAIL:** two requests, or `github_rate_limit` is missing. Send the answer.
3. Update with a deleted tracked file in the checkout. **Expected:** the job error lists it ("D bootstrap-modules/README.md") and says "Restore or review these changes before updating." It must not say "dubious ownership" or hide it. **FAIL:** any other text. Send the job log.
4. (Round 5) After a successful update, `stat -c '%U:%G %a %n' /opt/tec-tac-src/framework /opt/tec-tac-src/framework/.git /opt/tec-tac-src/framework/install.sh`. **Expected:** the Tactical account and group on all three, and `git status --porcelain` empty. The installer ran from `/var/lib/tec-tac/system-updates/install-stage/...` (the update log says so), never from this folder. **FAIL:** root on any of them, or the log shows the installer path inside `/opt/tec-tac-src`. The full round 5 checklist is at the end.
5. Optional rollback test on a server where a rollback can be forced: the log must show a readable message from a failing check, never `NameError`.

## Not done here

* **Django is not installed on this PC.** The Django test runner, the views against a real DRF stack, a real GitHub call and a real `flock` between uWSGI workers did not run. The two-process single-flight test needs `fcntl` and is skipped on this PC; it runs on Linux. A real rollback needs a server. `ruff` has no Core config of its own; it found no new finding in `system_update.py`, `views.py` or the helper (the existing ones are unchanged).
* **`tests/update-source-1.17.2.py` fails its last check on this PC with or without this release** ("0037 must be the newest migration, found 0043"), an old assertion that was already out of date. Everything before it in that file passes.
* Left out on purpose: `git ls-remote` for the branch head (a second transport would add a trust path to review), a stage with no saved check and no metadata call (it resolves the tag as before), the UI half (`reviews/requests/ui.md`), and the held Lows of the 1.17.97 review (Scheduler, a different theme).
* Q-CORE-H1A (the token on codeload.github.com) and Q-CORE-H2B stay as recorded; this release does not change which hosts see the token.

Decisions taken (information, no answer needed): see `reviews/questions/core.md`, "GitHub rate limit, source checkout and rollback installer, Core 1.17.98". Item 1 there is a security trade-off flagged for Johan.

## History: review rounds 0 to 4 (never signed)

> **History only.** Rounds 0 to 4 below describe rebuilds that were never signed. Round 5 replaced their model: the seal of the checkout, the hand-back to the Tactical account, root's Git in a root-owned checkout and the `tec-tac/verified/...` update branch are all gone. The tests those rounds name (`system-update-seal-1.17.98-1.py`, `system-update-source-checkout-1.17.98.py`, `system-update-linux-1.17.98-2.py`, `system-update-linux-1.17.98-3.py`) were removed in round 5; see "Fixed after review (round 5)" for what replaces them. The current behaviour is described only in round 5.

## Fixed after review (precheck round 0, 2 November 2026)

The precheck blocked two High findings in `scripts/system-update-helper.py`. Both are fixed under the same version, because no pipeline build has happened yet.

1. **Root ran Git in a Tactical-writable checkout, guarded by a deny-list.** The Tactical account could run code as root with `[commit] gpgsign=true` plus `[gpg] program=<script>`, or with `diff.<x>.command`, `core.worktree`, `core.gitProxy` or `core.askPass`. The check was also racy. Now, when the checkout's `.git` belongs to the Tactical account, every Git call runs as that account (`user`, `group`, no extra groups). Git's ownership guard stays on, so `safe.directory` is no longer given to Git in that case. Root never reads or runs anything from a file the web account controls. Related changes:
   - `apply_source_update` hands the files root just wrote to the Tactical account (never `.git`) before `git add`.
   - `restore_git_source` hands the tree over before the rollback Git steps and normalizes it back to root ownership afterwards, so the rollback installer still runs from a root-owned tree.
   - A root-owned `.git` still uses root's Git with `safe.directory` for the two configured paths. The deny-list is wider (gpg, diff, merge, credential, alias, `worktree`, `gitProxy`, `askPass`, `program`, `command`, `gpgsign` and more). A root-owned `.git` that holds a Tactical-owned `config` or `info/attributes` is refused.
   - `commit.gpgsign=false` and `tag.gpgsign=false` are always passed.
2. **`restore_source_owner` walked by path.** It used `os.walk` and `os.lchown(path)`, which follow intermediate links. Now one helper, `_chown_tree_nofollow`, walks with `os.fwalk(follow_symlinks=False)` and changes each name through its directory descriptor (`dir_fd`, `follow_symlinks=False`). It never touches the top-level `.git`. Apply, rollback and the end-of-job hand-back all use it.

Regression test: `tests/system-update-source-checkout-1.17.98.py` now covers `commit.gpgsign`, `gpg.program`, `diff.*.command`, `core.worktree`, `core.gitProxy` and `core.askPass`, the identity drop, the root-owned `.git` path, and the descriptor-only owner change. It runs with stubs here. Nothing ran as root or against a real Git on this PC.

Module-facing change: none.

## Fixed after review (round 1, 2 November 2026, version 1.17.98-1)

The AI review blocked 1.17.98 with two Critical and one High finding, all in `scripts/system-update-helper.py`. The rule behind all three: root never runs anything from a tree the Tactical account can still write to.

1. **Forward update: root ran `install.sh` the web account could change after the signature check (Critical).** The helper gave the tree to the Tactical account for Git, took it back, verified the manifest, then ran `install.sh`. A Tactical process holding `install.sh` open kept write access through its descriptor, because a `chown` does not close an open file. Now `seal_execution_tree` runs between Git and the manifest check. It works through directory descriptors and never follows a link. Each directory becomes root-owned and not group/other writable before it is listed. Each file is replaced by a fresh root-owned copy (new inode), so an old descriptor points at a file nobody runs. Links and special files are refused. Then `_root_verify_tree` checks the signed manifest on the sealed tree and the existing comparison with the staged manifest decides. The installer runs only after that.
2. **Rollback: root ran `install.sh` from a Git checkout made by the web account (Critical).** `restore_git_source` now seals the tree after Git has restored it, then `overlay_backup_bytes` puts the bytes of the root-owned backup archive (written before the update, validated with `_validated_rollback_members`, extracted in a 0700 root stage) over it, and seals again. Git state decides only the branch and head. If a Tactical-owned checkout has no recorded backup, the rollback stops. Both rollback call sites (after a failed install, and after an installer refusal) pass the backup.
3. **`safe.directory` for a mixed-owner checkout (High).** `_git` adds `safe.directory` only when the directory, `.git`, its entries, and the first level of `info`, `objects` and `refs` are all root-owned (`_git_tree_root_owned`). A mixed checkout is refused before Git starts, with the `chown` command. A Tactical-owned `.git` still runs Git as the Tactical account, as in 1.17.98.
4. **Guard.** `run_install` refuses a tree that was handed to the Tactical account (apply or rollback) and not sealed since. This covers the UI installer too, since both go through the same function.

Regression tests: new `tests/system-update-seal-1.17.98-1.py` (in-memory file system: a write through an old descriptor after the seal does not reach the file root runs; links refused; run order seal, verify, install; rollback sequence and refusal without a backup; `run_install` guard). Extended `tests/system-update-source-checkout-1.17.98.py` (mixed owners refused with no Git process, a Tactical-owned entry in a root-owned `.git` refused, a fully root-owned checkout still gets the exact `safe.directory`).

Not run here: the seal itself on a real Linux file system (this PC has no `fcntl`, `pwd` or descriptor-relative calls; the logic runs against a model). Server check: as the Tactical user, `exec 3>/opt/tec-tac-src/framework/install.sh` during an update, then confirm the root installer log shows the original bytes. Django is not installed here.

Residual note for Johan (information): the installer still runs from `/opt/tec-tac-src/<component>`, because `install.sh` records its own folder as the source path in the config. A private copy would have changed that recorded path. Sealing in place gives the same guarantee.

Module-facing change: none.

## Fixed after review (round 2, 2 November 2026, version 1.17.98-2)

The AI review blocked 1.17.98-1 with three High findings, all in `scripts/system-update-helper.py`. The rule stays the same: root never reads, writes or runs anything through a path the Tactical account can still change. This round makes the update itself obey it, not only the installer step.

1. **Git as the Tactical account failed in the sealed tree ("dubious ownership"), so every update rolled back.** Once the worktree is root-owned and `.git` is the Tactical account's, Git's ownership guard exits 128. `_git` now passes `-c safe.directory=<configured path>` on the Tactical-identity call as well. It is only the Tactical account trusting its own configured checkout, so it widens no trust for root. Still never `*`, never another path. A root-owned `.git` keeps the root-owned-tree check.
2. **Root wrote the release into a Tactical-writable tree.** The old order (clear, copy, chown, Git) let a compromised web process swap an entry for a link while root copied. New order:
   - `begin_source_update` runs the checks (owner, Git config, clean tree) and creates the update branch. The worktree is untouched.
   - `backup_root` runs next.
   - `finish_source_update` calls `_clear_worktree_safely`: the top directory becomes root-owned and not group/other writable first, so the web account can no longer add, rename or swap an entry. Every other entry moves into a root-only quarantine folder by descriptor and is removed with `shutil.rmtree` (descriptor based, never follows a link). Root writes nothing into an old directory.
   - The release is then copied into fresh root-owned paths. Group/other write and setuid bits are stripped from the root-private staging tree first, and the copy runs under `umask 022`, so a new directory is never writable by the web account while root fills it. Files stay world-readable so Git (as the Tactical account) can read them.
   - Git `add`, `commit` and `status` run as the Tactical account and only read the worktree. The tree is no longer handed to the Tactical account before the installer. `seal_execution_tree` and the signed-manifest check run as in 1.17.98-1.
   - `apply_source_update` stays as the one-step form of begin plus finish for callers that take no backup in between.
3. **The rollback installer ran from an unverified backup.**
   - `backup_root` now runs after the ownership and clean-tree checks and reads every entry through the descriptor that listed it with `O_NOFOLLOW`. A file swapped for a link is refused. Links and special files are left out of the archive, so a link to a root-only file cannot leak into it.
   - New `verify_rollback_tree`: before any rollback `run_install` the restored tree is sealed and checked by the privileged verifier. It must be signed, verified, and carry the version that was installed. Otherwise there is no installer and the job ends `rollback-failed` with "rollback verification failed: ... its installer was not run". A tree with an unknown installed version is refused too.
   - A failure after the branch was made but before the worktree was replaced (for example a backup that fails) now only drops the update branch. No installer runs and the job ends `failed-pre-mutation` with reason `before-source-change`. `git_state` carries `mutated` for this.

Regression tests:
* New `tests/system-update-linux-1.17.98-2.py`: real Git, real chown, a second uid, in a Linux container as root. A Tactical-owned checkout goes through `begin_source_update`, `backup_root`, `finish_source_update`, `seal_execution_tree` and `verify_source_runtime_layout` with no `RuntimeError`; a rollback ends clean (`verify_source_runtime_layout` passes, owner handed back, branch dropped). A directory and a file swapped for links just before the clear write nothing outside the tree. While root copies, the web account is refused when it tries to add, rename or write in the top directory, the new directories and the new files. A link to a root-only file is not archived and never read. It skips itself anywhere that is not root on Linux with Git. Run here in `python:3.12-slim` (desktop-linux Docker context) with Git installed: PASS.
* Extended `tests/system-update-seal-1.17.98-1.py` (new rollback order, `verify_rollback_tree` refuses unsigned, unverified, other version, unknown version and a changed tree), `tests/system-update-refused-1.17.43.py` (a failing rollback verification means the rollback installer never runs; a never-changed worktree runs no installer), `tests/system-update-source-checkout-1.17.98.py` (`safe.directory` for the configured path on the Tactical call, never for another path), and the stubs in `tests/system-update-rollback-verify-warning-1.17.96.py`.

Siblings checked: the UI installer goes through the same `run_job`, `begin_source_update`, `finish_source_update`, `restore_git_source` and `verify_rollback_tree`, so it is covered. `module-v2-job-helper.py`, `module-hotfix-job-helper.py` and `server-backup-helper.py` have their own deploy code and do not use these functions.

Not run here: the Django tests and any test needing `cryptography` (not installed on this PC or in the container). The installer itself is not run. A rollback to a version before 1.17.98 still needs a signed manifest in that old tree. If an older install has none, the rollback is refused with the reason (see `reviews/questions/core.md`, "Rollback needs a signed tree").

Module-facing change: none.

## Fixed after review (round 3, 2 November 2026, version 1.17.98-3)

* **High: Git as the Tactical account relied on `-c safe.directory`.** Git before 2.38 ignores that exemption on the command line, and Debian 11 (Git 2.30.2) and Ubuntu 22.04 (Git 2.34.1) are both supported by Tactical 1.5.2. After the worktree was cleared and the release copied, `git add` failed with "dubious ownership" and the update rolled back. Now every Git call that names a configured checkout gets a private, root-written global config: a root-owned 0755 folder with a root-owned 0644 `.gitconfig` that holds only `[safe] directory = "<the configured path>"`. `HOME` points at that folder (the global file of every Git version) and `GIT_CONFIG_GLOBAL` points at the same file (Git 2.32 and later). The folder is outside the checkout, is removed after each call, and never holds `*` or another path. A path that is not configured gets no exemption at all. `-c safe.directory` is no longer passed. The root-owned-tree and mixed-owner refusals are unchanged.
* **Medium: rollback of a root-owned UI checkout failed on ignored build output.** `git reset --hard` and `git clean -fd` leave ignored files, so `node_modules` (with its `.bin` links) and `dist` stayed and the tree check refused the links with "unsupported path". A mutated rollback now empties the worktree through `_clear_worktree_safely` and extracts the root-held backup whoever owns the checkout (the Tactical-owned path already did). The Git clean steps now use `-fdx`, so a rollback without a backup still removes ignored output. The backup excludes `node_modules` and `dist`, so a rollback leaves neither; the next install rebuilds them. The same code serves the Core and UI checkouts, so there is no sibling.

Tests: `tests/system-update-linux-1.17.98-3.py` (new) runs the helper's own `_git` as the Tactical account against a root-owned worktree on the container's Git, proves the exemption names only the configured path, and rolls back a root-owned UI checkout that gained `node_modules/.bin/<link>` and `dist`. `tests/system-update-linux-1.17.98-2.py` now uses the same global-config mechanism in its own Git helper. `tests/system-update-source-checkout-1.17.98.py` checks the config text, its mode and that `-c safe.directory` is gone. Run here in Docker (`desktop-linux`): python:3.12-slim (Git 2.47) passes both Linux tests; ubuntu:22.04 (Git 2.34.1, Python 3.10) passes both; debian:11 (Git 2.30.2, Python 3.9) shows `-c safe.directory` failing with exit 128 and the new mechanism passing, the forward path passing, and stops at the rollback only because Python 3.9's `tarfile.extractall` has no `filter` argument (the helper needs Python 3.12 there, as before).

## Fixed after review (round 4, 2 November 2026, version 1.17.98-4)

Round 4 passed the AI review. Signing stopped at promotion: "the rebuild version 1.17.98-3 still appears in ['scripts/system-update-helper.py']". The three held non-blocking findings of that review are fixed in the same rebuild.

* **Blocking at promotion: rebuild numbers in the helper.** `scripts/system-update-helper.py` named "1.17.98-1", "-2" and "-3" in 21 comments and docstrings. They now say "1.17.98". Nothing reads them at run time, and no other file outside `VERSION`, `tec_tac_package.json`, the release notes, `tests/` and `docs/` carries a "1.17.98-" literal.
* **Medium: the `stable_release` contract row still promised the 24-hour fetch and the `force=1` bypass.** The row in `contracts.py` (`GET /api/tfd/system/updates/online/`) now says what 1.17.98 does: under a branch source it is read from the saved copy, `cache.stale` shows when it is older than 24 hours, only `refresh=release` or `refresh=all` refreshes it, and `force=1` under a branch source means `refresh=branch` and does not refresh it. The `force` row no longer says it bypasses the caches. We chose the rewrite over the old `force=1` behaviour: no module calls the route, and keeping the old bypass would bring back the extra GitHub requests this release removes. The UI half is still the request in `reviews/requests/ui.md`.
* **Low: a GitHub transport failure looked like a fresh successful check.** `github_get_json` used to return the saved body on a network error or timeout, so callers renewed `checked_at` and showed no error. It now raises `GithubUnreachableError` (a `GithubRequestError`) that carries the saved body. The release check shows the saved release with its old `checked_at`, `cache.stale` true and `release_error` set. The branch check shows the saved head with `branch_error` set and does not renew its check time, so the next check tries again. An unpinned stage refuses the fallback instead of staging a stale head. The branch picker keeps showing the saved list, as before. With nothing saved the error is the plain `GithubRequestError`, as before.
* **Low: the view refused an empty `refresh=` that the service treats as none.** `SystemUpdateOnlineStatusView` no longer checks `refresh` itself. `_normalize_refresh` is the one place: empty means none (or the `force` alias), an invalid value raises `SystemUpdateError` and the view answers 400 with the same text as before. The contract row says an empty value is none.

Tests: `tests/github-rate-limit-1.17.98.py` gained section 11b (the `stable_release`, `force` and `refresh` contract text; empty `refresh` through `_normalize_refresh` and `online_status`; a `URLError` against saved branch and release answers keeps both old check times, sets `branch_error`, `release_error` and `cache.stale`, refuses an unpinned branch and release stage, keeps the saved branch list, and gives the plain error when nothing is saved). Its view check now asserts the view does not validate `refresh` a second time.

Module-facing change: none. No module calls `updates/online` (checked in `modules/`). The new answer text is documentation only; `branch_error` and `release_error` already existed and are now set in one more case.

## Fixed after review (round 5, 2 November 2026, version 1.17.98-5)

The AI review blocked 1.17.98-4 with one High finding: after every update the helper handed the whole framework worktree, `install.sh` included, back to the Tactical account (`restore_source_owner`), and the server-backup restore later ran that `install.sh` as root with no signature check. Johan and Sol's spec of the same day ("System Update Checkout and Ownership Fix", tt01) asked for the opposite of the reviewer's first fix: the source checkouts must stay `tactical:tactical` and clean. Both are met with the spec's own "Use staging instead of mutating source" model (coordinator decision, 2 November 2026): **root never runs an installer or script from a Tactical-writable checkout, and the checkout is never changed to root.**

Closes: the CORE-FIX-NOTE of review `core-1.17.98-4-20261102-105615` (High, `scripts/system-update-helper.py:2127`), and the `reviews/requests/core.md` entries "Core: System Update corrupts source checkouts and ownership; the direct installers are correct" (spec `docs/Tec-Tac Core – System Update Checkout and Ownership Fix.md`), "Core: installer trust bundle grants framework.update and ui.update to the dev publisher" (spec `docs/core - Trust Bundle Fix.md`) and, from the superseded entry "install.sh leaves the Framework runtime Tactical-owned", its one remaining point: one shared ownership rule for the installer and the updater.

### What changed and why

1. **Staging copy, verified, for every root installer run (the blocking finding).**
   * Forward update, rollback and restore copy the tree into `/var/lib/tec-tac/system-updates/install-stage/<job>-<label>/` (the staging root is checked to be a real directory, `root:root 0700`; never inside a checkout). Only the files the signed manifest lists are copied, plus the manifest and its signature. Each file is opened through directory descriptors with no link followed, and its size and SHA-256 are compared with the manifest while it is copied: a changed `install.sh` (or any changed file) stops the job there with "`<path>` differs from the signed release manifest; nothing was installed". Ownership is explicit (`root:root`, directories 0755, files 0644 or 0755): nothing is carried over with `cp -a` or by archive extraction.
   * The privileged verifier (`privileged-trust.py verify-tree`, the same one `verify_rollback_tree` uses) then checks the staged copy. A forward update also requires the staged manifest to be the one checked at extraction and the staged `VERSION` to be the package version. A rollback and a restore require a signed manifest for the expected version.
   * `run_install` refuses any tree that is not inside the staging root and has not passed that check ("refusing to run an installer from a tree that was not staged and verified by the root helper"). The source checkout can never be the execution tree again.
   * The development override for unsigned updates is unchanged: it applies, through the same verifier, to a forward update only, and an unsigned package is staged only from the root-private extraction, never from a checkout. A rollback and a restore still require a signed tree.
   * Removed: `restore_source_owner`, `seal_execution_tree` and its seal helpers, `overlay_backup_bytes`, `begin/finish/apply_source_update`, `_clear_worktree_safely`, `_replace_checkout_contents`, `restore_git_source`, the root-written `safe.directory` home and the root-Git config deny-list. Root no longer writes into a checkout, so nothing needs sealing or handing back.
2. **Restore (`server-backup-helper.py`, the consumer the reviewer named).** `run_post_restore_tec_tac` no longer runs `<framework source>/install.sh` or `<ui source>/scripts/install.sh`. It copies the installed system update helper (root-owned, not group/world writable, checked) into a root-only temporary folder and runs `--install-restored framework`, then `--install-restored ui`. That command gives the restored checkout to the Tactical account, stages it, verifies it (signed, for the version its `VERSION` names) and runs its installer from the copy. The copy of the helper is used for both steps because the restored Framework installer installs its own helper. A refused framework step stops the restore before the UI step.
3. **The spec's flow, steps 1 to 10 (`run_job`).**
   1. The exact commit is the one pinned when the job was claimed (`source.commit`, 40 hex, already validated by `sanitise_source`).
   2. The candidate package is verified as root, as before.
   3. Source ownership: the whole checkout, `.git` included, is made `tactical:tactical` (`normalise_source_owner`). A mixed checkout left by an older update (root worktree, Tactical `.git`, Git's "dubious ownership") is repaired here. A path owned by a third account is refused with the `chown` command, as before. Each owner is changed through a descriptor of the inode that was checked, links are never followed, and a root-owned file with a second hard link is refused, so a planted link can never hand a root file to the web account.
   4. Clean checkout: tracked changes are written to the update log (and `job.source_restored_changes`) and restored with `git reset --hard HEAD` as the Tactical account. `git clean` is not used broadly: only known generated untracked files are removed (Python bytecode, and an untracked UI `package-lock.json` as before). Any other untracked file stops the update with the list ("System Update will not delete"), because it may be an administrator's. Ignored files (`node_modules`, `dist`) are left alone.
   5. The checkout moves to exactly that commit: a fetch as the Tactical account only brings objects in (`origin <ref>`, then `origin <sha>` if needed), then `git checkout -B <ref> <sha>` for a branch source or a detached `HEAD` for a release. `HEAD` must equal the SHA and the tree must be clean. No second branch lookup. An offline package has no commit and leaves the checkout where it was (logged).
   6. The component's own installer runs from the verified staging copy (item 1). Nothing patches the checkout.
   7. Runtime ownership is applied and verified (item 4).
   8. Provenance is recorded: `job.installed_provenance` and `/var/lib/tec-tac/system-updates/provenance/<component>.json` (`root:<tactical group> 0640`) with repository, ref and the exact 40-character commit.
   9. The checkout is asserted `tactical:tactical` (directory and `.git`), at the expected `HEAD`, with `git status --porcelain` empty.
   10. The job completes.
   * Every Git call runs as the Tactical account (never as root), with hooks, the file-system monitor and attribute files switched off and its own `HOME`, so a fetch uses its own credential settings. Git refuses to run outside the two configured checkouts.
   * A failure before the installer ran puts the checkout back to its old `HEAD` and branch and runs no installer (`failed-pre-mutation`, reason `before-install`; was `before-source-change`, which no client reads). A refusal (78) does the same, as before.
   * A failure after the installer ran: the old installer runs from a staged copy of the root-held backup that verifies against the signed release that was installed, the runtime rule is applied, the checkout goes back to its old `HEAD` and branch as the Tactical account and is checked, and the previous provenance file is put back. If the runtime rollback fails, the checkout is still put back.
4. **One ownership rule (`RUNTIME_OWNERSHIP_RULE` in the helper).** `framework`, `scripts` and `templates` are `root:root 0755` (every directory 0755, every file 0644 or 0755 when it was executable, no group/other write, no setuid); `VERSION` and `tec_tac_package.json` are `root:root 0644`. `extensions` and `reportsets` are not in the rule and are never touched. `install.sh` applies and checks it through `tec-tac-system-update --runtime-ownership apply|verify <root> <framework> <scripts>` (the same code), and the updater, a rollback and a restore apply and check it after their installer. Directories are taken first through their own descriptor, files are changed through a descriptor, links are never followed.
5. **`install.sh`.**
   * `framework`, `scripts` and `templates` are copied with `cp -R --preserve=mode,timestamps` (no ownership carried over), `VERSION` and `tec_tac_package.json` with `install -o root -g root -m 0644`, then the rule is applied; at the end it is verified ("does not match the ownership rule" fails the install).
   * `TEC_TAC_FRAMEWORK_SOURCE` is the checkout the updater names (`TEC_TAC_STAGED_SOURCE_CHECKOUT`, read before the config like `TEC_TAC_API_URL`), or its own folder on a direct run. An older installer run by a rollback or a restore records the staging folder; the helper sets that one line back (`repin_framework_source`).
   * Bootstrap modules are read by the Tactical account from a root-owned, read-only copy in `/tmp` (the source may be a root-only staging copy); the source folder is no longer `chmod`-ed.
6. **The `vite.config.js` and `scripts/sync-modules.sh` changes on tt01.** Neither Core nor the UI installer edits those two files by name. The Core step that wrote tracked UI files was the update itself: `finish_source_update` replaced the whole UI worktree with the package bytes (and a rollback with the backup bytes), with new modes and owners, then the UI installer built inside that same checkout. Both are gone: the checkout is only moved by Git as the Tactical account, and the UI installer (`npm ci`, `npm run build`, `sync-modules.sh`) now runs inside the staging copy, so even a build step that rewrote tracked files would change only the copy. The UI repository needs no change, so no `reviews/requests/ui.md` entry was filed.
7. **UI module sync script, root-owned copy.** Module jobs run `UI_SYNC_SCRIPT` as root and refuse a script that is not root-owned. With a Tactical-owned UI checkout that refusal would stop every module install with a UI part. The helper now publishes `scripts/sync-modules.sh` and the `scripts/tec-tac-config.sh` it sources to `/usr/local/lib/tec-tac-ui-sync/scripts/` (`root:root`, replaced as a whole) and points `UI_SYNC_SCRIPT` at it. The bytes are read from the staged UI tree right after the verifier checked it and before its installer runs; they are published after a successful UI update, UI rollback or UI restore, and by `install.sh` (`--publish-ui-sync`, which stages and verifies the UI checkout, signed required). Without a signed UI checkout nothing changes and `UI_SYNC_SCRIPT` keeps its old value. The new folder is in the server-backup restore rollback snapshot list.
8. **Trust bundle (spec "Trust Bundle Fix").** `install.sh` grants `framework.update` and `ui.update` to the Tech Flow Dynamics dev publisher `tech_flow_dynamics-dev`, next to its `module.install` and `server_maintenance.register`, so a fresh install verifies signed Framework and UI updates without `publisher_permission_denied` and without a manual edit. The grant is made only while that publisher is trusted and only when its active key `tech-key-dev-1025` is the real Tech Flow Dynamics public key (`ed25519:SddWHe5LBIIPA4rbOsFVagnNyO2xQzbMfNgWvRy1+5k=`, compared as the 32 key bytes). No key is written, created or replaced; a server without that publisher, or with another key under that id, is left as it is; no other publisher changes. `framework.update` is still required for Framework updates and `ui.update` for UI updates, and publisher trust stays fail-closed. **Sign-off:** Johan asked for this directly in chat on 2 November 2026 ("here's another issue within core", with the spec). The `"environment": "production"` field of that publisher is reported, not changed: see `reviews/questions/core.md`.

### Module-facing changes

None. Checked in `modules/`: no module reads `UI_SYNC_SCRIPT`, the source checkout paths, `tec-tac-system-update` or the update permissions. No contract, route or capability changed. Core's own module helpers keep reading `UI_SYNC_SCRIPT` from the config; only its value moves to the root-owned copy.

### Safety review (for a human)

* **Ownership given to the web account.** Root now changes root-owned or mixed paths of the two configured source checkouts to the Tactical account. This is safe only because root never runs anything from a checkout any more (item 1). Guards: descriptor-based changes of the checked inode, no link followed, third-party owners refused, root-owned files with more than one hard link refused, Git never run as root.
* **Trust widened by a signed decision.** The dev publisher may now sign Framework and UI updates on fresh installs (item 8, Johan, 2 November 2026). Bound to the real public key; fail-closed otherwise.
* **Narrower than before.** A restore now refuses a source tree that has no signed manifest for its version (before, it ran any restored `install.sh`). A very old backup from before signed releases (Core 1.15.37) is refused by the restore ("restore verification failed ... has no signed manifest") and the restore rolls back. **Manual path for such a backup**, a root decision by an administrator after checking the files: extract the Core source from the backup and run its installer by hand, the same direct install as before:
  ```bash
  mkdir -m 700 /root/tt-old-backup && cd /root/tt-old-backup
  tar -xzf /path/to/<backup>.tar.gz tec-tac/tec-tac-backup.tar.gz
  tar -xzf tec-tac/tec-tac-backup.tar.gz opt/tec-tac-src
  FW="$(sed -n 's/^TEC_TAC_FRAMEWORK_SOURCE=//p' /opt/tec-tac/etc/tec-tac.conf)"
  # check the extracted files, then put them in place as the Tactical account's checkout and install from there:
  sudo rsync -a --delete --exclude .git "opt/tec-tac-src/$(basename "$FW")/" "$FW/" && sudo chown -R tactical:tactical "$FW"
  cd "$FW" && sudo bash install.sh
  ```
  The UI is the same with `opt/tec-tac-src/ui` and `sudo bash scripts/install.sh`. Simpler and preferred: restore the database and modules, then install the current signed Core and UI release.
* **New root command-line entry points:** `--runtime-ownership`, `--install-restored`, `--publish-ui-sync`. The Tactical account's sudo rules still reach only `--dispatch`, `--set-trust-policy` and `--set-account-security-policy` (the first argument is fixed, so `--dispatch x --install-restored ...` reaches the usage error).
* **Network as the Tactical account.** A fetch runs as the Tactical account with its own `HOME`. If that account cannot fetch from the repository, the update stops before anything is installed with the command to check.
* Nothing legal or financial in this release.

### Tests

* New `tests/system-update-linux-staging-1.17.98.py` (Linux, root, real Git, a real `tactical` account, signed trees with a key made for the test): spec tests 1 to 13, the fix note's three refusals (changed `install.sh` in the checkout during an update, in the rollback backup, and in a restored checkout: refused before any installer), ownership unchanged across a successful and a failed run, the UI sync copy, the hard-link guard. **Run here in Docker (`desktop-linux`, python:3.12-slim with Git 2.47): PASS.**
* New `tests/trust-bundle-dev-publisher-1.17.98.py`: runs the installer's `PY_DEV_PUBLISHER` step on temporary trust stores. The shipped bundle is refused before (`publisher_permission_denied`) and verifies signed Framework and UI trees after; other key, revoked key, untrusted publisher, missing publisher and other publishers are untouched; the key file is never written; each update permission is still required. PASS in Docker; the static part passes on Windows.
* New `tests/server-backup-restore-staged-1.17.98.py`: `run_post_restore_tec_tac` runs only `--install-restored framework` then `ui` through a checked helper copy, never an `install.sh`; a refused framework step stops the restore; a group-writable helper is refused. PASS in Docker.
* Changed: `tests/system-update-refused-1.17.43.py`, `tests/system-update-rollback-verify-warning-1.17.96.py` (stubs for the new flow; a source restore now follows the rollback installer; reason `before-install`), `tests/system-update-foundation.sh` (the Git section now covers log-and-restore, the untracked-file refusal, the exact commit while the remote moves on, release detach, rollback, an unknown commit and unsafe refs).
* Removed, because they tested the seal and hand-back that round 5 removed: `tests/system-update-seal-1.17.98-1.py`, `tests/system-update-source-checkout-1.17.98.py`, `tests/system-update-linux-1.17.98-2.py`, `tests/system-update-linux-1.17.98-3.py`. The history rounds above still name them; they no longer exist. What they covered that still applies is now in `tests/system-update-linux-staging-1.17.98.py`: `verify_rollback_tree` refuses an unsigned tree, an unknown version and another version; staging refuses a linked folder and a linked file inside manifest paths; a path owned by a third account is refused; Git never runs as root; the rollback backup is read without following links.
* Also run in Docker, all PASS: every `tests/system-update-*.py`, `tests/server-backup-*.py`, `tests/backup-recovery-system-update-1.15.140.py`, `tests/installer-rollback-verify-1.17.98.py`, `tests/github-rate-limit-1.17.98.py`, `tests/d2-d3-restore-orchestration-1.15.173.py`, `tests/runtime-script-imports-1.17.32.py`, `tests/trust-policy-upgrade-migration.py`, `tests/system-update-foundation.sh`, `tests/trusted-publisher-foundation.sh`, `tests/release-integrity.sh`. Three need Django or the `tec_tac` path and did not run (same before this change): `system-update-logs-runtime-1.17.67.py`, `server-backup-recovery-trust-capability-boundary.py`, `update-trust-policy.py`.

### Not run here

* Django is not installed on this PC: the Django test runner and `manage.py` checks did not run. The post-install Django checks were replaced by a `VERSION` check in the Linux test.
* The real `install.sh` and the real UI build (`npm ci`, Vite) were not run; the Linux test uses small installers that behave like them (including one that leaves a Tactical-owned runtime and one that rewrites `vite.config.js` in its own folder).
* The privileged verifier subprocess was replaced in the Linux test by the same `verify_release_tree` it calls; the trust root and policy floor of a real server were not used.
* Only Git 2.47 (Python 3.12) was run this round. Debian 11 (Git 2.30) and Ubuntu 22.04 (Git 2.34) were not: the helper no longer depends on `safe.directory`, because Git always runs as the owner of the whole checkout.
* `ruff`: no Core config of its own. `ruff check --select F,E9` is clean on the changed files; the full rule set shows one more `BLE001` in `run_job` (the same `except Exception` pattern the function already uses).

### Checks on the test server tt01 (Johan)

The first update **to** this release runs under the helper that is installed now, which still has the old behaviour. So install this release once from the command line, then test System Update with it. Run every block as one copy-paste. `FW` and `UI` are read from the config, whatever the folder names on tt01 are.

**0. Prepare (after the pipeline has signed 1.17.98-5 and pushed it to `origin/dev`).**
```bash
FW="$(sed -n 's/^TEC_TAC_FRAMEWORK_SOURCE=//p' /opt/tec-tac/etc/tec-tac.conf)"; UI="$(sed -n 's/^TEC_TAC_UI_SOURCE=//p' /opt/tec-tac/etc/tec-tac.conf)"; echo "FW=$FW UI=$UI"
sudo chown -R tactical:tactical "$FW" "$UI"
sudo -u tactical git -C "$FW" fetch origin && sudo -u tactical git -C "$UI" fetch origin && echo FETCH-OK
sudo -u tactical git -C "$FW" status --porcelain; sudo -u tactical git -C "$UI" status --porcelain
```
**Expected:** both paths print, `FETCH-OK`, and both status commands print nothing. **FAIL:** a fetch error (System Update needs it too; send the error), or changed files listed (restore them with `sudo -u tactical git -C "$FW" reset --hard`).

**1. Install 1.17.98-5 from the command line.**
```bash
sudo -u tactical git -C "$FW" checkout -B dev origin/dev && cat "$FW/VERSION"
cd "$FW" && sudo bash install.sh 2>&1 | tee /tmp/tt-install-1.17.98-5.log | grep -E 'runtime ownership|Dev publisher|UI module sync|Installation complete|ERROR'
```
**Expected:** `1.17.98-5`, then lines with `runtime ownership rule applied`, `runtime ownership verified`, `Dev publisher update permissions: granted framework.update, ui.update` (or `already holds`), a UI sync line, and `Installation complete.` **FAIL:** any `ERROR`; send `/tmp/tt-install-1.17.98-5.log`.

**2. Trust bundle and ownership after the direct install.**
```bash
sudo python3 -c 'import json;print(json.load(open("/etc/tec-tac/trusted-publishers/tech_flow_dynamics-dev/publisher.json"))["permissions"])'
sudo stat -c '%U:%G %a %n' /opt/tec-tac/framework /opt/tec-tac/scripts /opt/tec-tac/templates /opt/tec-tac/VERSION /opt/tec-tac/tec_tac_package.json "$FW" "$FW/.git" "$UI" "$UI/.git"
grep -E '^(TEC_TAC_FRAMEWORK_SOURCE|UI_SYNC_SCRIPT)=' /opt/tec-tac/etc/tec-tac.conf
```
**Expected:** the four permissions; `root:root 755` for the three runtime folders, `root:root 644` for the two files; `tactical:tactical` for the four source paths; `TEC_TAC_FRAMEWORK_SOURCE` is `$FW` and `UI_SYNC_SCRIPT=/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh`. **FAIL:** anything else; send the output.

**3. Framework System Update (reinstall the same dev commit) in Tec-Tac.** System updates, Framework, branch `dev`, Refresh, Install. Then:
```bash
J="$(ls -t /var/lib/tec-tac/system-updates/history/*.json | head -1)"; sudo python3 -c 'import json,sys;j=json.load(open(sys.argv[1]));print(j["status"],j["stage"],j.get("installed_provenance",{}).get("commit"),j.get("error"))' "$J"
sudo grep -E 'staging copy|installed_provenance|provenance|ownership rule|source checkout is at' "/var/lib/tec-tac/system-updates/logs/$(basename "$J" .json).log"
sudo -u tactical git -C "$FW" rev-parse HEAD; sudo -u tactical git -C "$FW" status --porcelain
sudo stat -c '%U:%G %a %n' "$FW" "$FW/.git" "$FW/install.sh" /opt/tec-tac/framework /opt/tec-tac/VERSION
```
**Expected:** `succeeded complete <40-character commit> None`; the log says the installer ran "from the verified staging copy", the source checkout "is at exactly <commit>", and the ownership rule was applied and verified; `rev-parse` prints that same commit; `status` prints nothing; the source paths are `tactical:tactical`, the runtime `root:root`. **FAIL:** any other status, root on a source path, or output from `status`; send the job file and log.

**4. UI System Update (branch `dev`).** Then:
```bash
sudo -u tactical git -C "$UI" status --porcelain; sudo -u tactical git -C "$UI" diff --stat HEAD -- vite.config.js scripts/sync-modules.sh
sudo stat -c '%U:%G %n' "$UI" "$UI/.git" "$UI/vite.config.js"; cat /var/lib/tec-tac/ui/tec-tac/VERSION; ls -l /usr/local/lib/tec-tac-ui-sync/scripts/
```
**Expected:** nothing from both Git commands, `tactical:tactical` on the three UI paths, the UI version you installed, and `sync-modules.sh` `-rwxr-xr-x root root`. **FAIL:** `M vite.config.js` or `M scripts/sync-modules.sh`; send the job log.

**5. Repeat step 3 once more.** **Expected:** the same output, owners unchanged. **FAIL:** any owner changed.

**6. A tracked change is restored, an unknown file stops the update.**
```bash
sudo -u tactical sh -c "echo '# local edit' >> '$FW/README.md'"
```
Run the Framework update again. **Expected:** it succeeds; its log lists `M README.md` under "tracked change(s); restoring them to HEAD"; `git status --porcelain` is empty afterwards. Then:
```bash
sudo -u tactical sh -c "echo note > '$FW/my-notes.txt'"
```
Run the update again. **Expected:** it stops with "untracked files that System Update will not delete" and `my-notes.txt`; nothing installed; the file is still there. Clean up: `sudo -u tactical rm "$FW/my-notes.txt"`. **FAIL:** the file was deleted, or the update ran.

**7. A changed install.sh is refused before anything runs (the review's fix note).**
```bash
sudo -u tactical sh -c "echo 'touch /tmp/tt-should-not-exist' >> '$FW/install.sh'"
sudo /usr/local/sbin/tec-tac-system-update --install-restored framework; echo "exit=$?"; ls /tmp/tt-should-not-exist
sudo -u tactical git -C "$FW" checkout -- install.sh && sudo -u tactical git -C "$FW" status --porcelain
```
**Expected:** "install.sh differs from the signed release manifest; nothing was installed", a non-zero exit, `ls` says the file does not exist, and the last command prints nothing. **FAIL:** `/tmp/tt-should-not-exist` exists (stop and tell me), or the installer started.

**8. A module with a UI part still installs** (the UI sync now uses the root-owned copy). Install or reinstall any signed module that has a UI. **Expected:** success, and the module log shows the UI sync. **FAIL:** "refusing non-root-owned or writable lifecycle script"; send the module job log and `grep UI_SYNC_SCRIPT /opt/tec-tac/etc/tec-tac.conf`.

### Fixed after the pre-release check (2 November 2026, still 1.17.98-5)

The pre-release check of commit f72e984 found one High, one Medium and three Low items. All are fixed in a new commit under the same version (nothing was packed).

1. **High: root read `VERSION` from the Tactical-owned checkout and followed a link.** `run_job` read `<checkout>/VERSION` with `read_text`, and the text went into `job.installed_version`, the 0640 job and history files, the audit row and the backup name; a link to a root-only file would have leaked it. Now every root read of a file inside a source checkout opens it with `O_NOFOLLOW` and reads at most 256 bytes, and only text matching `^[0-9A-Za-z.+-]{1,64}$` is used; anything else is `unknown` (system update helper `_read_version_file`, backup helper `detect_version`). Searched for every other root read of a file inside either checkout:
   * `scripts/system-update-helper.py`: the backup (`backup_root`) and staging (`stage_release_tree`) already read through descriptors without following links; the UI sync tools are read from the verified staging copy; the remaining uses only test that a path exists. No other read.
   * `scripts/server-backup-helper.py`: `detect_version` (three calls on the checkouts, also used for the runtime and the deployed UI) is fixed as above. **The server backup archived both checkouts with `dereference = True`**, which read any file a link in the checkout pointed at. The checkouts are now archived through descriptors (`make_payload_tar(..., nofollow_roots=...)`, `_add_tree_nofollow`): no link is followed or stored, each file must be the inode that was listed, and a root-owned file with a second hard link is left out. Other backup roots are unchanged.
   * `install.sh`: run directly by an administrator from a checkout, or by the updater from the staging copy; it no longer reads anything from the UI checkout (item 2). The bootstrap copy uses `cp -R`, which does not follow links inside the folder.
2. **Medium: `UI_SYNC_SCRIPT` could name a file in the UI checkout.** `install.sh` now writes only `/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh`. Until a verified copy is published there, module jobs leave UI sync off with a clear log line ("UI module sync is off: no verified UI sync script was published at ..."). `module-job-helper.py`, `module-v2-job-helper.py` and `module-hotfix-job-helper.py` share one guard, `trusted_ui_sync_script`: the script and the `tec-tac-config.sh` it sources are opened with `O_NOFOLLOW` and must be regular, root-owned and not group/world writable, and every parent folder must be root-owned and not group/world writable, so no other account can change or swap them between the check and the run. A script that fails this is refused (an old config value inside the Tactical-owned checkout fails on its folder). The v1 helper checks again immediately before it runs the script; v2 and the hotfix helper check right before the run. Running from the open descriptor was not used: the script finds `tec-tac-config.sh` through its own path.
3. **Low: lost coverage** is back in `tests/system-update-linux-staging-1.17.98.py` (see Tests above), plus a test that a `VERSION` link to a root 0600 secret never reaches the job, history, log or provenance files.
4. **Low: these notes.** Rounds 0 to 4 are marked as history, the removed tests are named consistently, and the manual path for backups from before 1.15.37 is above.
5. **Low:** `tests/github-rate-limit-1.17.98.py` no longer names rebuild versions.

Tests added or extended for this: `tests/module-ui-sync-guard-1.17.98.py` (new: one guard in all three helpers; a link, a writable or foreign-owned script, a writable config reader, a foreign or writable folder and a script inside the UI checkout are refused; a missing script means off; install.sh writes only the published path), `tests/server-backup-restore-staged-1.17.98.py` (a `VERSION` link is not read, version text is validated, the checkout backup holds no link and no file reached through a link), `tests/system-update-linux-staging-1.17.98.py` (above). Module-facing change: none; the three changed helpers are Core's own.

Checklist step 8 above still applies: a module with a UI part must install, and its log shows the UI sync (not "UI module sync is off").

## Fixed after review (round 6, 2 November 2026, version 1.17.98)

The pipeline blocked 1.17.98-5 with one High finding and held one Medium. Both are fixed.

1. **High: the downgrade gate trusted the Tactical-owned checkout.** `run_job` took the installed version from `<checkout>/VERSION`. Since round 5 the checkout belongs to the Tactical account, so it could commit `VERSION=0.0.0` and get any older signed release past the gate with `allow_downgrade` false and `TEC_TAC_ALLOW_SYSTEM_DOWNGRADES` off. The same value chose the version a rollback must verify, and `--publish-ui-sync` took its expected version from the UI checkout too.
   * New `installed_version(component, cfg)` reads root-held state only. For the Framework that is the runtime `VERSION` (`/opt/tec-tac/VERSION`, root:root 0644). For the UI it is the deployed UI `VERSION`, or else the root-owned provenance file. The read follows no link, and neither the file nor any folder above it may be writable by the Tactical account. Only a plain version (`^[0-9A-Za-z.+-]{1,64}$`) is accepted.
   * The downgrade gate, the backup name, the rollback's expected version and `job.installed_version` all use that value. The checkout's `VERSION` is kept as `job.source_checkout_version` for display.
   * After the checkout is restored to `HEAD`, its `VERSION` must equal the installed version. The backup of that `HEAD` is the rollback copy, so a different version stops the update before anything changes, with the command to fix it.
   * If the installed version cannot be read from root-held state, the update is refused. The one exception is an explicit controlled downgrade: `allow_downgrade` plus the root-owned `TEC_TAC_ALLOW_SYSTEM_DOWNGRADES`.
   * `--publish-ui-sync` requires the staged UI to be signed for the root-recorded installed UI version. A checkout at another version is refused.
   * A restore passes the version from the backup's own manifest (`--install-restored <component> <version>`). With no recorded version, the Framework uses the restored root-owned runtime `VERSION` and the UI is refused. The restored checkout is given to the Tactical account only after its staged copy was verified and installed.
   * `server-backup-helper.py` now records `framework_version` and `ui_version` from the runtime and the deployed UI, never the checkouts. The same applies to the backup metadata `core_version` and the restore's "current Core" notice.
2. **Medium (held): root's owner change followed a resolved path.** The configured checkout paths are no longer resolved. New `open_source_checkout` opens every folder from `/` down with `O_NOFOLLOW|O_DIRECTORY` from the folder above. Each must be root-owned and not group/world writable. The checkout itself is opened from that root-owned parent descriptor. The owner change walks from that descriptor (`os.fwalk(".", dir_fd=...)`). The same check runs before every Git call, before the backup of the checkout, and before staging from a checkout. A linked folder, a linked checkout, a Tactical-owned or writable folder above the checkout: all are refused, and nothing outside the checkout changes owner.

**Sweep: every decision root made from checkout contents before manifest verification.**

* **Changed to root-held state:**
  * The installed version: downgrade gate, rollback version, backup name, audit row.
  * The expected version of `--publish-ui-sync`.
  * The expected version of a restore.
  * The backup manifest's `framework_version` and `ui_version`, the metadata `core_version`, and the restore's current-version notice.
* **Kept, because they only drive Git as the Tactical account, change only the checkout, or can only refuse:**
  * `HEAD` and branch: used to put the checkout back, with Git as the Tactical account.
  * Tracked and untracked lists: logged and restored by Git as the Tactical account; unknown files refuse the update.
  * The origin URL: a fetch as the Tactical account; the bytes are verified afterwards.
  * The checkout `VERSION` after the move: it can only refuse.
* **Root reads files from a checkout in three places, each checked:**
  * The signed manifest and file list used for staging: every file is hash-checked while it is copied, the privileged verifier then checks the copy, and the staged manifest must be the one verified from the package (or the expected signed version for rollback, restore and UI sync).
  * The backup of the checkout: read through descriptors, with no link followed.
  * The display `VERSION`: no-follow, validated, never a decision.

Tests: `tests/system-update-linux-staging-1.17.98.py` now covers:
* The fix note's case. Installed 2.0.3; the Tactical account commits `VERSION=0.0.0`; a signed 2.0.2 with `allow_downgrade` false ends `failed-pre-mutation` with "downgrade requires explicit allow_downgrade request", no installer and an unchanged runtime.
* A newer package with that checkout is refused for the version mismatch.
* `--publish-ui-sync` from a checkout at an older UI is refused.
* A world-writable folder above the checkout, a Tactical-owned folder above it, a linked folder above it and a checkout that is itself a link are refused, also for Git, and nothing outside changes owner.

The test now runs below `/opt`, because `/tmp` is world-writable and is refused as a folder above a checkout. `tests/server-backup-restore-staged-1.17.98.py` checks that the backup's recorded versions are passed, and that an invalid recorded version is dropped. Five existing tests followed the intended change: `server-backup-d2-version-transition.py`, `server-backup-d2-d3.py`, `server-backup-decision-closure-1.15.166.py`, `d2-d3-restore-orchestration-1.15.173.py` (versions come from the runtime) and `system-update-audit-1.17.67.py` (the pin on the version line). If the Tactical account cannot be looked up, the installed version is unknown and the job refuses with the reason (it no longer stops before the job starts).

**For the test server:** a server whose checkout sits below a group- or world-writable folder, or below a symbolic link, now refuses updates with the folder named. Check with `namei -l "$FW"`. Every line above the checkout must be `root root` without group/other `w`. Also, `/opt/tec-tac/VERSION` must be readable as root-held state: after step 1 of the checklist it is `root:root 644`.
