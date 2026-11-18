# Tec-Tac Framework 1.18.8

Date: 18 November 2026. This is Patch A of three for the Core sandbox. The sandbox stays off. Nothing in Tec-Tac can start a sandbox run after this release, and the network is unchanged.

## BEFORE you update (canary first)

Run this on dev02 while Core 1.18.7 is still installed. It proves the new checks catch the problem before the fix goes in. A check that has never failed proves nothing.

1. Confirm what is installed. **PASS:** the line ends in `-> /usr/local/lib/tec-tac/sandbox/sandbox-helper.py`.

   ```
   ls -l /usr/local/sbin/tec-tac-sandbox
   ```

2. Copy four files from `D:\Visual Studios\Vibe Coding\Tec-Tac Project\workspace\core` to dev02. The 1.18.8 source is not on dev02 yet, so use `scp`. Keep the `tests/` and `scripts/` folders. Put your own dev02 login where it says `<your dev02 login>`.

   ```
   ssh <your dev02 login> "mkdir -p /root/canary-1.18.8/tests /root/canary-1.18.8/scripts"
   scp "D:\Visual Studios\Vibe Coding\Tec-Tac Project\workspace\core\tests\sandbox-canary-1.18.8.sh" "D:\Visual Studios\Vibe Coding\Tec-Tac Project\workspace\core\tests\sandbox-canary-1.18.8-before.py" <your dev02 login>:/root/canary-1.18.8/tests/
   scp "D:\Visual Studios\Vibe Coding\Tec-Tac Project\workspace\core\scripts\sandbox-canary-runner.py" "D:\Visual Studios\Vibe Coding\Tec-Tac Project\workspace\core\scripts\sandbox-helper.py" <your dev02 login>:/root/canary-1.18.8/scripts/
   ```

3. Run the before check. It installs nothing and never touches the kill switch.

   ```
   cd /root/canary-1.18.8 && sudo bash tests/sandbox-canary-1.18.8.sh before 2>&1 | tee ~/sandbox-before-1.18.8-$(date +%Y%m%d-%H%M).log
   ```

   **PASS (expected on 1.18.7):** the `view /` row, the `view /usr/local` row and the stand-in `read /tectac-canary-<hex>/...` row all end in `ATTACK SUCCEEDED`. The last line says `BEFORE RUN: N ATTACK SUCCEEDED` with N at least 3. The script ends with `PASS before run`.

   **FAIL:** zero `ATTACK SUCCEEDED` rows (the new rows prove nothing), any `NOT RUN` row, or the script stops at its own guard. Send the whole log and stop. Do not update.

   What each row means. `view /` lists the server's own folders, such as `rmmbackups`, `backup`, `backups`, `snap`, `boot`, that a 1.18.7 run can still see. `view /usr/local` shows the host's `/usr/local/sbin` and friends. The stand-in row is a fresh folder at `/` made by root. A 1.18.7 run can read the file inside it, so it proves the old view leaks.

   One row will not show a leak on 1.18.7: the marker in `/rmmbackups`. That folder is `0700` since Core 1.18.7, so the host's own permissions protect it. The canary still plants a marker there (never following a link). The stand-in folder is the proof, not that row.

## AFTER you update

4. Update dev02 to Core 1.18.8 from the dev branch. **PASS:** the install finishes and its log shows `Sandbox selftest passed` (the sandbox stays off). **FAIL:** a `WARNING: Sandbox is off:` line. The reason after it names the problem, for example `the sandbox root folder does not match this server; run the Core install again`. Send the install log tail.
5. Check the version and the helper.

   ```
   cd /opt/tec-tac-src/framework
   cat VERSION
   sudo sha256sum /usr/local/lib/tec-tac/sandbox/sandbox-helper.py scripts/sandbox-helper.py
   ls -ld /usr/local/lib/tec-tac/sandbox/root
   ```

   **PASS:** `1.18.8`; the two hashes are the same; `drwxr-xr-x ... root root ... /usr/local/lib/tec-tac/sandbox/root`. **FAIL:** any difference. Send the output.
6. Run the full canary.

   ```
   cd /opt/tec-tac-src/framework && sudo bash tests/sandbox-canary-1.18.8.sh 2>&1 | tee ~/sandbox-canary-1.18.8-$(date +%Y%m%d-%H%M).log
   ```

   **PASS:** the log ends with `ALL CANARY STEPS PASSED`. That means: every `view` row and the `/ lists only the allowed set` row are `OK`; the stand-in marker row is `OK`; the memory row is `OK` and shows `oom_kills` of 1 or more, or a refused allocation; every earlier row is `OK`; 0 rows `ATTACK SUCCEEDED`; 0 rows `NOT RUN`; only `public tcp 443` may be `SKIPPED`; the audit step (5o) passes. **FAIL:** any `FAIL` line. A row that says `ATTACK SUCCEEDED` is a real hole: leave the sandbox off and send the row.
7. Check the switch is still off.

   ```
   sudo /usr/local/sbin/tec-tac-sandbox --status
   ```

   **PASS:** `"enabled": false`. **FAIL:** anything else. Send the output.
8. Check nothing else broke. **PASS:** the Tactical web page loads; an agent checks in; `systemctl status tec-tac-sandbox.slice` shows no failed units. **FAIL:** any of the three. Say which.

**What to send back after any FAIL:** the whole canary output, the output of `--status`, `/var/lib/tec-tac/sandbox/canary.json`, `/var/lib/tec-tac/sandbox/status.json`, the last 40 lines of `/var/lib/tec-tac/sandbox/audit.jsonl`, `ls -la /usr/local/lib/tec-tac/sandbox/root`, `systemctl --version` and `uname -r`. Send both whole logs (before and after) even if everything passed.

## What changed and why

Today a sandbox run sees the server's file system with 12 folders hidden. Anything that is not on that list is visible: `/boot`, `/snap`, `/usr/local/sbin`, and the backup folders. A new folder would be visible by default. This release turns the list around. A run now starts with an almost empty root and sees only what Core puts into it.

* **A Core-made root for every run (the allow-list).** `install.sh` builds `/usr/local/lib/tec-tac/sandbox/root`. It holds only empty mount points. The unit starts with `RootDirectory=` on that folder, so everything not bound in does not exist for the run. The helper checks the folder at every start and in the selftest. A mismatch means no run, with the plain message `the sandbox root folder does not match this server; run the Core install again`. There is no weaker mode. The host's own `/usr/local` is replaced by an empty folder, and only the launcher and the runner's own folder are bound back into it.
* **One bind for a module's runtime.** A run now gets `/opt/tec-tac/runtimes/<module id>`, read only, as one bind. The per-root paths from the manifest are still checked (tree hashes) at every start. They never reach a unit property.
* **No module text in any unit property (AD-65).** The unit is built from Core constants, the checked module id and the hex run id. Every number is checked against its Core ceiling again before it is written. A final step checks the whole property list against a closed set. A later edit that adds a module string makes every start fail instead of reaching systemd.
* **Credentials use fixed slot names.** The unit sees `cred0` and `cred1` only. The launcher links each declared name to its slot under `/work/credentials`. A runner still reads `$CREDENTIALS_DIRECTORY/<declared name>`, and the file keeps its mode and access list.
* **Better memory evidence.** The helper now watches the run's own memory counters (`memory.events`, `memory.peak`) while the run lives, from a fixed path. The 1.17.124 read happened only at the end and was still `NOT RUN` on dev02. The end frame gains one extra key, `evidence`, that names where the kill count came from.
* **The helper writes its own audit rows.** `run.started` goes in before the unit is started. If it cannot be written, the run does not start. `run.ended` goes in for every end: normal, timeout, out of memory, cancel, or the caller walking away. A direct `sudo tec-tac-sandbox --start` leaves a record even if Django is bypassed. The rows hold counts, words and ids. They never hold the input, an output, a parameter, a credential, a person's name or a path.
* **A canary that lists, not guesses.** A new `rootview` group makes root list the host's own entries of 11 folders. The run lists what it sees. Any visible name that is not on the allowed list is `ATTACK SUCCEEDED`, with the first ten named. A second row checks the run's own `/`. Root also makes a fresh folder `/tectac-canary-<12 hex>` with one marker file. Marker files are made with `O_CREAT|O_EXCL|O_NOFOLLOW`, so a planted link is never followed (the lesson of 1.18.7-1). The canary removes only a folder with exactly that name, directly under `/`, and only when it is empty.
* **Housekeeping.** `RELEASE_NOTES_1.18.7.md` moved to `docs/releases/`. `tests/version-1.18.7.py` moved to `tests/legacy/` with `ROOT` set to `parents[2]`, and its stale 1.18.7-1 assertions corrected the way the 1.18.6 one was. Test only.

## Differences from the plan, found in the code

* **The cgroup path is nested.** The plan named `/sys/fs/cgroup/tec-tac-sandbox.slice/<unit>`. systemd reads a dash in a slice name as nesting, so the real path is `tec.slice/tec-tac.slice/tec-tac-sandbox.slice/<unit>`. The watch tries the nested path first and the flat one second. Both are built from constants and the hex run id. `finish_run` reads the same fixed path first. If neither has a file, the 1.17.124 lookup through `systemctl show -P ControlGroup` still runs, so a server that nests differently does not lose the evidence. dev02 shows which one worked: the memory row names its `evidence`.
* **Order of the skeleton.** The first draft of the install block created files before their folders, because a bash associative array has no order. A test caught it. The block now sorts the entries, parents first.
* **An empty directory in the runtimes folder is not a leak.** A module that has run once leaves an empty mount point in the root. The `view /opt/tec-tac/runtimes` row ignores an empty directory and flags a non-empty one.
* **The before program exits 1 on any `NOT RUN` row,** as well as when the `view /` row or the stand-in row does not show `ATTACK SUCCEEDED`. The plan said exit 1 only for the second case. The checklist FAIL line already listed `NOT RUN`.
* **`PROBE_PROPERTIES` lost its `filesystem_view` entry.** The selftest builds that probe from `file_view_properties()`, the same function the unit builder uses, so the two cannot drift.
* **Test hooks.** `CANARY_STANDIN_PARENT` (`/`) lets a test make the stand-in folder somewhere harmless. The launcher copies a slot file where symlinks do not exist (never on a server).

## Module-facing

None. `core.sandbox` stays at 1.0.0. No module declares `sandbox_runners`. `ai` only names the capability in a disabled placeholder. The end frame gains one additive key, `evidence`, which the Django side ignores because it reads known keys only. `framwork/tec_tac/sandbox.py` and its `sandbox.run.*` audit rows are unchanged.

What a runner sees changes once the sandbox is on. It sees only its own runtime folder, and its credentials still sit under `CREDENTIALS_DIRECTORY` by declared name.

## Assumptions (also in `reviews/questions/core.md`)

* **Credential names.** Fixed slots `cred0` and `cred1` in the unit, with a launcher symlink, are the literal reading of AD-65. If dev02 shows the symlink breaks a runner, it comes back to you as "keep the names in the property with a stricter character class". It never widens silently.
* **One runtime bind per module id.** A run sees the whole read-only runtime folder of its own module, not only the hash-checked roots. The folder is root-owned and read only, other modules' folders stay hidden, and the tree-hash check still runs on the declared roots at every start.
* **The `/rmmbackups` row cannot fail on 1.18.7.** The folder is `0700`. The stand-in folder and the listing rows are the proof.
* **Three systemd facts are proven only on dev02.** (1) `+` prefixed `ExecStartPost` and `ExecStopPost` commands run outside `RootDirectory=`. (2) `LoadCredential` and `PrivateTmp` mount points work inside the skeleton. (3) `/run` inside the unit holds only `credentials`. A wrong assumption shows as a failing canary row with the unit's own error text. The fix goes into a `-N` rebuild, or the release is held. The kill switch is off either way.

## What is not in this release

* Patch B (Core 1.18.9): private network, egress proxy, `allowed_hosts`, no DNS inside the run. The network is as it was.
* Patch C: killing leftover processes before the credential is read, the contract text, splitting selftest and canary into a root-only file, the `-I` shebang, registration type checks, the drop pattern, and the `io_uring` and `userfaultfd` filters.
* Audit rotation for `/var/lib/tec-tac/sandbox/audit.jsonl`. A row is about 300 bytes. Rotation is not part of this patch.
* Hardening the root-made marker in `/rmmbackups` beyond `O_EXCL|O_NOFOLLOW` (the Lows of the 1.18.7-1 review): a backup-helper item.
* "core-category modules cannot be disabled or uninstalled", the Welcome requests, and every other open request in `reviews/requests/core.md`.
* Docker or a separate remote runner as the sandbox. Johan, 18 November 2026: leave the Docker path for now.
* The kill switch. `SANDBOX_ENABLED` is `False` in the helper and in `sandbox.py`.

## What could not be run on the PC

No Linux, systemd, cgroups or Django here. Every unit-level fact (does systemd accept `RootDirectory=` with these mount points, what a run sees, what the kernel reports for memory) is proven only by the dev02 canary above. On this PC the tests ran against a fake file system and a fake `systemd-run`. The skeleton builder ran in bash against a temp folder, but the symlink form of a merged-`/usr` host (Ubuntu 22.04 and later) did not: dev02 shows it in `ls -la` of the root folder. Tests that need `fcntl`, `pwd` or `grp` run only on Linux.

## Requests

This release does not close `core.sandbox: consolidated fix plan, three patches (Johan, 18 November 2026, AD-65)`. It is Patch A of three. The entry ends when Patch C's canary passes in full on dev02 and on a second kind of server. The release manager records Patch A against it. After signing 1.18.8, ask Johan to run the before and after blocks above and send back both whole logs.

## Fixed after precheck

* The credential-slots test reused one work folder for several launcher runs. On Linux the second run hit an existing link, linked nothing and the `TOKEN=` assertion failed. Each launcher run in the test now gets its own fresh work folder.
* `link_credentials` in `scripts/sandbox-launcher.py` now removes an existing target before linking, so a reused folder behaves the same on every OS. A server is unaffected: `/work` is a fresh tmpfs per unit.
