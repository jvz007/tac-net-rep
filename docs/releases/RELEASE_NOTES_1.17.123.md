# Tec-Tac Framework 1.17.123

Date: 11 November 2026. `core.sandbox` canary: seven fixes from the dev02 run of Core 1.17.122 (106 OK, 9 ATTACK SUCCEEDED, 0 NOT RUN, 2 SKIPPED). **Nothing can run in the sandbox yet.** `SANDBOX_ENABLED` stays `False`. The sudo rule, `install.sh`, the registry, the status keys and the public contract `core.sandbox` 1.0.0 are unchanged. The kill switch is not touched. Every change is in the root-only helper (`scripts/sandbox-helper.py`), the in-unit canary program (`scripts/sandbox-canary-runner.py`), one doc and tests. No Django file changed.

Request: "core.sandbox canary 1.17.122 on dev02: 9 ATTACK SUCCEEDED (Core 1.17.123)" in `reviews/requests/core.md`. It stays open. It ends only when a signed Core 1.17.123 is installed on dev02 and its canary finishes with `ALL CANARY STEPS PASSED` (0 ATTACK SUCCEEDED, 0 NOT RUN, no security row SKIPPED), kill switch still off. **Release manager: mark it closed only on that result, and close the 1.17.122 held Low (credential rule wider than described) when this signs.**

Everything here tightens or measures; nothing widens a signed decision. Two open questions for Johan (abstract sockets, upstream resolver) are recorded as information in `reviews/questions/core.md`, Core 1.17.123, with the assumption I went on with.

## What changed and why

### 1. No loopback allow at all; Core's own resolv.conf

dev02 showed six rows that connected: `resolver 127.0.0.53` on ports 22, 80, 443, 1024, 4430 and 4433. `IPAddressAllow` is per address, not per port, and services bound to all local addresses answer on 127.0.0.53.

* **`IPAddressAllow` is gone.** `allow_property` is removed. A unit, a probe and an argv never carry an Allow. `ADDRESS_DENY` is unchanged and numeric.
* **Core's own `resolv.conf`.** At each start root writes `RUN_ROOT/resolv.conf` (root-owned, mode 0644, atomic write through `_write_root_file`, at most three IPv4 `nameserver` lines) from the upstream list in `/run/systemd/resolve/resolv.conf`. The unit binds it read only over `/etc/resolv.conf`. `/etc/resolv.conf` leaves `BASE_BINDS_REQUIRED`. If the upstream file is missing, `/etc/resolv.conf` is read, but only as a regular file with real addresses (never the link to the stub).
* **Selftest rule.** Upstreams are IPv4 only (a run has AF_INET only). An upstream inside a denied range (loopback including the 127.0.0.53 stub, private, link-local, carrier-grade NAT), one of the server's own addresses, or the gateway makes the sandbox **not ready**, with a plain reason that names the address. There is never an automatic allow. The DNS probe talks to each upstream directly from a unit under the full deny list and keeps the rule that any DNS reply (NXDOMAIN too) counts.
* **At each start** `usable_resolvers` keeps only upstreams that are in the selftest's proven list, still in the upstream file and still outside the denied ranges. None left is `Refusal sandbox_unavailable`.
* **Status.** The keys stay (`ready`, `resolver`, `resolvers`, `dns_ok`). `resolvers` is now the list of upstreams that answered. `dns_method` is `resolv_conf_bind` (not part of the public status answer).
* **Canary.** The loopback group tries `127.0.0.53` on the listening ports and on 22, 80, 443, 1024, 4430 and 4433. The old `resolver <ip>:<port>` rows are gone. "other resolver dropped" now tests the host's own `/etc/resolv.conf` entries and always the stub, so the row exists on every server and is never SKIPPED.
* `docs/sandbox-capability.md` is updated.

### 2. Every local address and the default gateway(s) are denied

dev02: `udp 129.232.197.1` (the gateway) was sent, and the server's own public address was not tested.

* At each start root reads `ip -o addr show`, `ip -4 route show default` and `ip -6 route show default` and appends each address and next hop as `/32` or `/128` to the unit's `IPAddressDeny` (numeric, no repeats, at most 64 outside the ranges already denied; an address already inside a denied range, such as the docker bridge, is not listed twice). The public internet keeps working, because the filter judges the destination address, not the next hop.
* **Fail closed.** If `ip` fails, no address can be read, a default route has no readable next hop, or there are too many, the start is refused with `sandbox_unavailable`. The functions are `parse_local_addresses`, `parse_gateways`, `local_deny` and `read_local_deny`. (The plan called the last one `deny_list`.)
* **Selftest.** A new probe sends a UDP packet to the own address and the gateway from a filtered unit and must get `eperm`, with a control unit without the filter that must send (a probe that cannot send anyway is never read as a pass). The DNS probe runs under the same full deny list.
* **Canary.** The LAN group adds `own address <ip> tcp 22/80/443`, `own address <ip> udp`, `gateway <ip> tcp 80/443` and `gateway <ip> udp`. A connection, or a refusal (a reset only comes from a host that was reached), is ATTACK SUCCEEDED. A missing row is NOT RUN (`CANARY_REQUIRED` and the plan's row names).
* Known limit, information only: an address that appears after a run has started (a DHCP change) is covered from the next start.

### 3. Memory beyond MemoryMax

`MemorySwapMax=0` was already set, so swap alone does not explain the dev02 `exited`. The likely cause is that the kernel kills only the runner child, the launcher survives and exits 137, and systemd then records `exit-code`, not `oom-kill`.

* The unit gets `MemoryZSwapMax=0` beside `MemorySwapMax=0`, only when the selftest saw systemd 255 or newer (an unknown property must not make every start fail; the selftest records the choice as information in the new `memory_zswap` row), and `OOMPolicy=kill` (tightening only).
* The in-unit probe prints a flushed `CANARYMEM` progress line after every 16 MiB block, and the helper keeps the last one. The row is OK only when the run was stopped (reason `oom`, or `exited` with exit 137) and the last allocation and the memory peak are at or below MemoryMax plus one block. Allocating past it, or finishing normally, is ATTACK SUCCEEDED. No end frame is NOT RUN. The "actual" column reads `allocated N MiB, ended <reason>`.

### 4. Credential frame stripping on every path

Every runner row in the dev02 table says `CREDENTIALS_DIRECTORY`, and the 1.17.122 check was `'CRED' in stdout`. The `found in output` result was very probably a false positive of the check, not a leak. Both halves are fixed:

* **The check** looks for the real thing in stdout, stderr, the end frame (every field except `credential_b64`) and the refusal: the nonce-shaped frame start (`[0-9a-f]{32} CRED `), the launcher header text, the token and the refreshed token (plain and base64). The words `CREDENTIALS_DIRECTORY` and `CRED` alone are not a finding. The row reports exactly which check found what.
* **The parser** (`StreamParser.finish`): a partial marker held back at EOF is now dropped when it is a prefix of the marker (before, up to 38 bytes, including part of the nonce, could be emitted), and nothing is emitted when the launcher header never arrived. A lone trailing newline is kept. Every other path was checked and is covered by tests: a frame split at every byte offset, cancel, timeout and output cap in the middle of a frame, a frame with no newline before the stream ends, an oversized or garbled frame, a runner without `credential_return`.
* **Django side (read only):** `credential_b64` is read in one place, `RunHandle._end_event`, and is never logged, audited or placed in out or err events. No change was needed there.

### 5. Abstract unix sockets from a root-made list; the AF_UNIX decision

The row was SKIPPED because `ProcSubset=pid` hides `/proc/net` inside the unit. Root now reads `/proc/net/unix` (stream and seqpacket listeners whose path starts with `@`, at most 200, names byte-exact in the JSON plan) and passes the list in the plan. The in-unit probe tries each one and prints only a verdict and a cleaned name, never content. If root cannot read the list, the row is NOT RUN. The row reports how many were listed. Information only: root's own throw-away abstract listener shows whether the namespace is shared.

* `canary_summary`: a SKIPPED row in any security group fails the canary. Only `public tcp 443` (a server with no public route) may be SKIPPED. `canary.json` lists the skipped rows and the failing skipped ones. The `SKIP` paths in the loopback and DNS groups are removed.
* **Decision, recorded:** `AF_UNIX` stays in `RestrictAddressFamilies` for runners. The runners are Node-based CLIs and libuv creates `socketpair(AF_UNIX)` pipes for child processes; seccomp cannot tell a pathname or abstract connect from a socketpair. The abstract namespace belongs to the network namespace, which `IPAddressDeny` does not change. So the unit does not keep abstract sockets out, the canary detects them. If dev02 lists a reachable host listener (a stock Ubuntu often has `multipathd` or `iscsid`), the row fails, and the plan's fallback (`PrivateNetwork=yes` plus a socket bridge for DNS and 443) goes to Johan as a design question (Question 1 of 1.17.123). Nothing is widened and it is not built before the dev02 result.

### 6. The credential rule and the 1.17.122 record

`credential_mode_problem` accepts group root only when the file's ACL contains the named entry `user:<unit uid>` with read only. Mode 400 or 440 `root:root` with no ACL is refused, with a plain reason (the unit could not read it anyway). The owner rule is unchanged (root or the unit's uid); the group is otherwise only the unit's own gid. The dev02 shape stays accepted.

**Correction of the record.** 1.17.122 was **not a pure narrowing of 1.17.120**. It newly accepted root as owner or group, and it added the uid floor of 61184, while removing the "any dynamic gid" case. 1.17.123 narrows group root to the ACL case. The correction is appended to `RELEASE_NOTES_1.17.122.md` (moved to `docs/releases/`, as the integrity test wants one root note) as "Correction (Core 1.17.123)" and to Question 1 of 1.17.122 in `reviews/questions/core.md`.

### 7. New canary script

`tests/sandbox-canary-1.17.123.sh` (the 1.17.122 script and its static test stay untouched). Same steps, with these changes: the helper guard needs the markers `MemoryZSwapMax`, `local_deny`, `parse_abstract_sockets` and `resolv_conf_bind` and refuses an older installed helper; step 2 prints the selftest rows for the upstream resolvers, the own addresses, the gateway and the memory choice as information; step 4 checks that the table has the new rows and that 0 rows are ATTACK SUCCEEDED, 0 NOT RUN and no security row SKIPPED (only `public tcp 443` may be); it prints the host's abstract listener names (names only) and Core's own resolv.conf as information. The padding-safe patterns are kept. It never enables the kill switch and holds no real secret.

## Tests

* New: `tests/sandbox-resolv-bind-1.17.123.py` (fix 1), `tests/sandbox-local-deny-1.17.123.py` (fix 2), `tests/sandbox-memory-1.17.123.py` (fix 3), `tests/sandbox-credential-frame-1.17.123.py` (fix 4), `tests/sandbox-abstract-1.17.123.py` (fix 5), `tests/sandbox-credential-root-group-1.17.123.py` (fix 6), `tests/sandbox-canary-script-1.17.123.py` (fix 7: runs the script's own grep and awk lines against a real table, and mutates the table to prove each step can fail). Each can fail: the 1.17.122 code lets the stub through, accepts root:root with no ACL, emits a held partial marker, reads `exited` as an attack, and has no own-address probe.
* Updated for the new builder and selftest: `sandbox-harness-1.17.118.py`, `sandbox-fake-runner-1.17.120.py`, `sandbox-unit-builder-1.17.118.py`, `sandbox-selftest-1.17.116.py`, `sandbox-address-numeric-1.17.120.py`, `sandbox-launch-1.17.118.py`, `sandbox-exec-escape-1.17.119.py`, `sandbox-path-chars-1.17.119.py`, `sandbox-percent-refuse-1.17.120.py`, `sandbox-canary-1.17.118.py`, `sandbox-credential-acl-1.17.122.py` and `sandbox-credential-mode-1.17.120.py`.
* **Not run here:** real systemd, root, Linux, Django and dev02. Whether the bind over `/etc/resolv.conf` works under `TemporaryFileSystem=/etc`, whether `127.0.0.53` and the own address are refused, whether the kernel's kill is seen as exit 137, and whether a host abstract listener is reachable can only be shown on dev02. Tests that need an AF_UNIX abstract socket run only on Linux and say so on other systems.

## dev02

Update dev02 to Core 1.17.123 and export the public contract as usual. Then run `sudo bash tests/sandbox-canary-1.17.123.sh` as root and send back the whole output. dev02's upstream resolvers (156.38.225.225 and 156.38.225.226) are public, so the new resolver rule does not stop it.

## Module-facing changes

None. A search of `modules/` finds `core.sandbox` used only by `modules/ai` (`providers.py`, `runner.py`) and `reportmanager` (`ai_schema`), through `tec_tac.sandbox`. None reads `dns_method`, the resolver keys, the canary table, the selftest rows or the credential frame; the public contract surface (`sandbox.py`, `sandbox_views.py`, `contracts.py`) is unchanged. `ai` is the only module on the credential-return path: the frame format and `credentials_out` are unchanged, and nothing about them is read differently.
