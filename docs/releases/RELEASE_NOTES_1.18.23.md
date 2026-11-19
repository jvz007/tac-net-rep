# Tec-Tac Framework 1.18.23

Date: 19 November 2026. core.sandbox Patch B, step 1: the canary rows come first. This release adds the network probes and a dev02 script that shows what a run can do on the network today. Enforcement does not change. `SANDBOX_ENABLED` stays `False`.

## Module-facing change

None. Test probes and test scripts only. No contract, capability, endpoint or import changes. Nothing under `modules/` calls core.sandbox.

## What changed and why

### The rule (AD-65)

Patch B will give each run its own network space and one proxy door. A new wall proves nothing unless its test is first seen to fail without it. So this release ships the tests and no wall.

Before Patch B, each row must behave as follows on today's build:

- Rows that Patch B changes must show ATTACK SUCCEEDED. If one shows OK, the row cannot tell a wall from no wall.
- Rows that already hold must show OK. They become regression guards that must stay OK after Patch B.
- The seven proxy rows cannot run yet. They show NOT RUN, "no proxy yet (Patch B)".

### 1. New probe group in `scripts/sandbox-canary-runner.py`

- New dict `NETWORK_GROUPS` with one group, `patchb_network`. It sits outside `GROUPS`, and `main()` runs both. The helper's `CANARY_GROUPS` and its normal table do not change, so `tests/sandbox-canary-1.17.118.py` (`runner.GROUPS` equals `CANARY_GROUPS`) stays green and `scripts/sandbox-helper.py` is byte-identical to 1.18.22.
- Each row prints one `CANARYROW` line in the existing format. SUCCEEDED means the run can do what Patch B will forbid. OK means it cannot. SKIP means the host itself cannot do the thing, so the row has no control. NOTRUN means the probe proves nothing (an unexpected errno, or no proxy).
- The plan comes from the driver on stdin: `host_public`, `host_dns`, `host_ping`, `host_ipv6`, `loopback_ports`, `own`, `gateways`, `allowed_host`, `allowed_host_address`, `listen_seconds`.
- The probes run in a pool of 12 threads. The runner reads the `/proc/self/net` tables first, before any probe socket exists, so a private network space shows none of its own sockets. Patch B's in-unit forwarder (127.0.0.1:3128) is never counted as a host socket and is never probed as a host service.

### 2. Root driver `tests/sandbox-canary-network-1.18.23.py`

Run on dev02 as root. It loads the installed helper and builds the plan: host controls (public connect, DNS, ping, IPv6), this server's own addresses and gateways, and the host's listening ports. It then starts the group through the helper's own `launch` with the real unit properties of the current build. The group choice is added to this run's copy of the row, so the helper needs no edit and its constant is not changed.

It prints the table in the helper's format, `ROW` and `DETAIL` lines, a classification per row, and a last line `PATCH B NETWORK ROWS: n ATTACK SUCCEEDED, m NOT RUN, k SKIPPED, expected before Patch B: rows ...`.

- Exit 0: the table matches the expectation.
- Exit 1: an expected-OK row shows ATTACK SUCCEEDED (a real hole today), an expected-ATTACK row shows OK (the row proves nothing), a row other than a proxy row is NOT RUN, or a proxy refusal row shows a tunnel opening.
- Exit 2: the unit could not start.

The host connects to the listener from 127.0.0.1 and from the server's own address after the runner prints `CANARYLISTEN<TAB>port`. If the host never tried, the listener row becomes NOT RUN.

Stand-ins: `example.com` is the allowed host (resolved on the host; override with `TECTAC_CANARY_ALLOWED_HOST`). The public targets are 1.1.1.1 and 9.9.9.9, and the IPv6 target is 2606:4700:4700::1111. The probes only open and close connections. Nothing is sent beyond one DNS query and one ping echo.

### 3. Script `tests/sandbox-canary-1.18.23.sh`

A copy of the 1.18.22 script with every step id and check kept. Changes:

- Version strings and copy hints say 1.18.23.
- The helper guard also needs the installed canary runner to hold `patchb_network` (an older runner is refused: "update Core first"). It also refuses a helper that already has `PrivateNetwork=yes`, because this script is the before-Patch-B run.
- New mode `sudo bash tests/sandbox-canary-1.18.23.sh network`: the guards, the selftest and step 5t only, about 1 to 2 minutes.
- New step 5t, after 5s and before step 6. It runs the driver, prints its table in full and passes on driver exit 0. ATTACK SUCCEEDED rows inside 5t are expected. They come from a separate output, so steps 4k, 4l and 4m never count them.
- After the usual `ALL CANARY STEPS PASSED` or `n STEP(S) FAILED` line, the script prints the `expected before Patch B:` list.

The 1.18.22 script stays in `tests/`.

### The rows, and what each shows today

| Row | Today | Why | Patch B |
|---|---|---|---|
| public tcp 443 to 1.1.1.1, public tcp 80 to 1.1.1.1, public tcp 443 to 9.9.9.9, tcp 443 to the allowed host's own address (no proxy) | ATTACK SUCCEEDED | The address filter denies private ranges only. Any public host and port works. | OK: no route except the proxy |
| resolv.conf lists a name server, getaddrinfo resolves example.com, udp 53 answered by the listed name server, udp 53 answered by 9.9.9.9 | ATTACK SUCCEEDED | A run has Core's own resolver list and direct DNS. | OK: no DNS inside |
| proc net tcp lists host sockets, proc net udp lists host sockets, network interfaces other than lo visible, default route visible | ATTACK SUCCEEDED | The run shares the host's network space. | OK: its own space with `lo` only |
| AF_PACKET socket, raw ICMP socket, AF_NETLINK route socket, AF_INET6 socket creation, tcp 443 to the IPv6 address | OK | `RestrictAddressFamilies=AF_INET` and the capability set already refuse them. | OK (guards) |
| host loopback services, own address tcp 22/80/443, default gateway tcp 80/443 | OK | The per-start address filter drops them. | OK (guards, after the per-start filter code is removed) |
| listener reachable from the host | Either | See "Where the plan was wrong" below. | OK |
| ICMP ping socket echo to 1.1.1.1 | Either | Depends on `net.ipv4.ping_group_range`. Not a required row. | OK |
| the seven proxy rows (positive control and six refusals: host not in allowed_hosts, IP literal, private address, this server's own address, allowed host on port 80, allowed host on port 22) | NOT RUN, "no proxy yet (Patch B)" | No proxy exists. | OK (200 on a refusal row is SUCCEEDED) |

Exit list for the Patch B canary: every row above OK, with 0 NOT RUN. The table is 29 rows; a SKIPPED row means the host had no control for it and is shown, never counted as OK.

### Where the plan was wrong

- The plan listed "listener reachable from the host" as ATTACK SUCCEEDED today. systemd's `IPAddressDeny` filters received packets as well as sent ones. The host can only reach a run's listener from 127.0.0.1 or its own address, and the current build denies both. So the row may read OK today. If we kept it as "must be ATTACK SUCCEEDED", step 5t could fail on a correct build. We made it "either result today" and it must be OK after Patch B. If dev02 shows ATTACK SUCCEEDED, that is a finding about the current wall.
- The plan named the driver and the runner test with the same file name. The driver is `tests/sandbox-canary-network-1.18.23.py`, the runner test is `tests/sandbox-canary-network-runner-1.18.23.py` and the driver test is `tests/sandbox-canary-network-driver-1.18.23.py`.
- `socket.if_nameindex()` needs netlink in glibc, and a run has `AF_INET` only. If it is refused, the row falls back to `/proc/self/net/dev`, so the interface row does not read OK for the wrong reason.

### Release bookkeeping

`RELEASE_NOTES_1.18.22.md` moved to `docs/releases/`. `tests/version-1.18.22.py` moved to `tests/legacy/`. New: `tests/version-1.18.23.py`, `tests/sandbox-canary-network-runner-1.18.23.py`, `tests/sandbox-canary-network-driver-1.18.23.py`, `tests/sandbox-canary-script-1.18.23.py`.

## Johan dev02 checklist

a. Update dev02 to Core 1.18.23 from the dev branch (the runner is installed by `install.sh`). PASS = the update finishes and Core starts. FAIL = it does not: send the error.
b. Run the full canary:

   `cd /opt/tec-tac-src/framework && cat VERSION && sudo bash tests/sandbox-canary-1.18.23.sh 2>&1 | tee ~/sandbox-canary-1.18.23-$(date +%Y%m%d-%H%M).log`

   The quick variant, for the network rows only: `sudo bash tests/sandbox-canary-1.18.23.sh network`.
   PASS = it starts and prints step 1 lines (or the selftest in network mode). FAIL = "the installed canary runner is older than Core 1.18.23": the update in step a did not reach the installed runner. FAIL = "already has PrivateNetwork=yes": send the message.
c. PASS = the last line before the `expected before Patch B:` line is `ALL CANARY STEPS PASSED`, and step 5t shows PASS with the expected rows as ATTACK SUCCEEDED. FAIL = any other step failing, an expected-OK row showing ATTACK SUCCEEDED, or an expected-ATTACK row showing OK. Send the whole output.
d. Confirm the sandbox is still off: `SANDBOX_ENABLED` is `False` and `--status` shows it disabled. PASS = off. FAIL = on: send the status output.

Send back the whole output, passed or not.

## What could not be run

- The real canary and the real probes. They need root, systemd, cgroup v2 and a Linux server (dev02). Step 5t and the driver have never run against a real unit; the dev02 run is the proof.
- Anything that imports Django. Django is not installed on this PC. This release touches no Django code.
- On this PC (Windows) the runner test uses stubs for the socket layer and real local sockets for the listener and proxy-reader checks. `/proc`, `AF_PACKET` and `AF_NETLINK` are stubbed.

## Assumptions

- Separate group dict plus a root driver, not a new `CANARY_GROUPS` entry. It adds no trust and leaves the 1.18.22 enforcement and table untouched.
- Step 5t passes when the table matches the expectation, so the canary-first proof is real. ATTACK SUCCEEDED rows are expected before Patch B and do not read as a release failure.
- The seven proxy rows show NOT RUN with a plain reason now, so the Patch B canary has its full row list from the first run.
- The stand-in hosts above. A row whose target the host itself cannot reach shows SKIPPED, not OK.

## What is not in this release

- Patch B enforcement: `PrivateNetwork=yes`, the egress proxy with `allowed_hosts`, no DNS inside, and removal of the per-start address filter code. It is the next sandbox patch, after the dev02 run of this release shows the expected rows.
- Patch C and any change to `scripts/sandbox-helper.py`, `install.sh`, unit properties or the kill switch.
- The other open requests in `reviews/requests/core.md`. This release has one theme.
