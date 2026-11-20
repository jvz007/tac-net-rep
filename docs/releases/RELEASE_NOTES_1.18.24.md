# Tec-Tac Framework 1.18.24

Date: 19 November 2026. core.sandbox Patch B: the network wall. A run now has its own, empty network space and reaches the network through one proxy door. The address filter, the per-start deny list and the resolver code are gone. `SANDBOX_ENABLED` stays `False`. Nothing is switched on, and no Patch C item is in this release.

## Module-facing change

The `core.sandbox` contract text, the manifest rules for `sandbox_runners` and the answers of `status()` and `describe()` change. Every change is additive or relaxes a refusal, and no module under `modules/` declares `sandbox_runners` or calls `core.sandbox` today (checked with a search of `modules/`). The only planned user is `ai` (a premium module, not yet built against this). Nothing breaks.

### `allowed_hosts` is allowed again (additive)

A runner entry may carry `allowed_hosts`. Before this release a manifest that declared it was refused ("the smaller sandbox has no host list").

- Optional list, at most 16 entries.
- Each entry is an exact, lower-case DNS name with at least two labels (letters, digits and `-`, labels of 1 to 63 characters, 253 characters at most).
- Refused: wildcards, ports (the port is always 443), paths, `@`, `%`, bracketed or colon addresses, IP literals in any spelling (dotted, decimal, hex, octal, short: the last label of a name is never all digits or a `0x` number), single-label names, names ending `.local`, `.internal`, `.localhost` or `.lan`, upper case, empty entries, repeats.
- `registry.py` (`_sandbox_allowed_hosts`) and the root helper (`check_allowed_hosts`) apply the same rules. A test keeps the two copies in step. The list is carried in the PluginSpec runner entry and in the registry row. The helper checks the row again at every start.
- A manifest without the key behaves as before. Its run has no door.
- `describe()` gains an `allowed_hosts` key (additive).

### Reserved proxy environment names

`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`, `ALL_PROXY`, `NO_PROXY` and `no_proxy` are Core's. A manifest `environment` that sets one is refused, by `registry.py` (`SANDBOX_RESERVED_ENV`) and by the helper (`RESERVED_ENV`). Core sets `HTTPS_PROXY` and `https_proxy` to `http://127.0.0.1:3128` only for a runner that has `allowed_hosts`. Nobody else sets them.

### What a run's network is now

- A run has its own network space (`PrivateNetwork=yes`). It sees only `lo`. It has no interface, no default route, no DNS and no `/etc/resolv.conf`.
- It reaches only the hosts in its `allowed_hosts`, on port 443, through the egress proxy. A program that needs the network must honour `HTTPS_PROXY` (an HTTP `CONNECT` proxy). A program that connects straight out fails at once.
- A runner with no `allowed_hosts` has no network at all: no proxy, no forwarder and no proxy variable.
- It can no longer reach this server's loopback, the LAN, the cloud metadata address or a public host directly. The old filter did not make this possible to prove. The new wall does.
- `status()`: `address_filter_ok` now means "the network wall is proven" and `dns_ok` now means "the egress proxy resolves names and opens a tunnel". Both keep their names and types. `network_private_ok` and `egress_ok` are new, with the same two answers (additive). The names `resolver`, `resolvers` and `dns_method` stay in `status.json` as empty values, so every reader still works.

### `AF_UNIX` is allowed for the egress door

The unit property is now `RestrictAddressFamilies=AF_INET AF_UNIX` (it was `AF_INET`). A run needs `AF_UNIX` only to reach the door. Host path sockets are not in the run's file view, and abstract sockets belong to the run's own network space, so a host listener cannot be reached. The 13 `unix <host path>` rows and the abstract group of the canary must still read OK. The four `unix socket creation refused` rows of 1.17.124 are retired.

### Contract export

`contracts.py` text is rewritten (manifest key paragraph and the `core.sandbox` paragraph) and `docs/sandbox-capability.md` has a new section. The public contract export cannot be generated on this PC (it needs a running server). The release manager exports a fresh file into `docs/contracts` after signing.

## What changed and why

AD-65 Patch B. The review found that the address filter (`IPAddressDeny`) could not stop a run from reaching the server by every route, and that a listener a run opened stayed in the host's network space. Giving the run its own empty network space removes the whole class. The proxy is the one door, because the AI runners (the first users) must reach a few named HTTPS hosts.

### 1. The run unit gets its own network space

`scripts/sandbox-helper.py`:

- `UNIT_FIXED_PROPERTIES` gains `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_INET AF_UNIX` (one constant, `NETWORK_PROPERTIES`).
- Removed from the unit builder, the closed-set check, `launch` and `build_argv`: the `IPAddressDeny` line and its pattern, `deny_extra`, the `resolv.conf` bind, `core_resolv_file`, `resolv_conf_bytes`, `usable_resolvers`, `upstream_problem`, `read_upstream_text` and the `local_deny_now` call in `launch` (it is read now only for a run that has a door).
- `read_local_deny` and `local_deny` stay. They hand this server's own addresses and gateways to the proxy, and the canary reads them.
- `etc/resolv.conf` leaves the skeleton, `BASE_BINDS` and the canary's `/etc` view, and `install.sh` stops creating it. `nsswitch` falls through to its default and a lookup is refused at once inside the run's own loopback.
- `build_environment` sets the proxy variables only for a row with `allowed_hosts`. `RESERVED_ENV` and `SANDBOX_RESERVED_ENV` carry the proxy names.
- The closed set is the new exact list. The one extra entry, for a row with `allowed_hosts`, is `BindReadOnlyPaths=<egress-door>/<hex run id>:/run/egress`. Nothing in a unit property comes from a module string.

### 2. The socket-activated egress proxy

- New `scripts/sandbox-egress.py` (root-installed, 0755) and two static template units written by `install.sh`: `tec-tac-sandbox-egress@.socket` and `tec-tac-sandbox-egress@.service`. The instance name is the 32-hex run id, checked by the helper before any `systemctl` call.
- Socket: `ListenStream=/run/tec-tac/sandbox/egress-door/%i/door.sock`, `SocketMode=0666`. The parent folders are root 0700, so only a run, through its own bind of one folder, can reach it.
- Service: its own dynamic user, the run's configuration as a root-only `LoadCredential`, no capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectProc=invisible`, `ProcSubset=pid`, a system call filter, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryMax=64M`, `TasksMax=64`, `LimitNOFILE=256`, `RuntimeMaxSec=720`.
- A second wall: `IPAddressDeny=` with the helper's numeric private ranges, and `IPAddressAllow=127.0.0.53/32` for the systemd-resolved stub only.
- HTTP `CONNECT` only. It answers before any lookup or connect: 403 for a method that is not `CONNECT`, a port other than 443, an IP literal in any spelling, a single-label or `.local`-style name, and a host that is not an exact match in the run's list; 400 for a malformed request line or a head over 8 KiB or slower than 10 s.
- It resolves the name on the host, never inside the run. Every address must be global (no private, loopback, link-local, multicast, carrier-grade NAT, `0/8`, `240/4`, `198.18/15`, `192.0.0.0/24` or unspecified range, and no IPv4-mapped, NAT64 or 6to4 form of one). It must not be one of this server's own addresses or gateways, an address of this server's own name, or an address a `bind()` probe accepts. It then connects to the checked numeric address and never to the name again, so a second DNS answer cannot change the target.
- Limits: 16 tunnels at once, 100 per run, 256 MiB per run, 10 s to connect, 60 s idle.
- It never logs a payload or a header. One JSON line per `CONNECT` goes to its audit file (host, port, allowed or refused, a reason code, bytes up and down).
- The helper starts the socket before the unit (a door that does not start is `sandbox_unavailable` and no run), reads the audit file after the run (O_NOFOLLOW, 256 KiB and 200 rows at most, strict schema per row), writes the root audit row `run.egress` (counts and the capped rows) before `run.ended`, and adds `egress_allowed`, `egress_refused` and `egress_bytes` to `run.ended`. `finally` stops and removes the units, the door folder, the configuration and the audit state. `sweep()` removes a stale instance and stops its units. `uninstall.sh` removes the templates. The server-backup rollback inventory (`scripts/server-backup-helper.py`, `TEC_TAC_SYSTEMD_INSTALL_UNIT_NAMES`) lists the two templates, so a rollback records and removes them like the sweep units (found by `tests/server-backup-sandbox-rollback-1.17.117.py`).

### 3. The forwarder inside the run

`scripts/sandbox-launcher.py`: with `--egress` it binds `127.0.0.1:3128` in the run's own network space before the runner starts and relays each connection, byte for byte and unparsed, to `/run/egress/door.sock`. One single-thread `selectors` loop (a thread per connection would use up the run's `TasksMax`), at most 16 live connections, 60 s idle and 600 s total per connection. If the port cannot be bound or the door is missing, the launcher ends with exit 70 and one plain stderr line, before the runner and before the header. The skeleton gains the empty folder `run/egress` (`install.sh`, the helper's skeleton lists, the canary's `/run` view).

### 4. `allowed_hosts` in the manifest

See "Module-facing change". `contracts.py`, `sandbox.py` (`describe()` and the network sentence) and `docs/sandbox-capability.md` are rewritten.

### 5. Selftest and status

The address filter, own-address and DNS probes are replaced by two checks.

- `network_private`: a unit with the real network properties and the real file view sees only `lo`, cannot connect to 1.1.1.1:443 or to a loopback port of this server, and has no `resolv.conf`. A control run without the wall must reach the loopback listener first.
- `egress_proxy`: the template units start for a throw-away run id with one stand-in host (`example.com`). A `CONNECT` to it answers 200. An unlisted host, an IP literal and port 80 answer 403. The units are stopped and cleaned up, even when the start fails. A host whose name server is a private or loopback address other than `127.0.0.53` fails closed with a plain reason. It is never allowed automatically.

`ready` needs both. `status.json` also records `selftest_ms` (additive). The selftest now runs 9 probe units (it ran 13 to 15 before, one per name server) and the proxy check. The measured time can only come from dev02: the canary script prints it in step 2, and the install-speed request depends on it.

### 6. Canary rows, flipped to the Patch B exit list

- The helper's `dns` and `public` groups are retired (`CANARY_GROUPS`, `CANARY_REQUIRED`, `CANARY_SKIP_ALLOWED`). `loopback` and `lan` stay as guards and skip port 3128. No row of the normal table may be SKIPPED.
- The four `unix socket creation refused` rows are retired. The 13 host-path rows and the abstract group stay. The new row `unix door path without a door` must read OK.
- The proxy rows are live. The positive control sends `CONNECT` to the allowed host and must get 200. The six refusals (host not listed, IP literal, private address, this server's own address, allowed host on port 80, port 22) must be refused. A 200 on a refusal row is ATTACK SUCCEEDED. A positive control that cannot work because the host has no public route is SKIPPED, never OK. A door that cannot be reached is NOT RUN.
- Held finding (Medium, from the 1.18.23 review): the listener row can now show the attack. After the run prints its listener port, the driver reads the host's own `ss -ltnH` as root. A LISTEN socket on that port in the host's namespace is ATTACK SUCCEEDED. Not listed there is OK. The host's connect attempts stay as detail only. The runner's listener bind address is a parameter (0.0.0.0 inside the unit only).
- Held finding (Low): each attack row has its own host control (tcp 443 to 1.1.1.1, tcp 80 to 1.1.1.1, tcp 443 to 9.9.9.9, tcp 443 to the allowed host's address, udp 53 to 9.9.9.9, udp 53 to the first listed name server, and the existing DNS, ping and IPv6 controls). A row without its own control is SKIPPED.
- Held finding (Low): the host-service probes are separate pool jobs with a 15 s deadline. 40 slow ports finish well inside the run's time, and a partial result is printed with "partial: n of 40 tried", never an empty row. `NET_HOST_PORTS_MAX x NET_LOCAL_SECONDS` is 20 s even serially, under half of the 45 s run limit.

### 7. Script `tests/sandbox-canary-1.18.24.sh`

A copy of the 1.18.23 script. Every step id is kept. Step 5t is the Patch B exit list (below). New: 5u (the run with a door wrote `run.egress` before `run.ended`, with numbers only) and 5v (no egress unit, door folder, configuration or audit state is left). The guards need the installed helper to hold `PrivateNetwork=yes`, the installed egress program (root 0755) and both template units, and refuse an older installed runner ("update Core first"). The `resolv_conf_bind` marker is no longer required. Step 4 loses the four creation rows and the old DNS and public rows, and gains the door row. The audit check allows the egress keys. The 1.18.23 script stays in `tests/`.

### The Patch B exit list

Step 5t passes only when all of these are met:

- The 12 former ATTACK rows read OK: `pb-public-tcp-443-1-1-1-1`, `pb-public-tcp-80-1-1-1-1`, `pb-public-tcp-443-9-9-9-9`, `pb-direct-allowed-host-443`, `pb-dns-resolv-conf-listed`, `pb-dns-getaddrinfo`, `pb-dns-listed-server-answers`, `pb-dns-public-9-9-9-9-answers`, `pb-proc-net-tcp`, `pb-proc-net-udp`, `pb-interfaces-beyond-lo`, `pb-default-route`.
- The 7 proxy rows read OK: `pb-proxy-allowed-443` (positive 200), `pb-proxy-refuse-host`, `pb-proxy-refuse-ip-literal`, `pb-proxy-refuse-private`, `pb-proxy-refuse-own-address`, `pb-proxy-refuse-port-80`, `pb-proxy-refuse-port-22`.
- `pb-listener-from-host` and `pb-ping-socket-echo` read OK.
- Every other row reads OK. 0 NOT RUN. 0 ATTACK SUCCEEDED.
- A row may be SKIPPED only where the host has no control for that row. On dev02 that is `pb-tcp-443-ipv6` (no IPv6 route).

## Retired checks

These tests asserted removed code. They moved to `tests/legacy/` as earlier releases did.

- `sandbox-address-numeric-1.17.120.py`: the numeric deny values in the loopback, private, local and DNS probes, `build_properties(deny_extra=...)` and the DNS probe calls. All retired with the address filter.
- `sandbox-resolv-bind-1.17.123.py`: Core's own `resolv.conf`, its bind and the resolver rule. A run has no resolver.
- `sandbox-unix-1.17.124.py`: asserted `RestrictAddressFamilies=AF_INET` and "no AF_UNIX anywhere". The rule is reversed by Patch B.
- `sandbox-canary-network-runner-1.18.23.py`: asserted the 1.18.22 helper hash, "no proxy yet" and the before-wall expectations. Replaced by `sandbox-canary-network-runner-1.18.24.py`.
- `sandbox-canary-script-1.17.123.py`, `sandbox-canary-script-1.17.124.py`, `sandbox-canary-script-1.18.8.py`: each runs an old script's guards against the current helper, which by design no longer holds `resolv_conf_bind` and now allows `AF_UNIX`. The old scripts stay in `tests/`.
- `version-1.18.23.py`.

Updated in place (still valid, changed expectations): `sandbox-abstract-1.17.123`, `sandbox-bpf-info-1.17.120`, `sandbox-canary-1.17.118`, `sandbox-canary-rootview-1.18.8`, `sandbox-contract-1.17.116`, `sandbox-django-launch-1.17.118`, `sandbox-file-view-1.18.8`, `sandbox-helper-register-1.17.116`, `sandbox-installer-1.17.116`, `sandbox-installer-skeleton-1.18.8`, `sandbox-launch-1.17.118`, `sandbox-local-deny-1.17.123` (the unit-deny and own-address-probe parts removed; the parsers, `local_deny`, the refusals and the LAN rows stay), `sandbox-no-plus-1.18.14`, `sandbox-registry-1.17.116`, `server-backup-sandbox-rollback-1.17.117`, `sandbox-run-audit-1.18.8`, `sandbox-run-private-1.18.15`, `sandbox-selftest-1.17.116`, `sandbox-skeleton-run-1.18.13`, `sandbox-template-1.18.8`, `sandbox-unit-builder-1.17.118`, and the shared `sandbox-harness-1.17.118` and `sandbox-fake-runner-1.17.120`.

## New tests

- `sandbox-private-network-1.18.24.py`, `sandbox-egress-proxy-1.18.24.py`, `sandbox-egress-units-1.18.24.py`, `sandbox-egress-audit-1.18.24.py`
- `sandbox-launcher-forwarder-1.18.24.py`, `sandbox-allowed-hosts-1.18.24.py`, `sandbox-selftest-network-1.18.24.py`
- `sandbox-canary-network-runner-1.18.24.py`, `sandbox-canary-network-driver-1.18.24.py`, `sandbox-canary-script-1.18.24.py`
- `version-1.18.24.py`
- `sandbox-canary-network-1.18.24.py` is the root driver for dev02 (not a test: it needs root and the installed helper, like its 1.18.23 predecessor).

Every test on this PC stubs the socket layer, binds 127.0.0.1 on an ephemeral port only, never opens a 0.0.0.0 listener and never contacts a public address.

## Where the plan did not fit the code

- The plan listed `ai` as the only module affected. A search of `modules/` finds no `sandbox_runners` declaration and no `core.sandbox` call, so nothing breaks today.
- The plan said the selftest "adds two probe units". It removed five or more (the filter, own-address and per-name-server DNS probes) and added two (`network_control` and `network_private`). The selftest has fewer units than before.
- The selftest needs a real tunnel (200) to `example.com` from the host. A server with no outbound route is therefore not ready. The old `public tcp 443` row was allowed to be SKIPPED, but a sandbox for AI runners has no use without outbound HTTPS. See the question file.
- `read_local_deny` is read in `launch` only for a run that has `allowed_hosts`. The plan said it also feeds the canary: it does, in `run_canary`.

## What could not be run

- Root, systemd, cgroup v2, socket activation, `DynamicUser`, `LoadCredential` from a root-only file, `IPAddressAllow` over the deny list, and the proxy against real DNS. This PC is Windows and has none of them.
- Anything that imports Django: Django is not installed here. `registry.py` imports without it, so its rules are tested. `sandbox.py` and `contracts.py` are only compiled here.
- `AF_UNIX`: Windows has none. The forwarder and the door row are tested against loopback stand-ins. The real `/run/egress/door.sock` path is proved by the dev02 script.
- The symlink case of the audit file read (the open uses `O_NOFOLLOW`) is skipped where Windows cannot make a symlink.

## Johan dev02 checklist

Run this once the release is signed and Core is updated on dev02. Send the whole output either way.

a. Update dev02 to Core 1.18.24 from the dev branch. Run `cd /opt/tec-tac-src/framework && cat VERSION`.
   PASS: it prints `1.18.24`.
   FAIL: it prints anything else. Send the output and stop.

b. Run the full canary: `cd /opt/tec-tac-src/framework && cat VERSION && sudo bash tests/sandbox-canary-1.18.24.sh 2>&1 | tee ~/sandbox-canary-1.18.24-$(date +%Y%m%d-%H%M).log`
   PASS: the last lines are `ALL CANARY STEPS PASSED`, then the Patch B exit list. Step 5t says PASS. Step 2 shows `network_private` and `egress_proxy` as `yes`, and prints the selftest time in ms.
   FAIL: any `FAIL` line, `n STEP(S) FAILED`, an `ATTACK SUCCEEDED` row or a `NOT RUN` row. Send the whole log. Do not switch anything on.

c. Network rows only (about 1 to 2 minutes): `cd /opt/tec-tac-src/framework && sudo bash tests/sandbox-canary-1.18.24.sh network`
   PASS: step 5t, 5u and 5v pass. All 12 former ATTACK rows are OK, all 7 proxy rows are OK (`pb-proxy-allowed-443` answered 200), 0 NOT RUN, 0 ATTACK SUCCEEDED. The only SKIPPED row is `pb-tcp-443-ipv6`, if dev02 has no IPv6 route.
   FAIL: any row outside that list. Send the table. A `pb-listener-from-host` row that says ATTACK SUCCEEDED is a real hole.

d. Check that nothing of the door is left: `systemctl list-units 'tec-tac-sandbox-egress@*' --all --no-legend; ls -A /run/tec-tac/sandbox/egress-door /run/tec-tac/sandbox/egress-config /run/tec-tac-sbx-egress`
   PASS: no unit is listed and the folders are empty or absent.
   FAIL: anything is listed. Send it.

e. Check the kill switch and the web page: `sudo /usr/local/sbin/tec-tac-sandbox --status`, then open the Tactical web page and check that an agent still checks in.
   PASS: `enabled` is `false`, the page loads and the agent checks in.
   FAIL: otherwise. Send the output.

If the proxy part fails on dev02 because of how systemd treats the socket folder bind, the credential, or `IPAddressAllow` over the deny list, the wall stays closed and the next patch fixes it. Nothing is widened to make it pass.

## Assumptions

- A run with no `allowed_hosts` still gets `PrivateNetwork=yes` but no proxy, no forwarder and no proxy variable, so it has no network at all.
- Exactly the signed format of `allowed_hosts`: exact lower-case names, port 443 only, no wildcard, no IP literal, no single label, none ending `.local`, `.internal`, `.localhost` or `.lan`, at most 16. Anything wider waits for Johan.
- The listener row is decided from the host's own `ss -ltnH` (a port-number match in the host namespace). A host service that happens to listen on the same port number as the run's ephemeral port would read as a finding and show up in the detail line. It never reads as OK by mistake.
- The proxy's second wall keeps the old numeric deny list and allows only `127.0.0.53/32`. A host with another private resolver fails closed in the selftest with a plain reason.
- The in-unit forwarder stops reading from one side when the other side has 256 KiB queued. It closes either side when the other closes.
- `RefuseManualStart=yes` is set on the proxy service. It starts only through its socket.

## What is not in this release

- Patch C items: kill leftovers before reading the credential, the returned-credential contract text, the selftest and canary split into a root-only file, the `-I` shebang, registration type checks, the drop pattern, denying `io_uring` and `userfaultfd`.
- The install-speed profiling request. It starts after Patch C passes the dev02 canary. This release only records the selftest time.
- Probe transport C1 and C2, and every other open request in `reviews/requests/core.md`.
- Switching the sandbox on. `SANDBOX_ENABLED` stays `False` and the kill switch is unchanged.
- The proxy-less fallback (deny whole subnets). The signed choice is the proxy.
- A fresh public contract file in `docs/contracts` (it is generated on a running server).

## For the release manager

After signing, annotate the "core.sandbox: consolidated fix plan, three patches" entry in `reviews/requests/core.md`: Patch B is Core 1.18.24 and its exit script is `tests/sandbox-canary-1.18.24.sh` (the plan's label 1.18.9 is obsolete). Keep the entry open for Patch C. Remove the three held findings under "From core core-1.18.23 review" in `reviews/core/BACKLOG-new-findings.md`, naming Core 1.18.24.
