# Tec-Tac Framework 1.15.63-3

## Housekeeping privileged-request claim hardening

- Hardened the root-owned housekeeping helper so it no longer executes directly from a Tactical-writable request file.
- Housekeeping requests are now opened with `O_NOFOLLOW`, checked as bounded regular files, copied into a root-only `running/` area, and reparsed from that claimed copy before any scan or purge occurs.
- Request filenames must be canonical UUIDs and match the fixed housekeeping request directory exactly.
- The claimed request is removed after the operation completes or fails.
- Installer now creates `/var/lib/tec-tac/housekeeping/running` as `root:root 0700`.
- Added regression coverage for mutable-request isolation and symlink rejection.


## Rebuild 1 security correction

- Corrected the Housekeeping privileged-helper trust boundary so `running/` and `results/` cannot be redirected through Tactical-swappable symlinks.
- The housekeeping parent is now installed as `root:root 0755`; only the request/result child directories retain Tactical group access, while `running/` remains `root:root 0700`.
- The privileged helper validates trusted directories with `lstat()` and fails closed on symlinks, wrong owner, wrong type, or unsafe modes before any privileged write.
- Removed helper-side path-based `chmod`/`chown` of replaceable directories.
- Result publication now uses a unique `mkstemp()` file, fd-based ownership/mode changes, `fsync()`, and atomic `os.replace()`.
- Added regressions proving swapped `running/` and `results/` symlinks cannot alter sentinel ownership/mode or receive attacker-selected UUID result/request files.


## Rebuild 2 housekeeping configuration correction

- Moved the Tactical-writable housekeeping policy file from `/var/lib/tec-tac/housekeeping/config.json` into the dedicated `/var/lib/tec-tac/housekeeping/config/config.json` child directory.
- Installer creates `config/` as `root:<tactical-group> 2770` while keeping the housekeeping parent `root:root 0755` and `running/` `root:root 0700`.
- Existing legacy `config.json` is migrated during install after the parent has been locked against Tactical directory-entry replacement; unsafe symlink/non-regular legacy entries are discarded rather than followed.
- `save_config()` now writes through a unique temporary file in `config/`, applies mode `0640` to the open fd, fsyncs it, and atomically replaces `config.json`; an existing config symlink is replaced rather than followed.
- Filesystem/config-directory failures are translated to bounded `HousekeepingError` responses instead of escaping as raw server errors.
- Added regression coverage for fresh-install storage beneath a root-owned `0755` housekeeping parent, config symlink replacement, atomic temp cleanup, and bounded failure when the config child is unavailable.


## Rebuild 3: housekeeping upgrade mode normalization

- Clear inherited setuid/setgid bits explicitly when normalizing the root-owned housekeeping parent and private running directory.
- Use `chmod 00755` for the housekeeping parent and `chmod 00700` for `running/`, preventing the legacy 1.15.62 setgid layout from surviving an upgrade.
- Added regression coverage that starts from a `2770` housekeeping parent and verifies the upgraded trust boundary is exactly `0755` / `0700`.
