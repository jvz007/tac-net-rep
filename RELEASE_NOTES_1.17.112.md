# Tec-Tac Framework 1.17.112

Date: 10 November 2026. A server-maintenance job can now be told "continue" while it runs, and a job that waits for a person no longer blocks every other maintenance job. Nothing changes for an action that uses neither.

Closes: `reviews/requests/core.md`, "From certificatemanagement 0.4.1 (10 November 2026)": "core.server_maintenance: a per-job input channel" and "an action that waits for a person must not hold the global lock". Also the held Low of the Core 1.17.111 review (contract text spacing).

## What changed and why

1. **A running job can receive a signal.**
   * Why: Certificate Management 0.4.1 renews a certificate with a manual DNS challenge. The job shows the TXT record and waits. The person cannot tell it "Record added, continue" for a resolver the module cannot see, because Core starts a job with stdin closed.
   * Now: `core.server_maintenance` goes 1.1.0 to **1.2.0** and gains `send_signal(*, job_id, name, context, user=None)`. The names are fixed: `continue` and `abort`. An action lists the names it accepts in a new optional manifest key `signals` (at most 2 different names). A name the action does not list can never be sent.
   * The permission is checked as `cancel` checks it (a refusal writes the usual `deny` row). The job must be `running` (`job_not_running`). The name must be one the action lists (`signal_not_accepted`; a job that started before this release accepts nothing).
   * Core writes a request file and the root helper delivers it with `--signal <job-id>`. The helper reads the accepted names from the **root registry**, never from the job file Tactical can write. It creates one root-only file per name with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, at most 512 bytes. A second send of the same name does nothing and never overwrites. A symlink or a FIFO at the request path is removed without being opened.
   * The action program finds the folder in `TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR` (and its job id in `TEC_TAC_SERVER_MAINTENANCE_JOB_ID`) and polls it for a file named after the signal. Core never reads a signal. `abort` is only a name the program may act on: Cancel stays the way to stop a job.
   * One Core audit row per send (module `core`, action `run`, object type `server_maintenance_job`, metadata `job_id`, `action`, `name`, `owner_module`; never the parameters).
   * Code: `server_maintenance.py` (`send_signal`, `_action_signals`, `_signal_root`), `scripts/server-maintenance-helper.py` (`signal_job`, `--signal`), `registry.py`, `install.sh`.
2. **An action that waits for a person does not hold the global lock.**
   * Why: a manual renewal waits up to 120 minutes for a DNS record. While it held the one global lock, updates, backups and health jobs queued behind it.
   * Now: a manifest action may set `waits_for_person: true` (default false). Core does not queue that job for the lock. It is `running` at once with lock state `program_managed`. The child gets `TEC_TAC_SERVER_MAINTENANCE_LOCK`, the path of the lock file, and **the action program must take `flock` on it itself** for the part that changes the server. The lock state ends `released` as before. Cancel, timeout and the finished states are unchanged.
   * Why the program and not Core: Certbot's manual hook waits inside its single run, so the wait cannot be split off as a separate Core-run stage without rewriting the module. A stricter two-stage design needs the module restructured; recorded in `reviews/questions/core.md`.
   * **Limits.** Only a signed module's manifest can set it: `--register` (an administrator's hand registration) refuses the key, and the helper honours it only for a registry file that `--register-module` wrote. `timeout_seconds` must be at most 14400 (4 hours); `registry.py` and the helper both refuse more. The executable is the root-installed, SHA-256-checked copy, as for every module action.
   * **What Core cannot do.** It cannot make sure the program really takes the lock. A job that waits and never takes it is the program's fault and shows in the job log. This is stated in `docs/server-maintenance-capability.md`.
3. **Held Low fixed: contract text spacing.** Three purpose texts (`describe_delegation`, `register_delegation_grant`, `start_delegated_run`) ran a full stop into "Since 1.17.111". Each now has the space. Text only.

## Module-facing changes: core.server_maintenance 1.2.0

* The capability is **1.2.0**, additive, still major 1. A module that asks for `>=1,<2` or `>=1.1,<2` keeps working. A module that wants `send_signal` asks for `>=1.2,<2` and `requires.framework` `>=1.17.112`.
* New operation `send_signal`. New optional manifest keys on a `server_maintenance_actions` entry: `signals` and `waits_for_person`. Core's `registry.py` refused unknown entry keys before, so a module that uses either key needs `requires.framework` `>=1.17.112`.
* Job rows gain `signals` (`[{name, sent_at}]`), `accepts_signals` and `waits_for_person`. `list_actions` rows gain `signals` and `waits_for_person`. Every earlier key stays. Metadata gains `signal_names`, `waits_for_person_actions` and `action_manifest_keys_added_in_1_2_0`.
* New environment variables for an action program: `TEC_TAC_SERVER_MAINTENANCE_JOB_ID` and `TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR` (only for an action that lists signals), and `TEC_TAC_SERVER_MAINTENANCE_LOCK` (only for a `waits_for_person` action). Nothing else in the child's environment changes.
* New lock state `program_managed` on a job that waits for a person.
* A grep of `modules/` found three users of `core.server_maintenance`: `certificatemanagement`, `securityWAF` and `tacticalupdater`. None reads the `lock` field. `securityWAF` reads only the `waiting_for_lock` status and stage, which an ordinary job still reports unchanged. None changes.
* **Install step.** `install.sh` creates `signal-requests` (2770, root:tactical, like `cancel-requests`) and the sudoers line gains `--signal *`. A server that has not run `install.sh` again refuses `send_signal` with a plain `dispatch_failed` message.
* The module validator under `pipeline/` must learn the keys `signals` and `waits_for_person` before it accepts a manifest that carries them (not Core's to change; recorded in `reviews/requests/_unsorted.md`).

## Assumptions (also in reviews/questions/core.md)

* The program-taken lock (option a) rather than a Core-run two-stage lock (option b).
* A minor capability bump, because a module must be able to detect `send_signal`.
* `send_signal` checks the permission before it reveals the job's state or accepted names, so a caller without the permission cannot probe a job (denied means hidden). Only after that does it answer `job_not_running` or `signal_not_accepted`.

## What did not run here

Django is not installed on this PC, and neither is a root Linux environment. The new tests run Core's real `server_maintenance.py`, `registry.py` and the root helper against stubs and temporary folders. `flock` is a recording stub here, and symlink and FIFO cases are skipped on Windows. The real root, sudo, systemd and flock behaviour is in `tests/server-maintenance-signals-runtime-1.17.112.sh` and `tests/server-maintenance-waits-runtime-1.17.112.sh`, which the dev server runs as root.

## Tests

* New: `tests/server-maintenance-signals-1.17.112.py`, `tests/server-maintenance-waits-for-person-1.17.112.py`, `tests/contract-text-spacing-1.17.112.py`, and the dev-server scripts `tests/server-maintenance-signals-runtime-1.17.112.sh` and `tests/server-maintenance-waits-runtime-1.17.112.sh`.
* Three pins that required `core.server_maintenance` to be exactly 1.1.0 now accept 1.1.0 or higher in major 1: `tests/job-log-routes-1.17.67.py`, `tests/scheduler-compat-1.17.67.py`, `tests/server-maintenance-permission-1.17.17.py`.
