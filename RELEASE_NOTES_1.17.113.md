# Tec-Tac Framework 1.17.113

Date: 10 November 2026. A module that needs a newer Core now says so, and a module's root program can receive one of the module's own secrets without the value passing through the job, argv, the environment or the logs. Nothing changes for a module that uses neither.

Closes: `reviews/requests/core.md`, "From Johan's install of certificatemanagement 0.4.2, 10 November 2026" (`requires.framework` first) and the first entry of "From certificatemanagement 0.4.3 plan, 10 November 2026" (a secret for a server-maintenance action). The third entry of that block (next run of a schedule) stays open.

## What changed and why

1. **An unmet `requires.framework` is refused first, with the Core version the module needs.**
   * Why: installing certificatemanagement 0.4.2 on a Core older than 1.17.112 said "Manifest server_maintenance_actions entry 3 contains unsupported keys". The refusal was right, but it hid the real reason: the server needs a newer Core.
   * Now: when a package is inspected for install or upgrade, Core reads `requires.framework` from the staged manifest before any other manifest check. If it is not met, the refusal reads "This module needs Tec-Tac Core 1.17.112 or later; this server runs 1.17.111." A constraint that fails for another reason (for example the `<` bound) reads "needs Tec-Tac Core >=1.17.112,<2.0.0; this server runs 2.1.0."
   * It covers the v1 upload, the v2 package preview and the stored-package path, because all of them call `module_manager.inspect_archive`. It raises `ModuleManagerError`, like the other refusals, so every caller and UI path shows it as before.
   * It does not run at start-up. `registry._load_manifest` and `discover_plugins` are unchanged, so a module that is already installed is not stopped by a Core downgrade, and nothing new can stop discovery for every module.
   * If there is no `requires.framework`, the constraint is malformed or the running version cannot be read, the early check steps aside and today's later checks decide. They already fail closed.
   * **Honest limit:** the clearer message exists only on a Core that carries this release. A server still on 1.17.111 shows the old text until it is updated.
   * Code: `registry.framework_requirement_problem`, `module_manager._refuse_unmet_framework` (called from `inspect_archive`). Docs: one paragraph in `docs/module-updates.md`.
2. **Secret inputs for a server-maintenance action (`core.server_maintenance` 1.3.0).**
   * Why: certificatemanagement 0.5.0 (renewal through DNS providers) and 0.6.0 (certificates from Cert Warden and CertMate) need a provider credential or an API key in a root program. Core has `core.secrets`, but there was no safe path from it to a root program.
   * Now: a `server_maintenance_actions` entry may list `secret_inputs`: at most 8 entries, each `{name, required}` (`required` defaults to true; a plain name is accepted), names in the `core.secrets` pattern `[a-z0-9][a-z0-9._-]{0,63}`, no repeats, extensions only, and `requires.framework` of `>=1.17.113`. There is no owner field. The owner is always the module that owns the action, so a module can never name another module's secret.
   * **The flow.**
     1. `start()` reads each named secret inside the Core process, before any job file exists. A required secret that is not configured refuses the start (`secret_not_configured`). One that cannot be read refuses it (`secret_unreadable`). Nothing is created and no value is named.
     2. Core writes one strict audit row per start that hands secrets over (module `core`, action `run`, object type `server_maintenance_job`; metadata `job_id`, `action`, `owner_module`, `secret_names`; never a value) before it dispatches. A hand-over that cannot be audited is not made (`audit_failed`).
     3. The job file records only the names. The job record, the public job, `list_actions` rows and the logs never carry a value.
     4. The values reach the root helper on the **stdin** of the existing `sudo -n helper --dispatch <job-id>` call, as JSON `{name: base64}`. Never in argv, never in the environment, never in a file Tactical can read. The sudoers line does not change.
     5. The helper reads stdin only when the **root registry** says the action has `secret_inputs` (the job file cannot ask for it). Names that are not registered are dropped. A required name that is absent fails the job with `secret_missing`.
     6. The helper writes each value to `/run/tec-tac/server-maintenance/secrets/<job id>/<name>` (folder 0700 root, files 0400 root, created with `O_CREAT|O_EXCL|O_NOFOLLOW`). `/run` is memory only and is cleared at boot.
     7. The program is started later, in its own systemd unit. It gets one new environment variable, `TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR`, the path of that folder (a path, not a value; set only for an action that lists `secret_inputs`). Nothing else in the environment changes.
     8. The folder is removed when the job ends for any reason: success, failure, timeout, cancel, cancelled before execution, worker error and dispatch failure. Every helper start also sweeps the folder of any job that is finished or unknown, so a helper crash leaves none for long.
     9. After the program exits, the helper replaces the exact secret values in the job's stdout, stderr and lifecycle logs with `***`.
   * **Core side.** `secret_store` has no owner-taking function, and AD-57 lets only the owner module read. One new private function, `secret_store._read_for_server_maintenance`, decrypts a secret for `server_maintenance` only. It is not exported, not in the contract and not in `secrets_contract_metadata`. It refuses (403 `caller_not_allowed`, one `deny` audit row) unless its immediate caller is `_resolve_secret_inputs` in `server_maintenance.py`, the action is registered by a signed module manifest in the root registry, the owner is the module the action id names and is an enabled, non-legacy extension, and the name is in the action's `secret_inputs`. It counts the read like `get`. The plaintext lives in a small wrapper whose `repr` and `str` are `<redacted>`, which cannot be pickled, and which is never returned from a provider method or put into an exception message. A dispatch error that echoes a value is scrubbed before it is stored.
   * **A hand registration cannot use it.** `--register` refuses the key. A registry file that lists `secret_inputs` but was not written by `--register-module` is run without secrets and fails `secret_missing`.
   * **Not covered. Flagged for human review.** This is a new reason for Core to read a module's secret (AD-57 names only the owner module). It is built fail closed as above, and the question is in `reviews/questions/core.md`. Plainly:
     * The Core worker holds the plaintext in memory for the moment of the call. Python cannot wipe it.
     * The root program is trusted, signed code. It could still leak the value if it prints it. The log scrub limits the damage in the logs only, and it runs after the program exits, so a value that a program echoes is readable in the job logs while the program is still running.
     * The caller check is code-path evidence, like the module caller check, not a sandbox.
   * Code: `server_maintenance.py`, `secret_store.py`, `registry.py`, `contracts.py`, `scripts/server-maintenance-helper.py`, `install.sh` (the capability check now also verifies the provider carries `secret_inputs`). Docs: new "Secret inputs" section in `docs/server-maintenance-capability.md`, a pointer in `docs/secret-store.md`.

## Module-facing changes: core.server_maintenance 1.3.0

* The capability is **1.3.0**, additive, still major 1. A module that asks for `>=1,<2`, `>=1.1,<2` or `>=1.2,<2` keeps working. A module that wants `secret_inputs` asks for `>=1.3,<2` and `requires.framework` `>=1.17.113`.
* New optional manifest key on a `server_maintenance_actions` entry: `secret_inputs`. Core's `registry.py` refuses unknown entry keys on an older Core, so a module that uses it needs `requires.framework` `>=1.17.113` (and the registry refuses it with a lower floor).
* Job rows and `list_actions` rows gain `secret_inputs` (job rows: names only; action rows: `[{name, required}]`). Every earlier key stays. Metadata gains `action_manifest_keys_added_in_1_3_0`, `secret_input_limits`, `secret_inputs_env` and `requires_framework_added_in_1_3_0`.
* New environment variable for an action program: `TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR` (only for an action that lists `secret_inputs`).
* New start refusals: `secret_not_configured`, `secret_unreadable`, `secret_not_allowed`. New job failure classification: `secret_missing`.
* A grep of `modules/` found three users of `core.server_maintenance`: `certificatemanagement`, `securityWAF` and `tacticalupdater`. None reads anything that changes, and the new key is optional, so a 1.2.0 manifest and a plain `start()` behave exactly as before. Modules that use `core.secrets` (licensing, softwarerepository, ai) are unaffected: `put`, `get`, `delete`, `configured` and `list_names` keep their behaviour.
* The module validator under `pipeline/` must learn `secret_inputs` (and still needs `signals` and `waits_for_person` from 1.17.112). It is not Core's to change; recorded in `reviews/requests/_unsorted.md`.
* certificatemanagement 0.5.0 and 0.6.0 adopt it after this release is signed and its contract exported; until then both ship disabled (`reviews/requests/certificatemanagement.md`).
* **Install step.** None beyond installing Core. The helper creates `/run/tec-tac/server-maintenance/secrets` itself when a job first needs it.

## Tests

* `tests/module-install-framework-first-1.17.113.py`: the order proven both ways, the messages, the fall-through cases, a protected id and start-up discovery unchanged.
* `tests/server-maintenance-secret-inputs-1.17.113.py`: registry and helper agreement, `start()` with and without secrets, the value found nowhere durable, every refusal, the private read's caller rules, helper dispatch, run, cleanup after every ending, the scrub and the sweep.
* `tests/server-maintenance-secrets-runtime-1.17.113.sh`: dev server only, as root (a real `--dispatch` with stdin, tmpfs, `ps`, `/proc/<pid>/environ`, the journal).
* Pins updated to accept `core.server_maintenance` 1.2.0 or higher in major 1: `tests/server-maintenance-signals-1.17.112.py`, `tests/contract-text-spacing-1.17.112.py` (the version text). The `core.secrets` pins in `tests/secret-store-1.17.100.py` and `tests/secret-store-hardening-1.17.101.py` now name the one private read (`_read_for_server_maintenance`) as the only addition; `job-log-routes-1.17.67.py`, `scheduler-compat-1.17.67.py` and `server-maintenance-permission-1.17.17.py` already accepted 1.1.0 or higher and pass unchanged.

## Not run here

Django and a root Linux are not on this PC. The stub tests ran. The runtime script runs on the dev server only. Not covered on this PC: the helper as root through sudo and systemd, real tmpfs, root ownership and modes, symlink and FIFO cases (skipped on Windows). `tests/contract-catalog-1.17.61.py`, `tests/secret-store-1.17.100.py` (the online catalogue part) and `tests/secret-store-hardening-1.17.101.py` (its version pin) already fail before this release on this PC; see the report.

## Assumptions (also in reviews/questions/core.md)

* Option (a) for the secret hand-over (owner's own action and names only, tmpfs file, log scrub, strict audit row per hand-over), fail closed. Johan's call, flagged for human review.
* A minor capability bump, with limits of 8 names, 16 KiB per value and 64 KiB in all.
* The early `requires.framework` check runs only at install and upgrade inspection, not at start-up.
* The held Low of 1.17.112 (`waits_for_person` leaves no evidence that the program took the lock) stays held; it waits on Johan's answer to Question 1 of Core 1.17.112.

## Fixed after precheck (10 November 2026, version unchanged)

1. **Secret inputs are switched off (fail closed).** Core reading an owner's secret for that owner's own action is a new trusted purpose that no signed decision covers (AD-57 says only the owner reads). `server_maintenance.SECRET_INPUTS_ENABLED` is `False`: `start()` of an action that lists `secret_inputs` refuses with `secret_inputs_disabled`, reads nothing, writes no job and no hand-over row. The manifest key, the registry check, the helper and the contract text stay, so the feature comes on with one constant once Johan signs it. The provider metadata shows `secret_inputs_enabled: false`. Module-facing: certificatemanagement's secret-input actions cannot start until then. Question 1 in `reviews/questions/core.md` stays open.
2. **A forged call can no longer read another module's secret.** `_resolve_secret_inputs` now takes only an action id, re-reads the root-registry action itself and refuses (`secret_not_allowed`) unless its caller is `ServerMaintenanceProvider.start` (code-object identity). `_SecretHandOver` no longer has a readable `_values` attribute; the bytes live in closures. Regression: new section at the end of `tests/server-maintenance-secret-inputs-1.17.113.py` (forged module-path call with another module's action id, look-alike `start`, disabled start).

## Fixed after review (10 November 2026, version 1.17.113)

1. **The private secret read is no longer reachable with a forged frame, and it obeys the OFF switch.** `secret_store._read_for_server_maintenance` used to trust the caller's file name, function name and module name, which a module can imitate with `compile()`. It now refuses (`caller_not_allowed`, one deny row) unless `server_maintenance.SECRET_INPUTS_ENABLED` is on, and then only when the caller's code object is `server_maintenance._resolve_secret_inputs.__code__`. The registry and owner checks stay. With the switch off (as shipped) nothing can reach the read. Regression: `tests/server-maintenance-secret-inputs-1.17.113.py` now runs the forged shape (real file path, real name, real `__name__`) with the switch off and on, for its own and another module's action id, and expects `caller_not_allowed`. The accepted-caller checks use the real function's code object and need the switch on. No module-facing change.
