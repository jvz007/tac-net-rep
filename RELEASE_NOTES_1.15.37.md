# Tec-Tac Framework 1.15.37

- Adds publisher-tool v0.2.0 schema-2 signed source-tree verification to System Updates.
- Verifies the exact signed manifest bytes, trusted publisher/key/environment, and every declared file path, byte size and SHA-256 before staging a signed update.
- Re-verifies the extracted staged tree and the exact Git checkout that will execute `install.sh`, preventing verification/execution byte drift.
- Preserves legacy unsigned stable releases below the signed-release cutoff while failing closed for partial or invalid signing material.
- Defaults Framework stable releases from 1.15.37 onward to require signed-tree metadata; the cutoff is configurable with `TEC_TAC_FRAMEWORK_SIGNED_RELEASE_MIN_VERSION`.
- Persists release tag, commit SHA and publisher verification provenance into System Update job/history records.
