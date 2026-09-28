# Fixing — Core 1.15.158

Recovery-key import no longer follows the final import path or reads an unbounded source as root. Imported trust-key publication also fsyncs the trust directory.

Regression: `tests/recovery-key-import-1.15.158.py`.
