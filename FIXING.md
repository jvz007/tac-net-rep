# FIXING.md — Core 1.15.115

This build starts the next release line after the reviewed 1.15.114 release.

## System Update installer lifecycle
- A Framework installer that reaches the final successful verification boundary now clears its temporary EXIT trap and returns status 0 explicitly.
- This prevents a completed install from being misreported as `framework installer exited with status 1` and unnecessarily rolled back.

## Detached signed System Update uploads
- Offline System Updates accept one release archive plus `tec-tac-release.json` and `tec-tac-release.json.sig` in the same multipart request.
- The API accepts repeated multipart file fields and classifies the archive/signing sidecars by filename.
- Both signing sidecars are required together; duplicate archives, duplicate signing files, unsupported extras, and archive+detached signing ambiguity fail closed.
- Signing sidecars are independently size-bounded and staged as managed files.
- The root update helper claims the sidecars through the same no-follow/inode snapshot boundary used for update archives.
- Detached sidecars are injected only into the root-private extracted release tree before the existing root signed-tree verification runs.
- Existing embedded signed-tree archives and online GitHub update staging remain supported.

## Regression coverage
- `tests/system-update-detached-upload.py`
- `tests/system-update-claim-security.py`
- `tests/system-update-signed-tree.py`
- `tests/system-update-foundation.sh`
