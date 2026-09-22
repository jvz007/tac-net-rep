from __future__ import annotations

import time
from pathlib import Path

from django.core.files import File
from django.core.management.base import BaseCommand, CommandError

from tec_tac.module_manager import get_job
from tec_tac.module_manager_v2 import (
    ModuleManagerV2Error,
    discard_v2_stage,
    queue_batch_install,
    queue_v2_install,
    stage_multiple_packages,
)


TERMINAL_STATES = {"succeeded", "failed", "dispatch_failed"}
SUPPORTED_SUFFIXES = (".zip", ".tgz", ".tar.gz")


def _is_supported(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SUPPORTED_SUFFIXES)


class Command(BaseCommand):
    help = (
        "Install trusted bootstrap module packages through the normal Module Manager "
        "inspection, dependency planning, privileged lifecycle and audit path."
    )

    def add_arguments(self, parser):
        parser.add_argument("--path", required=True, help="Directory containing bootstrap module package archives.")
        parser.add_argument(
            "--timeout",
            type=int,
            default=1800,
            help="Maximum seconds to wait for the lifecycle job (default: 1800).",
        )
        parser.add_argument(
            "--requested-by",
            default="bootstrap:install.sh",
            help="Audit requester recorded on the module lifecycle job.",
        )

    def handle(self, *args, **options):
        root = Path(options["path"]).expanduser().resolve()
        timeout = max(30, int(options["timeout"] or 1800))
        requested_by = str(options["requested_by"] or "bootstrap:install.sh").strip() or "bootstrap:install.sh"

        if not root.exists():
            self.stdout.write(f"[TEC-TAC] Bootstrap module directory not present; skipping: {root}")
            return
        if not root.is_dir():
            raise CommandError(f"Bootstrap module path is not a directory: {root}")
        if root.is_symlink():
            raise CommandError("Bootstrap module directory must not be a symbolic link.")

        packages = []
        for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
            if path.name.startswith(".") or path.name.lower() in {"readme", "readme.md", "readme.txt"}:
                continue
            if path.is_symlink():
                raise CommandError(f"Bootstrap module package must not be a symbolic link: {path.name}")
            if path.is_dir():
                raise CommandError(f"Nested bootstrap module directories are not supported: {path.name}")
            if not path.is_file():
                raise CommandError(f"Unsupported bootstrap module entry: {path.name}")
            if not _is_supported(path):
                raise CommandError(
                    f"Unsupported bootstrap module file {path.name!r}; expected .zip, .tgz, or .tar.gz."
                )
            packages.append(path)

        if not packages:
            self.stdout.write(f"[TEC-TAC] No bootstrap module packages found in {root}; skipping.")
            return

        self.stdout.write(f"[TEC-TAC] Bootstrap module intake: {len(packages)} package(s) from {root}")
        opened = []
        stage = None
        queued = False
        try:
            uploads = []
            for path in packages:
                handle = path.open("rb")
                opened.append(handle)
                uploads.append(File(handle, name=path.name))
                self.stdout.write(f"[TEC-TAC]   package: {path.name}")

            stage = stage_multiple_packages(uploads)
            kind = str(stage.get("kind") or (stage.get("preview") or {}).get("kind") or "package")
            preview = stage.get("preview") or stage
            plan = stage.get("plan") or preview.get("plan") or {}
            if plan.get("valid") is False:
                problems = plan.get("problems") or []
                raise CommandError(f"Bootstrap module dependency plan is not installable: {problems}")

            actions = plan.get("actions") or []
            if actions:
                self.stdout.write("[TEC-TAC] Bootstrap module install plan:")
                for action in actions:
                    current = action.get("current_version") or "not installed"
                    target = action.get("version") or "unknown"
                    self.stdout.write(
                        f"[TEC-TAC]   {action.get('id')}: {current} -> {target} ({action.get('action')})"
                    )

            order = list(plan.get("order") or []) or None
            upload_id = str(stage.get("upload_id") or "")
            if not upload_id:
                raise CommandError("Bootstrap module staging did not return an upload id.")

            if kind == "batch":
                job = queue_batch_install(upload_id, requested_order=order, requested_by=requested_by)
            else:
                job = queue_v2_install(upload_id, requested_order=order, requested_by=requested_by)
            queued = True
            job_id = str(job.get("id") or "")
            if not job_id:
                raise CommandError("Bootstrap module lifecycle did not return a job id.")

            self.stdout.write(f"[TEC-TAC] Bootstrap module lifecycle job: {job_id}")
            deadline = time.monotonic() + timeout
            last_marker = None
            while time.monotonic() < deadline:
                current = get_job(job_id)
                marker = (current.get("status"), current.get("stage"))
                if marker != last_marker:
                    self.stdout.write(
                        f"[TEC-TAC] Bootstrap modules: status={marker[0] or 'unknown'} stage={marker[1] or 'unknown'}"
                    )
                    last_marker = marker
                if current.get("status") in TERMINAL_STATES:
                    if current.get("status") == "succeeded":
                        self.stdout.write(self.style.SUCCESS("[TEC-TAC] Bootstrap modules installed successfully."))
                        return
                    tail = [str(line) for line in (current.get("log_tail") or [])[-12:]]
                    detail = str(current.get("error") or "Bootstrap module lifecycle failed.")
                    if tail:
                        detail += "\nFinal lifecycle output:\n" + "\n".join(tail)
                    raise CommandError(detail)
                time.sleep(1.0)

            raise CommandError(
                f"Timed out after {timeout}s waiting for bootstrap module job {job_id}. "
                "The durable lifecycle job may still be running; inspect Module Manager job history before retrying."
            )
        except ModuleManagerV2Error as exc:
            raise CommandError(str(exc)) from exc
        finally:
            for handle in opened:
                try:
                    handle.close()
                except OSError:
                    pass
            if stage is not None and not queued:
                upload_id = str(stage.get("upload_id") or "")
                if upload_id:
                    try:
                        discard_v2_stage(upload_id)
                    except Exception:
                        pass
