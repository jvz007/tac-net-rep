from pathlib import Path

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Compare an exported public contract file with what this Core publishes now (1.17.66). Run it right after the export. "
        "It fails on any difference: the core.system_actions metadata, a contract row, the stale wording, or any other line."
    )

    def add_arguments(self, parser):
        parser.add_argument("file", help="the exported tec-tac-public-contract Markdown file")

    def handle(self, *args, **options):
        from tec_tac import contract_export_check as check
        from tec_tac.contracts import CORE_CONTRACTS, build_contract_catalog, framework_version, render_markdown
        from tec_tac.system_actions import system_actions_contract_metadata

        path = Path(options["file"])
        try:
            exported = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise CommandError(f"Cannot read {path}: {exc}") from exc
        problems = check.check_export_text(
            exported, rows=CORE_CONTRACTS, metadata=system_actions_contract_metadata(), version=framework_version(),
        )
        problems += check.diff_against_live(exported, render_markdown(build_contract_catalog()))
        if problems:
            for line in problems:
                self.stderr.write(f"FAIL: {line}")
            raise CommandError(f"The export {path.name} differs from the contract this Core publishes ({len(problems)} difference(s)). Export again.")
        self.stdout.write(f"PASS: {path.name} matches the contract of Core {framework_version()}.")
