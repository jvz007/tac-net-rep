#!/usr/bin/env python3
"""D2/D3 decision-level behavioral closure.

Exercises the real validate-restore operation result shape used by the Backup &
Restore UI, and the real restored-Core version verifier. Peripheral transport
and host-readiness probes are isolated so this remains ordinary-CI portable.
"""
from __future__ import annotations
import hashlib
import importlib.util
import io
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_backup_helper_decision', ROOT / 'scripts' / 'server-backup-helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

with tempfile.TemporaryDirectory() as td_raw:
    td = pathlib.Path(td_raw)
    state = td / 'state'
    staging = state / 'staging'
    staging.mkdir(parents=True)
    framework = td / 'framework'
    runtime = td / 'runtime'
    framework.mkdir(); runtime.mkdir()
    (framework / 'VERSION').write_text('1.15.166\n', encoding='utf-8')

    config = {
        'TEC_TAC_SERVER_BACKUP_ROOT': str(state),
        'TEC_TAC_SERVER_BACKUP_STAGING': str(staging),
        'TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS': str(td),
        'TEC_TAC_FRAMEWORK_SOURCE': str(framework),
        'TEC_TAC_ROOT': str(runtime),
        'TACTICAL_ROOT': str(td / 'rmm'),
    }

    manifest = {
        'format_version': 2,
        'artifact_type': 'tec-tac-recovery-bundle',
        'created_at': '2026-09-29T07:00:00Z',
        'installation_id': 'install-old',
        'server_name': 'old-rmm',
        'components': {'tec_tac': {'included': True, 'framework_version': '1.15.83'}},
        'recovery_modes': ['tec_tac'],
    }

    original_download = h.download_destination
    original_validate_bundle = h.validate_recovery_bundle
    original_validate_component = h.validate_tec_tac_component
    original_preflight = h.validate_target_preflight
    try:
        def fake_download(config_arg, destination, name, downloaded, log):
            downloaded.write_bytes(b'validated recovery bundle bytes')
            return {
                'size_bytes': downloaded.stat().st_size,
                'sha256': hashlib.sha256(downloaded.read_bytes()).hexdigest(),
            }

        component = td / 'component.tar.gz'
        component.write_bytes(b'component')

        def fake_validate_bundle(*_args, **_kwargs):
            return manifest, {'tec_tac': component}

        def fake_validate_component(*_args, **_kwargs):
            return None

        def portable_preflight(config_arg, report, mode, staged_bytes, **_kwargs):
            for cid, label in (
                ('target.mutation_lock', 'Backup/restore mutation'),
                ('target.arch', 'CPU architecture'),
                ('target.os', 'Operating system'),
                ('target.memory', 'System memory'),
                ('target.disk', 'Staging free space'),
                ('target.tools', 'Required executables'),
                ('target.dns', 'Restore dependency DNS'),
                ('target.tactical_present', 'Existing Tactical installation'),
            ):
                status = 'not_applicable' if cid in {'target.arch','target.os','target.memory','target.dns'} else 'passed'
                h._vr_check(report, 'target', cid, label, status, 'portable D2/D3 decision test')

        h.download_destination = fake_download
        h.validate_recovery_bundle = fake_validate_bundle
        h.validate_tec_tac_component = fake_validate_component
        h.validate_target_preflight = portable_preflight

        report = h.operation_validate_restore(
            config,
            {
                'id': '11111111-1111-4111-8111-111111111111',
                'request': {
                    'backup_ref': 'destination:local:tec-tac-backup-decision.tgz',
                    'restore_mode': 'tec_tac',
                    'destination': {'id': 'local', 'type': 'local', 'name': 'local', 'path': str(td)},
                },
                'context': {'requested_by': 'admin'},
            },
            io.StringIO(),
        )
    finally:
        h.download_destination = original_download
        h.validate_recovery_bundle = original_validate_bundle
        h.validate_tec_tac_component = original_validate_component
        h.validate_target_preflight = original_preflight

    assert report['ok'] is True, report
    assert report['source_identity']['installation_id'] == 'install-old'
    assert report['source_identity']['server_name'] == 'old-rmm'
    assert report['source_identity']['created_at'] == '2026-09-29T07:00:00Z'
    assert report['source_identity']['core_version'] == '1.15.83'
    assert report['archive_verification']['status'] == 'not_verified'
    transition = report['version_transition']
    assert transition['current_core_version'] == '1.15.166'
    assert transition['restored_core_version'] == '1.15.83'
    assert transition['is_core_downgrade'] is True
    assert transition['notice'].startswith('This restore puts Core back to 1.15.83.')
    assert any(str(item).startswith('This restore puts Core back to 1.15.83.') for item in report['warnings'])

    # AD-3: registered S3/WebDAV/SFTP destinations share the rclone transport
    # boundary. A registered S3 restore with no adjacent hash companion must
    # stay restorable and report not_verified rather than falling into SCP.
    registered_s3 = h.validate_destination(
        {
            'id': 's3-registered',
            'type': 's3',
            'name': 'registered-s3',
            'provider': 'Other',
            'bucket': 'tectac-test',
            'prefix': 'backups',
            'remote_path': 'backups',
        },
        config,
    )
    original_make_rclone_config = h.make_rclone_config
    original_load_registered_destination = h.load_registered_destination
    original_rclone_path_exists = h.rclone_path_exists
    original_download = h.download_destination
    original_validate_bundle = h.validate_recovery_bundle
    original_validate_component = h.validate_tec_tac_component
    original_preflight = h.validate_target_preflight
    try:
        def fake_make_rclone_config(config_arg, destination, temp, log):
            cfg = pathlib.Path(temp) / 'rclone.conf'
            cfg.write_text('[tectac]\ntype = test\n', encoding='utf-8')
            return cfg

        h.make_rclone_config = fake_make_rclone_config
        h.load_registered_destination = lambda config_arg, destination_id: registered_s3 if destination_id == 's3-registered' else (_ for _ in ()).throw(RuntimeError('unexpected destination id'))
        h.rclone_path_exists = lambda remote, cfg: False
        h.download_destination = fake_download
        h.validate_recovery_bundle = fake_validate_bundle
        h.validate_tec_tac_component = fake_validate_component
        h.validate_target_preflight = portable_preflight
        s3_report = h.operation_validate_registered_restore(
            config,
            {
                'id': '22222222-2222-4222-8222-222222222222',
                'request': {
                    'backup_ref': 'destination:s3-registered:tec-tac-backup-decision.tgz',
                    'restore_mode': 'tec_tac',
                    'destination_id': 's3-registered',
                    'overrides': [],
                },
                'context': {'requested_by': 'admin'},
            },
            io.StringIO(),
        )
    finally:
        h.make_rclone_config = original_make_rclone_config
        h.load_registered_destination = original_load_registered_destination
        h.rclone_path_exists = original_rclone_path_exists
        h.download_destination = original_download
        h.validate_recovery_bundle = original_validate_bundle
        h.validate_tec_tac_component = original_validate_component
        h.validate_target_preflight = original_preflight

    assert s3_report['ok'] is True, s3_report
    assert s3_report['archive_verification']['status'] == 'not_verified', s3_report

    # D2 completion is not merely advisory: after the restored payload is in
    # place, Core must verify that the effective installed version is exactly
    # the older version declared by the backup.
    (runtime / 'VERSION').write_text('1.15.83\n', encoding='utf-8')
    log = io.StringIO()
    effective = h._verify_restored_core_version(config, {'framework_version': '1.15.83'}, log)
    assert effective == '1.15.83'
    assert 'verified restored Core version: 1.15.83' in log.getvalue()

print('[TEST] PASS D2/D3 decision-level restore validation, provenance, hash state and downgrade closure')
