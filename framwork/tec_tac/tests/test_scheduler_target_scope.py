from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from tec_tac import scheduler_views


class _FakeSchedule:
    class OwnerType:
        USER = "user"

    saved_targets = None

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def save(self):
        type(self).saved_targets = self.targets


class SchedulerTargetShapeApiTests(SimpleTestCase):
    def _request(self, targets):
        return SimpleNamespace(
            user=SimpleNamespace(id=7, username="operator"),
            data={
                "name": "scope-test",
                "action_id": "communicator.message",
                "schedule_type": "once",
                "run_at": "2026-09-26T08:00:00Z",
                "targets": targets,
            },
        )

    def _post(self, targets):
        action = SimpleNamespace(id="communicator.message", module_id="communicator", target_types=("endpoints", "dynamic"))
        with (
            patch.object(scheduler_views, "validate_schedule_payload", side_effect=lambda data: dict(data)),
            patch.object(scheduler_views, "_require_action", return_value=action),
            patch.object(scheduler_views, "_validate_shape", return_value=None),
            patch.object(scheduler_views, "_require_target_scope", return_value=None),
            patch.object(scheduler_views, "TecTacSchedule", _FakeSchedule),
            patch.object(scheduler_views, "serialize_schedule", side_effect=lambda schedule, include_runs=False: {"targets": schedule.targets}),
        ):
            return scheduler_views.SchedulerListView().post(self._request(targets))

    def test_rejects_hidden_agents_alias(self):
        response = self._post({"type": "endpoints", "ids": ["own-agent"], "agents": ["foreign-agent"]})
        self.assertEqual(response.status_code, 400)

    def test_rejects_scope_identity_in_dynamic_filter(self):
        response = self._post({
            "type": "dynamic",
            "scope": {"type": "client", "ids": [1]},
            "filter": {"site_id": 99},
        })
        self.assertEqual(response.status_code, 400)

    def test_saved_native_targets_are_canonical(self):
        response = self._post({"type": "endpoints", "ids": ["agent-a", "agent-a", 42]})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["targets"], {"type": "endpoints", "ids": ["agent-a", "42"]})
        self.assertEqual(set(response.data["targets"]), {"type", "ids"})

class SchedulerLegacyTargetRegressionTests(SimpleTestCase):
    def test_manager_bypasses_legacy_target_shape_before_normalization(self):
        manager = SimpleNamespace(id=1, username="admin", is_superuser=True)
        legacy = {"type": "dynamic", "filter": {"os": "windows"}}
        with patch.object(scheduler_views, "_role_for_user", return_value=None):
            # Must not raise SchedulerError/PermissionDenied for an administrator.
            scheduler_views._require_target_scope(manager, legacy, payload=False)
            self.assertTrue(scheduler_views._can_access_target_scope(manager, legacy))

    def test_non_manager_legacy_shape_is_denied_not_scheduler_error(self):
        operator = SimpleNamespace(id=7, username="operator", is_superuser=False)
        malformed = [
            {"type": "dynamic", "filter": {"os": "windows"}},
            {"type": "endpoints", "agent_ids": ["x"]},
        ]
        with patch.object(scheduler_views, "_role_for_user", return_value=None):
            for targets in malformed:
                with self.assertRaises(scheduler_views.PermissionDenied):
                    scheduler_views._require_target_scope(operator, targets, payload=False)
                self.assertFalse(scheduler_views._can_access_target_scope(operator, targets))

    def test_payload_shape_errors_remain_400_style_scheduler_errors(self):
        operator = SimpleNamespace(id=7, username="operator", is_superuser=False)
        with patch.object(scheduler_views, "_role_for_user", return_value=None):
            with self.assertRaises(scheduler_views.SchedulerError):
                scheduler_views._require_target_scope(
                    operator,
                    {"type": "endpoints", "agent_ids": ["x"]},
                    payload=True,
                )

    def test_reconcile_path_normalizes_before_persistence(self):
        source = (scheduler_views.__file__.replace("scheduler_views.py", "scheduler.py"))
        text = open(source, encoding="utf-8").read()
        reconcile = text[text.index("def reconcile_schedule"):text.index("def disable_owned_schedule")]
        self.assertIn('data["targets"] = normalize_scheduler_targets(data.get("targets"))', reconcile)
        self.assertIn('raise SchedulerError(str(exc)) from exc', reconcile)
