# Tec-Tac Scheduler

Framework 1.8.0 adds a framework-owned scheduling service for modules.

## Contract

Modules define **what** can run; Tec-Tac owns **when** it runs.

Register an action from a module `AppConfig.ready()`:

```python
from tec_tac.scheduler import register_scheduled_action

register_scheduled_action(
    id="communicator.message",
    module_id="communicator",
    label="Send message",
    target_types=("endpoint", "endpoints", "site", "client", "group", "dynamic"),
    permission="communicator.send",
    handler=send_message_handler,
)
```

Handler context contains `schedule_id`, `run_id`, `target_mode`, `targets`, `parameters`, `scheduled_for`, and `manual`.

## Runtime

`tec-tac-scheduler.timer` evaluates due schedules every minute. Due runs are dispatched into Tactical's existing Celery worker through `tec_tac.execute_schedule_run`. No Tactical tracked source files are modified.

## Schedule types

- Once
- Daily
- Weekly
- Monthly

Each schedule stores an IANA timezone. Target definitions can be snapshot or dynamic. Missed-run, concurrency and retry policies are framework-owned.

## API

- `GET /api/tfd/scheduler/actions/`
- `GET|POST /api/tfd/scheduler/schedules/`
- `GET|PATCH|DELETE /api/tfd/scheduler/schedules/<id>/`
- `POST /api/tfd/scheduler/schedules/<id>/run/`
- `GET /api/tfd/scheduler/runs/`
