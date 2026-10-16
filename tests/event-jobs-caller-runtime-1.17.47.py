"""Runtime probe for Core 1.17.47: what the caller check on every ``core.event_jobs`` publish really costs, and one real publish.
It did NOT run on the development PC (Django, PostgreSQL and the real module folders are not available there).

Run it on the dev server through Tactical's manage.py shell, after Core 1.17.47 is installed:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/event-jobs-caller-runtime-1.17.47.py

It prints, in microseconds: the real ``registry.discover_plugins()`` (a scan of every module folder), the real
``module_state.load_state()``, one cold and one warm call of the caller check, and a publish with the check on a warm snapshot. It then proves
two things on the real system: a publish from a frame that lies in the owning module's own folder is queued and stores a real row, and a
publish from this shell (outside every module) is refused with ``error`` and stores nothing.

The owner frame is a function compiled under the module's real folder (the technique of the stub test), so this probe is not hostile code
in the product: it forges a file name on purpose, once, in a throw-away shell. The probe job is registered in this shell only, under the id
of an installed, enabled extension (the owner check of ``register_event_job`` is skipped because this script does not lie inside a
module's folder). Its handler never runs. Every row it stores has a key that starts with ``probe-`` and is deleted at the end. It prints
PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import time

from tec_tac import caller_identity as ci
from tec_tac import event_jobs as ej
from tec_tac import module_state, registry
from tec_tac.models import TecTacEventJob, TecTacEventJobStat

RESULTS = []


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def micro(fn, loops):
    start = time.perf_counter()
    for _ in range(loops):
        fn()
    return (time.perf_counter() - start) / loops * 1e6


PLUGINS = tuple(registry.discover_plugins())
OWNER = next((p for p in PLUGINS if p.plugin_type == "extension" and not p.legacy and module_state.is_enabled(p.plugin_id)), None)
if OWNER is None:
    print("SKIP: no installed, enabled extension module to publish for")
    sys.exit(0)
JOB = f"{OWNER.plugin_id}.probe-caller-job"
print(f"probe module: {OWNER.plugin_id}; installed plugins: {len(PLUGINS)}")

ej._verify_owner = lambda module_id, handler: None  # this script is not inside the module's folder (see the header)
ej._clear_for_tests()
handle = ej.register_event_job(id=JOB, module_id=OWNER.plugin_id, label="Probe", handler=lambda context: None)

# a function whose code file lies inside the owner's own folder: the real helper sees the owner's code as the caller
ns = {}
exec(compile("def fire(handle, key):\n    return handle.publish(key)\n", str(OWNER.root / "_tectac_probe.py"), "exec"), ns)  # noqa: S102
fire = ns["fire"]


def cleanup():
    TecTacEventJob.objects.filter(job_id=JOB).delete()
    TecTacEventJobStat.objects.filter(job_id=JOB).delete()


def costs():
    print(f"  discover_plugins()          {micro(lambda: registry.discover_plugins(), 50):10.1f} us")
    print(f"  load_state()                {micro(lambda: module_state.load_state(), 200):10.1f} us")

    def cold():
        ci.clear_snapshot_for_tests()
        return fire_helper()

    def fire_helper():
        return ci.calling_module_for_core_provider(provider_file=ej.__file__, cache_seconds=5)

    print(f"  caller check, cold          {micro(cold, 50):10.1f} us  (a frame of this shell is the caller, so it answers None; the read cost is what counts)")
    fire_helper()
    print(f"  caller check, warm          {micro(fire_helper, 2000):10.1f} us")
    ej._RATE.limit = 10**9
    counter = [0]

    def publish():
        counter[0] += 1
        return fire(handle, f"probe-cost-{counter[0]}")

    publish()
    ej._GAUGES.set(JOB, 0)  # the gauge is open
    original_persist, original_check = ej._persist_safely, ej._verified_caller_ok
    ej._persist_safely = lambda definition, key, payload: "queued"  # time the gate only, not the INSERT and the broker
    try:
        print(f"  publish with the check, warm {micro(publish, 2000):9.1f} us  (gate only: the INSERT and the broker publish are not timed)")
        ej._verified_caller_ok = lambda definition: True
        print(f"  publish without the check    {micro(publish, 2000):9.1f} us")
    finally:
        ej._persist_safely, ej._verified_caller_ok = original_persist, original_check
        ej._RECENT._seen.clear()
        ej._RATE._windows.clear()


step("cost of the real reads (printed, no limit asserted)", costs)

def owner_publish():
    cleanup()
    result = fire(handle, "probe-owner-1")
    check(result.outcome == "queued", result)
    check(TecTacEventJob.objects.filter(job_id=JOB, key="probe-owner-1").count() == 1, "the row is stored")


def shell_publish():
    before = TecTacEventJob.objects.filter(job_id=JOB).count()
    result = handle.publish("probe-shell-1")  # this shell is outside every module
    check(result.outcome == "error" and result.reason == "the caller is not the module that owns this job", result)
    check(TecTacEventJob.objects.filter(job_id=JOB).count() == before, "nothing is stored")
    check(not TecTacEventJob.objects.filter(job_id=JOB, key="probe-shell-1").exists(), "no probe-shell row")


step("a publish from the owning module's own frame is queued and stores a row", owner_publish)
step("a publish from this shell is refused and stores nothing", shell_publish)
cleanup()
print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
sys.exit(0 if all(RESULTS) else 1)
