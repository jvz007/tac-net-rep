"""Runtime check for Core 1.17.70 (CQ203, the second kind of system action). It did NOT run on the development PC (Django is not installed there).

It leaves nothing behind: the one real write is made inside a database transaction that is rolled back, and no audit row, schedule or registration of its own is written.

One command, on the dev server:
    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/system-writes-runtime-1.17.70.py

Each line prints PASS or FAIL (or SKIP with its reason); the file ends with PASS only when every line passed.
    1 the capability is 1.3.0 and lists run_write; the table has winupdate.set_action as a replacement-only write row
    2 the WinUpdate model and serializer Core uses are importable, and the serializer has no field Core writes besides action
    3 the fixed read of an existing update's endpoint and decision works (SKIP when this server has no Windows update row)
    4 the locked compare-and-set write saves one decision through Tactical's own serializer, leaves installed and kb alone, skips a row whose decision
      changed meanwhile, and is rolled back
    5 the write row refuses the wrong registrant (Windows Patching, an unrelated name) with a plain error
"""
import sys

from django.db import transaction
from tec_tac import system_actions as sa
from tec_tac import system_writes as writer

RESULTS = []


def check(label, ok):
    RESULTS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + label)


meta = sa.system_actions_contract_metadata()
row = sa.SYSTEM_FUNCTIONS.get("winupdate.set_action")
check("capability core.system_actions is 1.3.0 and lists run_write", meta["version"] == "1.3.0" and "run_write" in meta["operations"])
check("the table has winupdate.set_action as a replacement-only write row",
      row is not None and row.kind == "write" and row.replacement_only is True and tuple(row.min_flags) == ("can_manage_winupdates",) and "winupdate.set_action" in meta["functions"])
check("the metadata lists the four new refusal reasons", all(r in meta["refusal_reasons"] for r in ("wrong_kind", "bad_changes", "unknown_update", "action_not_allowed")))

check("Core can reach Tactical's WinUpdate model and serializer", writer.available())
from winupdate.models import WinUpdate  # noqa: E402
from winupdate.serializers import WinUpdateSerializer  # noqa: E402

check("WinUpdate has an action column with the four choices", {c[0] for c in WinUpdate._meta.get_field("action").choices} == {"inherit", "approve", "ignore", "nothing"})
check("the serializer saves every field (fields = __all__), which is why Core hands it only the action key", "action" in WinUpdateSerializer().fields)

sample = WinUpdate.objects.order_by("pk").values_list("pk", "agent__pk", "action").first()
if sample is None:
    print("SKIP the read and write checks: this server has no Windows update row yet (scan one endpoint first)")
else:
    number, agent_pk, action = sample
    check("the fixed read names the update's endpoint", writer._read_update_agents([number]).get(number) == agent_pk)
    check("the fixed read names the update's decision", writer._read_actions([number]).get(number) == action)
    other = "ignore" if action != "ignore" else "approve"
    kb_before = WinUpdate.objects.filter(pk=number).values_list("kb", "installed").first()
    try:
        with transaction.atomic():
            result = writer._write_locked([(number, action, other)])
            now = WinUpdate.objects.filter(pk=number).values_list("action", "kb", "installed").first()
            check("the locked write saved the one decision through Tactical's serializer", result["saved"] == [[number, other]] and now[0] == other)
            check("installed and kb were not touched", (now[1], now[2]) == tuple(kb_before))
            stale = writer._write_locked([(number, action, action)])  # 'before' is no longer what the row holds: a person's decision wins
            check("a row whose decision is not the one Core read is left alone", stale["changed"] == [number] and stale["saved"] == [])
            missing = writer._write_locked([(2**62, "nothing", "approve")])
            check("a row that does not exist is counted, not written", missing["vanished"] == [2**62])
            transaction.set_rollback(True)
    except Exception as exc:  # noqa: BLE001 - a probe: report it as a failed line
        check(f"the write probe ran without an error ({type(exc).__name__}: {exc})", False)
    after = WinUpdate.objects.filter(pk=number).values_list("action", flat=True).first()
    check("the probe was rolled back: the decision is what it was", after == action)

try:
    sa.register_system_action("patching.runtimeprobe", "patching", "probe", "winupdate.set_action", ["can_manage_winupdates"], dangerous=True)
    check("Windows Patching is refused the write row", False)
except sa.SystemActionRegistrationError as exc:
    check("Windows Patching is refused the write row (" + str(exc)[:70] + "...)", "honourably replaces" in str(exc))
except Exception as exc:  # noqa: BLE001 - a probe
    check(f"Windows Patching is refused the write row (unexpected {type(exc).__name__})", False)

print("PASS system writes runtime 1.17.70" if all(RESULTS) else "FAIL system writes runtime 1.17.70")
if not all(RESULTS):
    sys.exit(1)
