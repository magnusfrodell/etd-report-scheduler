"""0.7.0: schedules for all tenants or a group, recipients per tenant, only-with-findings,
one alert per schedule run and catch-up per tenant."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote
from uuid import uuid4

import pytest
from aiosmtpd.controller import Controller
from sqlalchemy import select

from app.db import session_scope
from app.models import ReportRun, ReportSchedule, Tenant
from app.scheduler import cron_trigger, missed_runs
from app.services import run_report, run_schedule
from app.settings_store import load_settings, save_settings
from tests.conftest import make_tenant
from tests.test_posture_reports import NOW, _msg
from tests.test_quality_alerts_backup import alert_inbox  # noqa: F401 - pytest fixture
from tests.test_rbac import _grant, _login, _user


class _Relay:
    def __init__(self) -> None:
        self.deliveries: list[tuple[str, ...]] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001 - aiosmtpd signature
        self.deliveries.append(tuple(sorted(envelope.rcpt_tos)))
        return "250 OK"


@pytest.fixture
def relay(client):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    inbox = _Relay()
    controller = Controller(inbox, hostname="127.0.0.1", port=port)
    controller.start()
    with session_scope() as s:
        save_settings(s, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "etd@example.com", "smtp_starttls": False})
    yield inbox
    controller.stop()
    with session_scope() as s:
        save_settings(s, {"smtp_host": "", "smtp_from": "", "smtp_port": 587, "smtp_starttls": True})


def _tenant(name: str, *, group: str = "", contacts: tuple[str, ...] = (), enabled: bool = True) -> int:
    tid = make_tenant(name)
    with session_scope() as s:
        t = s.get(Tenant, tid)
        t.profile = {"group": group, "report_recipients": list(contacts)}
        t.enabled = enabled
    return tid


def _schedule(report_key: str = "health_check", **fields: object) -> int:
    with session_scope() as s:
        schedule = ReportSchedule(report_key=report_key, cron="0 7 * * 1", recipients=fields.pop("recipients", ""),
                                  output_format="html", enabled=True, **fields)
        s.add(schedule)
        s.flush()
        return schedule.id


def _runs(sid: int) -> dict[int | None, tuple]:
    with session_scope() as s:
        runs = s.execute(select(ReportRun).where(ReportRun.schedule_id == sid).order_by(ReportRun.id)).scalars()
        return {r.tenant_id: (r.status, r.delivered_to, r.delivery_note, r.triggered_by) for r in runs}


def test_group_schedule_uses_each_tenants_contacts_and_picks_up_new_tenants(relay):
    group = f"Premium-{uuid4().hex[:6]}"
    a = _tenant("Group-A", group=group, contacts=("ciso@a.example",))
    b = _tenant("Group-B", group=group.upper())  # the group match ignores case; no contacts
    _tenant("Group-C", group="Basic", contacts=("x@c.example",))
    d = _tenant("Group-D", group=group, contacts=("x@d.example",), enabled=False)
    sid = _schedule(target="group", target_group=group, recipient_mode="tenant")
    run_schedule(sid)
    runs = _runs(sid)
    assert set(runs) == {a, b}, "only the enabled tenants in the group"
    assert runs[a][1] == "ciso@a.example"
    assert runs[b][0] == "ok" and runs[b][1] is None and runs[b][2] == "Not sent: the tenant profile has no report recipients."
    assert relay.deliveries == [("ciso@a.example",)]
    e = _tenant("Group-E", group=group, contacts=("soc@e.example",))
    run_schedule(sid)
    assert e in _runs(sid) and d not in _runs(sid), "a tenant added later is covered without touching the schedule"


def test_all_tenant_schedule_with_both_recipient_lists(relay):
    a = _tenant("All-A", contacts=("ciso@a.example",))
    off = _tenant("All-Off", contacts=("x@off.example",), enabled=False)
    sid = _schedule(target="all", recipient_mode="both", recipients="noc@partner.example")
    run_schedule(sid)
    runs = _runs(sid)
    assert a in runs and off not in runs
    assert runs[a][1] == "noc@partner.example, ciso@a.example"
    assert ("ciso@a.example", "noc@partner.example") in relay.deliveries


def test_only_with_findings_archives_but_does_not_send_quiet_reports(relay):
    group = f"Findings-{uuid4().hex[:6]}"
    quiet = _tenant("Quiet-Tenant", group=group, contacts=("q@quiet.example",))
    noisy = _tenant("Noisy-Tenant", group=group, contacts=("n@noisy.example",))
    with session_scope() as s:
        s.add(_msg(noisy, 1, action_type=None, action_timestamp=None, is_auto_remediated=False))  # still in the mailbox
    sid = _schedule("exposure", target="group", target_group=group, recipient_mode="tenant", only_with_findings=True)
    run_schedule(sid, reference=NOW)
    runs = _runs(sid)
    assert runs[noisy][1] == "n@noisy.example"
    assert runs[quiet][0] == "ok" and runs[quiet][1] is None and runs[quiet][2].startswith("Not sent: nothing to report")
    assert relay.deliveries == [("n@noisy.example",)]


def test_problems_across_many_tenants_send_one_alert(alert_inbox, monkeypatch):  # noqa: F811 - fixture
    group = f"Alert-{uuid4().hex[:6]}"
    for name in ("Alert-One", "Alert-Two"):
        _tenant(name, group=group)
    sid = _schedule(target="group", target_group=group)

    def boom(*_args, **_kwargs):
        raise RuntimeError("template exploded")

    monkeypatch.setattr("app.services.render_report", boom)
    run_schedule(sid)
    assert len(alert_inbox.subjects) == 1 and "2 of 2 tenant(s)" in alert_inbox.subjects[0]
    assert "Alert-One" in alert_inbox.bodies[0] and "Alert-Two" in alert_inbox.bodies[0]


def test_catch_up_completes_a_partly_run_schedule(client):
    group = f"Catch-{uuid4().hex[:6]}"
    a, b = _tenant("Catch-A", group=group), _tenant("Catch-B", group=group)
    now = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)  # a Monday; the schedule fires Mondays at 07:00
    sid = _schedule(target="group", target_group=group, created_at=now - timedelta(days=30))
    with session_scope() as s:
        tz = load_settings(s).timezone
        due = [fire for schedule_id, fire in missed_runs(s, now - timedelta(hours=10), now, tz) if schedule_id == sid]
    assert len(due) == 1
    run_report("health_check", tenant_id=a, schedule_id=sid, reference=due[0], triggered_by="schedule")  # A made it before the outage
    with session_scope() as s:
        assert [f for i, f in missed_runs(s, now - timedelta(hours=10), now, tz) if i == sid] == due, "B is still missing"
    run_schedule(sid, reference=due[0], triggered_by="catchup", only_missing=True)
    with session_scope() as s:
        runs = list(s.execute(select(ReportRun).where(ReportRun.schedule_id == sid)).scalars())
        assert sorted((r.tenant_id, r.triggered_by) for r in runs) == sorted([(a, "schedule"), (b, "catchup")]), "A is not run twice"
        assert not [f for i, f in missed_runs(s, now - timedelta(hours=10), now, tz) if i == sid]


def test_schedule_form_and_report_cards(logged_in):
    group = f"Ui-{uuid4().hex[:6]}"
    tid = _tenant("Ui-Tenant", group=group, contacts=("ciso@ui.example",))
    page = logged_in.get("/schedules?report=vendor_risk").text
    assert '<option value="vendor_risk" selected>' in page and f'value="group:{group}"' in page and "including tenants added later" in page
    r = logged_in.post("/schedules", data={"report_key": "exposure", "target": f"group:{group}", "recipient_mode": "tenant",
                                           "only_with_findings": "on"}, follow_redirects=False)
    assert "err=" not in r.headers["location"]
    logged_in.post("/schedules", data={"report_key": "executive_summary", "target": "all", "only_with_findings": "on"}, follow_redirects=False)
    with session_scope() as s:
        exposure = s.execute(select(ReportSchedule).where(ReportSchedule.target_group == group)).scalar_one()
        assert exposure.target == "group" and exposure.recipient_mode == "tenant" and exposure.only_with_findings
        summary = s.execute(select(ReportSchedule).where(ReportSchedule.report_key == "executive_summary",
                                                         ReportSchedule.target == "all")).scalars().first()
        assert summary is not None and not summary.only_with_findings, "a summary always has something to say"
    logged_in.post("/select-tenant", data={"tenant": str(tid), "next": "/reports"})
    assert 'href="/schedules?report=exposure"' in logged_in.get("/reports").text, "the group schedule covers this tenant"
    logged_in.post("/select-tenant", data={"tenant": "all", "next": "/reports"})
    assert f"Group: {group}" in logged_in.get("/schedules").text


def test_only_tenant_admins_schedule_for_all_tenants(client):
    tid = _tenant("Operator-Tenant")
    _grant(_user("groupoperator"), tid, "operator")
    try:
        _login(client, "groupoperator")
        r = client.post("/schedules", data={"report_key": "health_check", "target": "all"}, follow_redirects=False)
        assert r.status_code == 403 or "err=" in r.headers.get("location", "")
        r = client.post("/schedules", data={"report_key": "health_check", "target": str(tid)}, follow_redirects=False)
        assert "err=" not in r.headers["location"]
        assert "including tenants added later" not in client.get("/schedules").text
    finally:
        _login(client, "admin", "test-password")


def test_profile_holds_group_and_report_recipients(logged_in):
    tid = make_tenant("Profile-Contacts")
    r = logged_in.post(f"/tenants/{tid}/profile", data={"group": "  Premium   Plus ", "report_recipients": "ciso@corp.example, not-an-address"},
                       follow_redirects=False)
    assert "not-an-address" in unquote(r.headers["location"])
    with session_scope() as s:
        profile = s.get(Tenant, tid).profile
    assert profile["group"] == "Premium Plus" and profile["report_recipients"] == ["ciso@corp.example"]


@pytest.mark.parametrize("expression, expected", [
    ("0 7 * * 1", ["Mon 21"]),                       # APScheduler's own from_crontab would say Tuesday
    ("0 7 * * 0", ["Sun 20"]),
    ("0 7 * * 7", ["Sun 20"]),                       # from_crontab rejects 7
    ("0 7 * * 1-5", ["Mon 21", "Tue 22", "Wed 23", "Thu 24", "Fri 25"]),
    ("0 7 * * 5-7", ["Sun 20", "Fri 25", "Sat 26"]),
    ("0 7 * * mon,wed,fri", ["Mon 21", "Wed 23", "Fri 25"]),
    ("0 7 * * */2", ["Sun 20", "Tue 22", "Thu 24", "Sat 26"]),
])
def test_cron_day_of_week_follows_standard_cron(expression, expected):
    trigger, fire, seen = cron_trigger(expression, "UTC"), datetime(2026, 9, 20, 0, 0, tzinfo=UTC), []  # from Sunday the 20th
    while (fire := trigger.get_next_fire_time(None, fire)) and fire < datetime(2026, 9, 27, tzinfo=UTC):
        seen.append(f"{fire:%a %d}")
        fire += timedelta(minutes=1)
    assert seen == expected


@pytest.mark.parametrize("expression", ["0 7 * * 8", "0 7 * * 5-2", "0 7 * *", "0 7 * * fri/0"])
def test_invalid_cron_is_rejected(expression):
    with pytest.raises(ValueError):
        cron_trigger(expression)
