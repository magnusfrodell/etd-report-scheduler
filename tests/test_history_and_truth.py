"""0.5.3: history survives schedule deletion and restarts, missed schedules are caught up, delivery
results are honest, and reports never turn missing evidence into a good result."""

from __future__ import annotations

import gzip
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote
from zoneinfo import ZoneInfo

import httpx
import pytest
from aiosmtpd.controller import Controller
from sqlalchemy import select

from app.collectors.logs import parse_log
from app.db import session_scope
from app.models import DailyStat, LogFile, ReportRun, ReportSchedule, Tenant
from app.reports import audit_compliance
from app.reports.base import ReportContext
from app.reports.periods import period_for
from app.scheduler import missed_runs, read_heartbeat, write_heartbeat
from app.services import get_report, recover_interrupted_runs, render_report, run_report, run_schedule
from app.settings_store import load_settings, save_settings
from tests.conftest import make_tenant
from tests.test_posture_reports import NOW, P, _build, _collect, _msg, _seed


def _schedule(tid: int, *, created: datetime, enabled: bool = True, cron: str = "0 7 * * *") -> int:
    with session_scope() as s:
        schedule = ReportSchedule(tenant_id=tid, report_key="health_check", cron=cron, recipients="", output_format="html",
                                  enabled=enabled, created_at=created)
        s.add(schedule)
        s.flush()
        return schedule.id


# ------------------------------------------------------------------ history (F05, restarts, outages)
def test_deleting_a_schedule_keeps_its_reports(logged_in):
    tid = make_tenant("History-Co")
    sid = _schedule(tid, created=datetime.now(UTC) - timedelta(days=30))
    run_id = run_schedule(sid)
    r = logged_in.post(f"/schedules/{sid}/delete", follow_redirects=False)
    assert "kept" in r.headers["location"]
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run is not None and run.schedule_id is None and run.triggered_by == "schedule"
    assert "from a schedule" in logged_in.get(f"/archive?report=health_check&tenant={tid}&run={run_id}").text


def test_runs_interrupted_by_a_restart_are_closed(client):
    tid = make_tenant("Restart-Co")
    with session_scope() as s:
        run = ReportRun(tenant_id=tid, report_key="health_check", status="running", triggered_by="manual")
        s.add(run)
        s.flush()
        run_id = run.id
    assert recover_interrupted_runs() >= 1
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.status == "failed" and run.error.startswith("Interrupted") and run.finished_at is not None


def test_heartbeat_round_trip(client):
    moment = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    write_heartbeat(moment)
    assert read_heartbeat() == moment


def test_missed_schedules_are_caught_up_once(client):
    tid = make_tenant("Catchup-Co")
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    down_since = now - timedelta(days=3)
    daily = _schedule(tid, created=now - timedelta(days=30))
    newer = _schedule(tid, created=datetime(2026, 9, 19, 10, 0, tzinfo=UTC))
    _schedule(tid, created=now - timedelta(days=30), enabled=False)
    with session_scope() as s:
        tz = load_settings(s).timezone
        missed = missed_runs(s, down_since, now, tz)
    due = [d for sid, d in missed if sid == daily]
    assert len(due) == 3 and due == sorted(due)
    assert len([d for sid, d in missed if sid == newer]) == 1, "only what fell due after the schedule was created"
    run_id = run_schedule(daily, reference=due[-1], triggered_by="catchup")
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        expected = period_for(get_report("health_check").period_kind, due[-1], ZoneInfo(tz))
        assert run.triggered_by == "catchup" and run.period_start == expected.start
        again = [d for sid, d in missed_runs(s, down_since, now, tz) if sid == daily]
    assert again == due[:2], "a caught-up period is not queued again"


# ------------------------------------------------------------------ delivery (F08)
class _Relay:
    def __init__(self) -> None:
        self.messages: list[object] = []

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # noqa: ANN001 - aiosmtpd signature
        if address.startswith("nobody@"):
            return "550 5.1.1 No such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001
        self.messages.append(envelope)
        return "250 OK"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def smtp_relay_at(client):
    def configure(port: int) -> None:
        with session_scope() as s:
            save_settings(s, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "etd@example.com", "smtp_starttls": False})

    yield configure
    with session_scope() as s:
        save_settings(s, {"smtp_host": "", "smtp_from": "", "smtp_port": 587, "smtp_starttls": True})


def test_partly_refused_delivery_is_reported(logged_in, smtp_relay_at):
    tid = make_tenant("Delivery-Co")
    relay, port = _Relay(), _free_port()
    controller = Controller(relay, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        smtp_relay_at(port)
        run_id = run_report("health_check", tenant_id=tid, recipients=["soc@example.com", "nobody@example.com"], output_format="html")
    finally:
        controller.stop()
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.status == "ok" and run.delivered_to == "soc@example.com"
        assert "nobody@example.com" in run.delivery_error and "550" in run.delivery_error
    assert len(relay.messages) == 1
    page = logged_in.get(f"/archive?report=health_check&tenant={tid}&run={run_id}").text
    assert 'id="pv-warning" class="preview-warning">' in page and "sent to soc@example.com" in page


def test_failed_delivery_keeps_the_report(client, smtp_relay_at):
    tid = make_tenant("Undelivered-Co")
    smtp_relay_at(_free_port())  # nothing listens there
    run_id = run_report("health_check", tenant_id=tid, recipients=["soc@example.com"], output_format="html")
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.status == "failed" and run.error.startswith("The report was generated, but sending it failed") and run.html_path


# ------------------------------------------------------------------ reports tell the truth (F04, F10, F11, F12)
def _stats(tid: int, threats_per_day: int) -> None:
    with session_scope() as s:
        for i in range(7):
            s.add(DailyStat(tenant_id=tid, day=(P.start + timedelta(days=i)).date(), total_messages=100, incoming=100, phishing=threats_per_day))


def _checks(tid: int) -> dict[str, dict]:
    return {c["name"]: c for c in _build(tid, "posture_effectiveness")["checks"]}


def test_posture_needs_evidence_before_a_grade(client):
    tid = make_tenant("Evidence-Co")
    _stats(tid, 5)  # 35 threats in the statistics, but the conviction collector never ran
    pe = _build(tid, "posture_effectiveness")
    checks = {c["name"]: c for c in pe["checks"]}
    assert checks["Threats remediated"]["status"] == "unknown" and checks["Dwell time for retro verdicts"]["status"] == "unknown"
    assert pe["grade"] is None and pe["insufficient"] and pe["evidence"] < 80
    with session_scope() as s:
        ctx = ReportContext(period=P, generated_at=NOW, timezone="UTC", tenant=s.get(Tenant, tid))
        html = render_report(s, get_report("posture_effectiveness"), ctx)
    assert "Insufficient evidence for a score" in html and "grade A" not in html
    with session_scope() as s:
        s.get(Tenant, tid).convictions_collected_at = NOW
    assert _checks(tid)["Threats remediated"]["detail"].startswith("The daily statistics count 35 threat(s)")


def test_no_threats_is_not_applicable_rather_than_perfect(client):
    tid = make_tenant("Quiet-Co")
    _stats(tid, 0)
    with session_scope() as s:
        s.get(Tenant, tid).convictions_collected_at = NOW
    checks = _checks(tid)
    for name in ("Threats remediated", "Remediation is automatic", "Dwell time for retro verdicts", "No threats through allow-lists"):
        assert checks[name]["status"] == "na" and checks[name]["points"] is None, name


def test_dwell_counts_retro_verdicts_never_remediated(client):
    tid = make_tenant("Dwell-Co")
    _stats(tid, 1)
    with session_scope() as s:
        s.get(Tenant, tid).convictions_collected_at = NOW
        s.add(_msg(tid, 1, is_retro_verdict=True))  # remediated two minutes after delivery
        s.add(_msg(tid, 2, is_retro_verdict=True, action_type=None, action_timestamp=None, is_auto_remediated=False))
    dwell = _checks(tid)["Dwell time for retro verdicts"]
    assert dwell["status"] != "ok" and "1 still not remediated" in dwell["detail"]


def test_vap_share_uses_one_unit(client):
    tid = make_tenant("Vap-Co")
    mailboxes = [f"user{i}@corp.example" for i in range(10)]
    with session_scope() as s:
        s.add(_msg(tid, 1, to_addresses=mailboxes, mailboxes=mailboxes))
    assert _build(tid, "vap_index")["top10_share"] == 100  # one threat to ten mailboxes used to read 1,000 %


def test_subdomain_spoofs_are_found(client):
    tid = make_tenant("Spoof-Co")
    with session_scope() as s:
        s.get(Tenant, tid).profile = {"own_domains": ["corp.example"]}
        s.add(_msg(tid, 1, from_address="billing@corp.example.secure-login.net"))
    hit = next(x for x in _build(tid, "vendor_risk")["lookalikes"] if x["domain"] == "secure-login.net")
    assert hit["seen_as"] == "corp.example.secure-login.net" and hit["protected"] == "corp.example"


def test_dmarc_policy_is_not_presented_as_authentication(client):
    tid = make_tenant("Dmarc-Co")
    _seed(tid)
    assert not any("authenticated fine" in r for r in _build(tid, "auth_posture")["recommendations"])


# ------------------------------------------------------------------ Log Export (F03)
def test_parse_log_counts_unreadable_lines():
    assert parse_log(b'{"a": 1}\nnot json\n{"b": 2}\n') == ([{"a": 1}, {"b": 2}], 1)
    assert parse_log(gzip.compress(b'{"a": 1}\n' * 50)[:-10]) == ([], 1), "a truncated download"
    assert parse_log(b"") == ([], 0)


def test_corrupt_log_file_is_fetched_again_then_marked_partial(client, mock_etd, monkeypatch):
    tid = make_tenant("Corrupt-Logs-Co")
    target = "log_date=2026-08-31/hour=09/log_type=audit/"
    original = mock_etd._log_file

    def corrupt(request: httpx.Request) -> httpx.Response:
        response = original(request)
        return httpx.Response(200, content=response.content + b"\n{not json") if target in unquote(str(request.url)) else response

    monkeypatch.setattr(mock_etd, "_log_file", corrupt)
    result = _collect(tid, datetime(2026, 9, 1, 10, 30, tzinfo=UTC))
    assert "marked partial" in result["note"]
    assert sum(1 for d in mock_etd.downloads if target in d) == 3, "fetched again before giving up"
    with session_scope() as s:
        row = s.execute(select(LogFile).where(LogFile.tenant_id == tid, LogFile.status == "partial")).scalar_one()
        assert row.parse_errors == 1 and row.events >= 1 and row.log_type == "audit"
        cov = audit_compliance.log_coverage(s.get(Tenant, tid), datetime(2026, 8, 31, tzinfo=UTC), datetime(2026, 9, 1, tzinfo=UTC), s)
        assert cov["partial_files"] == 1 and cov["unreadable_lines"] == 1
