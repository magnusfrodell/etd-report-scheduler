"""0.9.0: demo mode - invented tenants behind a simulated ETD API, collected and reported by the real code."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.config import get_config
from app.db import session_scope
from app.delivery.email import send_email
from app.demo import scenario
from app.demo.seed import add_demo_tenant, collect_history, fill_archive_history
from app.demo.simulator import day_messages, day_stats, simulator
from app.etd import client as etd_client
from app.etd import factory
from app.models import ConvictedMessage, DailyStat, ReportRun, ReportSchedule, Tenant, utcnow
from app.reports import domains
from app.services import build_context, get_report
from app.settings_store import load_settings

SPECS = {t.key: t for t in scenario.TENANTS}


@pytest.fixture(scope="module")
def demo_world(client):
    """The four demo tenants with their history collected through the real collectors - once per module."""
    patch = pytest.MonkeyPatch()
    patch.setattr(factory, "transport_factory", simulator.transport_for)
    patch.setattr(etd_client, "limiter_for", lambda key, per_second=2.0: etd_client.RateLimiter(0))
    with session_scope() as s:
        ids = {spec.key: add_demo_tenant(s, spec).id for spec in scenario.TENANTS}
    records = scenario.dns_records()
    patch.setattr(domains, "resolve_txt", lambda name: list(records.get(name, [])))
    collect_history(list(ids.values()))
    yield ids
    patch.undo()


def test_the_simulation_is_deterministic_and_consistent():
    simulator.spec_for(SimpleNamespace(client_id="demo-nordic-freight", name="Nordic Freight AB"))
    day = utcnow().date() - timedelta(days=3)
    first, again = day_messages("nordic-freight", day), day_messages("nordic-freight", day)
    assert first == again and first, "the same day always gives the same messages"
    stats = day_stats("nordic-freight", day)
    for verdict in ("phishing", "malicious", "bec", "scam"):
        assert stats["verdicts"][verdict] == sum(1 for m in first if m["verdict"]["category"] == verdict), "statistics agree with the search"


def test_each_demo_tenant_tells_its_story(demo_world):
    nordic, baltic, helios, aurora = (demo_world[k] for k in ("nordic-freight", "baltic-pharma", "helios-energy", "aurora-retail"))
    month_ago = utcnow() - timedelta(days=30)
    with session_scope() as s:
        assert s.execute(select(func.count()).select_from(DailyStat).where(DailyStat.tenant_id == nordic)).scalar_one() >= 89

        def messages(tid: int, *conditions):
            return s.execute(select(func.count()).select_from(ConvictedMessage).where(ConvictedMessage.tenant_id == tid, *conditions)).scalar_one()

        assert messages(nordic, ConvictedMessage.from_address == "accounts@baltic-shipping.example", ConvictedMessage.verdict == "bec") > 0
        assert messages(nordic, ConvictedMessage.from_address == "it-support@nordicfreigth.example") > 0
        assert messages(helios, ConvictedMessage.direction == "outgoing", ConvictedMessage.timestamp >= month_ago) > 0, "the hijacked mailbox"
        assert messages(baltic, ConvictedMessage.is_retro_verdict.is_(True), ConvictedMessage.action_type.is_(None)) > 0, "retro verdicts left behind"
        techniques = {t["type"] for m in s.execute(select(ConvictedMessage.techniques).where(ConvictedMessage.tenant_id == nordic)).scalars()
                      for t in m or []}
        assert {"QR Code", "Malicious HTML Attachment", "Domain Brand Impersonation"} <= techniques
        assert "logs" in (s.get(Tenant, aurora).collector_errors or {}), "Aurora's Log Export fails - for the Data quality page"
        tenant = s.get(Tenant, nordic)
        definition = get_report("vendor_risk")
        data = definition.build(s, build_context(s, definition, tenant, utcnow(), load_settings(s).timezone))
    assert "baltic-shipping.example" in {r["domain"] for r in data["compromised"]}
    assert "nordicfreigth.example" in {r["domain"] for r in data["lookalikes"]}


def test_archive_history_is_backdated_to_when_the_schedule_would_have_run(demo_world):
    with session_scope() as s:
        schedule = ReportSchedule(tenant_id=demo_world["nordic-freight"], report_key="vendor_risk", cron="30 7 * * 1", recipients="",
                                  output_format="pdf", enabled=True, created_at=utcnow() - timedelta(days=200))
        s.add(schedule)
        s.flush()
        sid = schedule.id
    assert fill_archive_history([sid], per_schedule=3) == 3
    with session_scope() as s:
        runs = list(s.execute(select(ReportRun).where(ReportRun.schedule_id == sid).order_by(ReportRun.started_at)).scalars())
    assert len({r.period_start for r in runs}) == 3 and all(r.triggered_by == "schedule" and r.status == "ok" for r in runs)
    assert all(r.started_at.weekday() == 0 for r in runs), "generated on the Mondays the schedule fires"
    assert runs[-1].started_at - runs[0].started_at >= timedelta(days=13)


def test_demo_mode_saves_mail_to_the_outbox_instead_of_sending(client, monkeypatch):
    monkeypatch.setattr(get_config(), "demo_mode", True)
    with session_scope() as s:
        settings = load_settings(s)  # no relay configured - demo mode never needs one
    stamp = datetime.now(UTC)
    assert send_email(settings, ["ciso@corp.example"], "Demo outbox check", "<p>hello</p>") == {}
    outbox = get_config().data_dir / "demo-outbox"
    newest = max(outbox.glob("*.eml"), key=lambda p: p.stat().st_mtime)
    assert newest.stat().st_mtime >= stamp.timestamp() - 1 and b"Demo outbox check" in newest.read_bytes()


def test_activate_sends_every_call_to_the_simulator(monkeypatch):
    from app import demo
    from app.demo import seed

    for module, name in ((factory, "transport_factory"), (etd_client, "limiter_for"), (domains, "resolve_txt")):
        monkeypatch.setattr(module, name, getattr(module, name))  # restored after the test
    monkeypatch.setattr(seed, "seed_demo", lambda: False)
    monkeypatch.setattr(seed, "warm_up", lambda fill_archive: None)
    app = SimpleNamespace(state=SimpleNamespace())
    demo.activate(app)
    assert factory.transport_factory == simulator.transport_for
    assert any("p=none" in r for r in domains.resolve_txt("_dmarc.heliosenergy.example"))
    assert domains.resolve_txt("unknown.example") == [], "no real DNS lookups for demo domains"
    for _ in range(50):
        if not app.state.demo_warming:
            break
        time.sleep(0.02)
    assert app.state.demo_warming is False
