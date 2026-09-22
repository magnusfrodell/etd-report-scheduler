from datetime import UTC, date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from app.db import session_scope
from app.models import DailyStat, ReportRun, Tenant
from app.reports import repo
from app.reports.base import ReportContext
from app.reports.periods import pct_change, period_for
from app.reports.registry import REPORTS, get_report
from app.services import run_report
from tests.conftest import make_tenant


def test_period_previous_complete_periods():
    tz = ZoneInfo("Europe/Stockholm")
    now = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)
    d = period_for("daily", now, tz)
    assert d.start_day == date(2026, 9, 21) and d.end_day == date(2026, 9, 21) and d.previous_start_day == date(2026, 9, 20)
    w = period_for("weekly", now, tz)
    assert w.start_day == date(2026, 9, 14) and w.end_day == date(2026, 9, 20) and w.previous_start_day == date(2026, 9, 7)
    m = period_for("monthly", now, tz)
    assert m.start_day == date(2026, 8, 1) and m.end_day == date(2026, 8, 31) and m.previous_start_day == date(2026, 7, 1)
    assert m.label == "August 2026" and m.days == 31


def test_pct_change():
    assert pct_change(110, 100) == 10.0 and pct_change(50, 100) == -50.0
    assert pct_change(5, 0) is None and pct_change(0, 0) is None


def _seed(tenant_id: int, day: date, total: int, malicious: int) -> None:
    with session_scope() as s:
        s.add(DailyStat(tenant_id=tenant_id, day=day, total_messages=total, incoming=total, malicious=malicious))


def test_tenant_isolation_and_rollup(client):
    a, b = make_tenant("Iso-A"), make_tenant("Iso-B")
    tz = ZoneInfo("UTC")
    now = datetime(2026, 9, 22, 6, 0, tzinfo=UTC)
    p = period_for("daily", now, tz)
    _seed(a, p.start_day, 1000, 7)
    _seed(a, p.previous_start_day, 900, 3)
    _seed(b, p.start_day, 5000, 40)

    with session_scope() as s:
        ctx_a = ReportContext(period=p, generated_at=now, timezone="UTC", tenant=s.get(Tenant, a))
        data_a = get_report("executive_summary").build(s, ctx_a)
        assert data_a["current"]["total_messages"] == 1000 and data_a["current"]["threats"] == 7
        assert data_a["previous"]["threats"] == 3 and data_a["headline"][1]["pct"] == 133.3
        assert repo.stat_totals(s, b, p.start_day, p.end_day).threats == 40

        ctx_all = ReportContext(period=p, generated_at=now, timezone="UTC", tenants=[s.get(Tenant, a), s.get(Tenant, b)])
        roll = get_report("cross_tenant_rollup").build(s, ctx_all)
        assert [r["tenant"] for r in roll["rows"]] == ["Iso-B", "Iso-A"], "ranked by threats"
        assert roll["grand"]["threats"] == 47 and roll["rows"][0]["threat_pct"] is None


def test_run_report_archives_and_records(client, tenant_id):
    for key in ("executive_summary", "compromise_indicators", "health_check"):
        run_id = run_report(key, tenant_id=tenant_id, deliver=False)
        with session_scope() as s:
            run = s.get(ReportRun, run_id)
            assert run.status == "ok", run.error
            assert run.html_path and Path(run.html_path).exists()
            html = Path(run.html_path).read_text()
            assert REPORTS[key].name in html and "Tenant-" in html
    run_id = run_report("cross_tenant_rollup", deliver=False)
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.status == "ok" and run.tenant_id is None and "_all-tenants" in run.html_path


def test_run_report_failure_is_recorded(client):
    run_id = run_report("executive_summary", tenant_id=999999, deliver=False)
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.status == "failed" and "Tenant not found" in run.error


def test_registry_scopes():
    assert set(REPORTS) == {"executive_summary", "compromise_indicators", "health_check", "cross_tenant_rollup"}
    assert REPORTS["cross_tenant_rollup"].is_cross_tenant and not REPORTS["health_check"].is_cross_tenant


def test_concurrent_runs_never_share_archive_files(client, tenant_id):
    """Two runs of the same report for the same tenant in the same second get distinct files."""
    import threading

    now = datetime(2026, 9, 22, 7, 0, 0, tzinfo=UTC)
    ids: list[int] = []
    lock = threading.Lock()

    def go():
        rid = run_report("health_check", tenant_id=tenant_id, deliver=False, now=now)
        with lock:
            ids.append(rid)

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with session_scope() as s:
        runs = [s.get(ReportRun, rid) for rid in ids]
        assert all(r.status == "ok" for r in runs)
        paths = {r.html_path for r in runs}
        assert len(paths) == 6 and all(Path(p).exists() for p in paths)
        assert all(f"-run{r.id}.html" in r.html_path for r in runs)
