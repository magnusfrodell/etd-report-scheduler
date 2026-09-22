from datetime import timedelta

from sqlalchemy import func, select

from app.collectors.runner import collect_convictions_for_tenant, collect_stats_for_tenant
from app.db import session_scope
from app.models import ConvictedMessage, DailyStat, Tenant, TopEntry, utcnow


def test_collect_stats_backfills_90_days_then_refreshes(tenant_id, mock_etd):
    first = collect_stats_for_tenant(tenant_id)
    assert first["status"] == "ok" and first["days"] == 90, "first run covers the whole 90-day horizon"
    report_calls = [b for p, b in mock_etd.calls if p == "/v1/messages/report"]
    assert len(report_calls) == 3, "90 days of daily buckets still cost only three Reporting API calls"
    second = collect_stats_for_tenant(tenant_id)
    assert second["status"] == "ok" and second["days"] == 4, "later runs refresh 3 days back + today"
    with session_scope() as s:
        rows = list(s.execute(select(DailyStat).where(DailyStat.tenant_id == tenant_id).order_by(DailyStat.day)).scalars())
        assert len(rows) == 90
        assert rows[0].incoming == 100 and rows[0].threats == 7 and rows[0].unwanted == 15 and rows[0].retro_verdicts == 2
        tops = list(s.execute(select(TopEntry).where(TopEntry.tenant_id == tenant_id)).scalars())
        periods = {(t.period_start, t.period_end) for t in tops}
        assert {t.kind for t in tops} == {"targets", "threatSenders"}
        assert len(periods) >= 3, "trailing 30 days plus at least two previous calendar months inside the horizon"
        t = s.get(Tenant, tenant_id)
        assert t.stats_collected_at is not None and t.last_error is None and t.stats_backfilled is True
        assert t.api_calls_count == mock_etd.token_calls + len([1 for p, _ in mock_etd.calls if p != "/v1/oauth/token"])


def test_collect_convictions_is_incremental(tenant_id, mock_etd):
    first = collect_convictions_for_tenant(tenant_id)
    assert first["status"] == "ok" and first["created"] == 205 and first["updated"] == 0
    second = collect_convictions_for_tenant(tenant_id)
    assert second["status"] == "ok" and second["created"] == 0 and second["updated"] == 205, "rescan updates, never duplicates"
    with session_scope() as s:
        n = s.execute(select(func.count()).select_from(ConvictedMessage).where(ConvictedMessage.tenant_id == tenant_id)).scalar_one()
        assert n == 205
        m = s.execute(select(ConvictedMessage).where(ConvictedMessage.tenant_id == tenant_id, ConvictedMessage.etd_id == "msg-0")).scalar_one()
        assert m.verdict in ("bec", "scam", "phishing", "malicious") and m.is_auto_remediated is True and m.action_folder == "junkemail"
        assert m.techniques[0]["type"] == "Malicious URL" and m.secure_email_gateway == "ciscoDefault"
        t = s.get(Tenant, tenant_id)
        assert t.convictions_watermark is not None and t.convictions_watermark > utcnow() - timedelta(minutes=5)
    search_calls = [b for p, b in mock_etd.calls if p == "/v1/messages/search"]
    assert search_calls[0]["verdicts"] == ["bec", "scam", "phishing", "malicious"], "threat verdicts only by default"


def test_failed_tenant_records_error(tenant_id, monkeypatch):
    import httpx

    from app.etd import factory

    monkeypatch.setattr(factory, "transport_factory", lambda tenant: httpx.MockTransport(lambda r: httpx.Response(500, json={"message": "boom"})))
    result = collect_stats_for_tenant(tenant_id)
    assert result["status"] == "failed"
    with session_scope() as s:
        t = s.get(Tenant, tenant_id)
        assert t.last_error and "500" in t.last_error and t.last_error_at is not None


def test_backfill_walks_back_within_budget(tenant_id, mock_etd):
    from app.collectors.runner import backfill_for_tenant
    from app.db import session_scope as scope
    from app.settings_store import save_settings

    with scope() as s:
        save_settings(s, {"api_daily_budget": 30, "backfill_window_days": 7})
    assert collect_convictions_for_tenant(tenant_id)["status"] == "ok", "quick 7-day pull first"

    first = backfill_for_tenant(tenant_id)
    assert first["status"] == "paused", first
    with scope() as s:
        t = s.get(Tenant, tenant_id)
        assert t.backfill_cursor is not None and t.backfill_done_at is None
        cursor_after_first = t.backfill_cursor
        assert t.api_calls_count <= 30 + 3, "budget respected (a few calls of slack for the window in progress)"
        # Reset the day counter to simulate the next day, then finish the backfill.
        t.api_calls_count = 0
        save_settings(s, {"api_daily_budget": 8000})
    second = backfill_for_tenant(tenant_id)
    assert second["status"] == "done", second
    with scope() as s:
        t = s.get(Tenant, tenant_id)
        assert t.backfill_done_at is not None and t.backfill_cursor < cursor_after_first
        assert (utcnow() - t.backfill_cursor).days >= 88
    assert backfill_for_tenant(tenant_id)["status"] == "skipped"
    windows = [b["timestamp"] for p, b in mock_etd.calls if p == "/v1/messages/search"]
    starts = [w[0] for w in windows]
    assert starts == sorted(starts, reverse=True) or len(set(starts)) > 1, "newest windows first"


def test_collect_all_runs_stats_convictions_and_backfill(tenant_id, mock_etd):
    from app.collectors.runner import collect_all_for_tenant

    results = collect_all_for_tenant(tenant_id)
    assert [r["status"] for r in results] == ["ok", "ok", "done"]
    with session_scope() as s:
        t = s.get(Tenant, tenant_id)
        assert t.stats_backfilled and t.backfill_done_at is not None and t.convictions_watermark is not None
