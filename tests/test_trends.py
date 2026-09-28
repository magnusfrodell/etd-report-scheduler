"""0.15.0: trends over time - one tenant over twelve months, and every tenant side by side."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app.db import session_scope
from app.models import ConvictedMessage, DailyStat, Tenant
from app.reports import trends
from app.reports.registry import REPORTS
from app.services import build_context, render_report
from tests.conftest import make_tenant

NOW = datetime(2026, 9, 15, 9, 0, tzinfo=UTC)  # monthly period: August 2026; twelve months back to September 2025


def _days(first: date, last: date):
    d = first
    while d <= last:
        yield d
        d += timedelta(days=1)


def _seed_stats(tid: int, first: date, last: date, messages: int, phishing: int, skip: set[date] | None = None) -> None:
    with session_scope() as s:
        for d in _days(first, last):
            if skip and d in skip:
                continue
            s.add(DailyStat(tenant_id=tid, day=d, total_messages=messages, incoming=messages, phishing=phishing))


def _seed_messages(tid: int, month: date, count: int, retro: int, dwell_hours: float, techniques: list[str]) -> None:
    with session_scope() as s:
        for i in range(count):
            at = datetime(month.year, month.month, 10 + i, 8, 0, tzinfo=UTC)
            is_retro = i < retro
            s.add(ConvictedMessage(tenant_id=tid, etd_id=uuid.uuid4().hex, timestamp=at, verdict="phishing", is_retro_verdict=is_retro,
                                   action_timestamp=at + timedelta(hours=dwell_hours), is_auto_remediated=True, action_type="move",
                                   techniques=[{"technique": techniques[i % len(techniques)]}]))


@pytest.fixture(scope="module")
def worsening(client) -> int:
    """Thirteen months: 10 threats per 10 000 messages, then 20 in the last three months; January 2026 only
    partly collected; retro share 25 % -> 50 %, dwell 2 h -> 6 h; QR Code rising, Link Masquerade falling."""
    tid = make_tenant(f"Trend-Worse-{uuid.uuid4().hex[:6]}")
    january_gap = set(_days(date(2026, 1, 11), date(2026, 1, 31)))
    _seed_stats(tid, date(2025, 8, 1), date(2026, 5, 31), 1000, 1, skip=january_gap)
    _seed_stats(tid, date(2026, 6, 1), date(2026, 8, 31), 1000, 2)
    for month in (date(2026, 3, 1), date(2026, 4, 1), date(2026, 5, 1)):
        _seed_messages(tid, month, 4, retro=1, dwell_hours=2, techniques=["Link Masquerade", "Link Masquerade", "Link Masquerade", "QR Code"])
    for month in (date(2026, 6, 1), date(2026, 7, 1)):
        _seed_messages(tid, month, 4, retro=2, dwell_hours=6, techniques=["QR Code", "QR Code", "QR Code", "Link Masquerade"])
    _seed_messages(tid, date(2026, 8, 1), 4, retro=2, dwell_hours=6, techniques=["QR Code", "QR Code", "Callback Phishing", "Link Masquerade"])
    return tid


def _data(tid: int | None, key: str = "trends", lang: str = "en") -> dict:
    definition = REPORTS[key]
    with session_scope() as s:
        tenant = s.get(Tenant, tid) if tid else None
        ctx = build_context(s, definition, tenant, NOW, "UTC", lang=lang)
        return definition.build(s, ctx)


def test_twelve_months_with_incomplete_months_marked(worsening):
    data = _data(worsening)
    rows = data["rows"]
    assert len(rows) == 12 and rows[0]["month"] == "Sep 2025" and rows[-1]["month"] == "Aug 2026"
    january = next(r for r in rows if r["month"] == "Jan 2026")
    assert january["days"] == 10 and january["expected"] == 31 and not january["complete"]
    assert rows[-1]["per_10k"] == 20.0 and rows[0]["per_10k"] == 10.0
    assert data["threats_12m"] == sum(r["threats"] for r in rows)


def test_the_last_three_months_are_compared_with_the_three_before(worsening):
    data = _data(worsening)
    assert data["now"]["per_10k"] == 20.0 and data["before"]["per_10k"] == 10.0 and data["rate_change"] == 100.0
    assert data["now"]["retro_share"] == 50.0 and data["before"]["retro_share"] == 25.0 and data["retro_points"] == 25.0
    assert data["dwell_now"] == "6.0 h" and data["dwell_before"] == "2.0 h"


def test_techniques_on_the_rise_in_decline_and_new(worsening):
    data = _data(worsening)
    assert data["rising"][0] == {"technique": "QR Code", "now": 8, "before": 3}
    assert data["falling"][0] == {"technique": "Link Masquerade", "now": 3, "before": 9}
    assert data["new_techniques"] == ["Callback Phishing"]


def test_what_stands_out_says_it_plainly(worsening):
    insights = " ".join(_data(worsening)["insights"])
    assert "The threat rate is 100.0 % higher than in the three months before: 20.0 against 10.0" in insights
    assert "Aug 2026: 20.0 threats per 10 000 messages, against 10.0 in Aug 2025." in insights
    assert "50.0 % were convicted retrospectively, against 25.0 %" in insights
    assert "median 6.0 h against 2.0 h" in insights
    assert "QR Code is on the rise: 8 threats in the last three months against 3 before." in insights
    assert "1 month(s) have less than 80 % of their days collected" in insights


def test_a_young_tenant_gets_no_invented_comparison(client):
    tid = make_tenant(f"Trend-Young-{uuid.uuid4().hex[:6]}")
    _seed_stats(tid, date(2026, 7, 1), date(2026, 8, 31), 1000, 3)
    _seed_messages(tid, date(2026, 8, 1), 4, retro=1, dwell_hours=2, techniques=["QR Code"])
    data = _data(tid)
    assert data["rate_change"] is None and data["before"] is None and not data["rising"] and not data["new_techniques"]
    assert any("not yet enough history" in line for line in data["insights"])
    assert not any("on the rise" in line for line in data["insights"]), "no technique is rising against months never collected"


def test_every_tenant_side_by_side_largest_increase_first(worsening):
    flat = make_tenant(f"Trend-Flat-{uuid.uuid4().hex[:6]}")
    _seed_stats(flat, date(2025, 9, 1), date(2026, 8, 31), 1000, 1)
    silent = make_tenant(f"Trend-Silent-{uuid.uuid4().hex[:6]}")
    data = _data(None, "trends_all")
    by_id = {r["tenant"]: r for r in data["rows"]}
    with session_scope() as s:
        worse_name, flat_name, silent_name = (s.get(Tenant, t).name for t in (worsening, flat, silent))
    order = [r["tenant"] for r in data["rows"]]
    assert order.index(worse_name) < order.index(flat_name) < order.index(silent_name)
    worse = by_id[worse_name]
    assert worse["change"] == 100.0 and len(worse["spark"]) == 12
    assert worse["spark"][4] == "·", "January was not completely collected"
    assert worse["spark"][-3:] == "███" and worse["spark"][0] == "▁"
    assert by_id[flat_name]["change"] == 0.0 and set(by_id[flat_name]["spark"]) == {"▄"}
    assert by_id[silent_name]["spark"] == "·" * 12 and by_id[silent_name]["change"] is None
    assert len(data["fleet"]) == 12


def test_the_swedish_trend_report(worsening):
    definition = REPORTS["trends"]
    with session_scope() as s:
        html = render_report(s, definition, build_context(s, definition, s.get(Tenant, worsening), NOW, "UTC", lang="sv"))
    assert "Tolv månader · sep. 2025 – aug. 2026" in html
    assert "Hotnivån är 100,0 % högre än under de tre månaderna dessförinnan: 20,0 mot 10,0 hot per 10 000 meddelanden." in html
    assert "QR Code ökar" in html and "ofullständig" in html


def test_sparkline():
    assert trends.sparkline([1.0, 2.0, None, 8.0]) == "▁▂·█"
    assert trends.sparkline([None, None]) == "··"
    assert trends.sparkline([5.0, 5.0]) == "▄▄"
