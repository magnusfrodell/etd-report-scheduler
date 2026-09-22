from datetime import UTC, datetime, timedelta

import pytest

from app.etd.client import ETDClient, ETDError, iso_utc, parse_ts
from app.etd.regions import REGIONS, base_url_for
from tests.etd_mock import MockETD


def _client(fake: MockETD) -> ETDClient:
    return ETDClient("de", "cid", "secret", "apikey", transport=fake.transport)


def test_token_is_cached_and_refreshed_on_401():
    fake = MockETD(reject_first_bearer=True)
    c = _client(fake)
    now = datetime.now(UTC)
    data = c.report("verdicts", now - timedelta(days=2), now, "1d")
    assert data["aggregations"], "report data expected"
    assert fake.token_calls == 2, "one initial token plus one refresh after the 401"
    c.report("verdicts", now - timedelta(days=1), now, "1d")
    assert fake.token_calls == 2, "cached token reused"


def test_directions_fallback_to_singular():
    fake = MockETD(directions_key="direction")
    c = _client(fake)
    now = datetime.now(UTC)
    data = c.report("directions", now - timedelta(days=1), now, "1d")
    assert data["aggregations"][0]["messages"]["incoming"] == 100
    sent = [b["aggregateBy"] for p, b in fake.calls if p == "/v1/messages/report"]
    assert sent == ["directions", "direction"]
    c.report("directions", now - timedelta(days=1), now, "1d")
    assert [b["aggregateBy"] for p, b in fake.calls if p == "/v1/messages/report"][-1] == "direction", "alias remembered"


def test_search_paginates_and_chunks_windows():
    fake = MockETD(n_messages=205)
    c = _client(fake)
    now = datetime.now(UTC)
    msgs = list(c.iter_messages(now - timedelta(days=45), now, verdicts=["malicious", "phishing"]))
    search_calls = [b for p, b in fake.calls if p == "/v1/messages/search"]
    assert len(msgs) == 2 * 205, "two windows (45 days > 31) each return the full fake set"
    assert len(search_calls) == 2 * 3, "3 pages per window"
    assert all(len(set(b["timestamp"])) == 2 for b in search_calls)
    assert all("neutral" not in b["verdicts"] for b in search_calls)


def test_windows_and_clamp():
    now = datetime.now(UTC)
    w = ETDClient.windows(now - timedelta(days=70), now)
    assert len(w) == 3 and w[0][0] == now - timedelta(days=70) and w[-1][1] == now
    with pytest.raises(ValueError):
        ETDClient._clamp(now - timedelta(days=200), now - timedelta(days=150))


def test_missing_api_key_is_auth_error():
    fake = MockETD()
    c = ETDClient("de", "cid", "secret", "", transport=fake.transport)
    with pytest.raises(ETDError):
        c.get_token()


def test_log_export_window_limit():
    fake = MockETD()
    c = _client(fake)
    now = datetime.now(UTC)
    with pytest.raises(ValueError):
        c.log_download_links(now - timedelta(hours=5), now, ["audit"])
    links = c.log_download_links(now - timedelta(hours=2), now, ["audit", "message"])
    assert set(links) == {"audit", "message"}


def test_timestamp_helpers():
    assert iso_utc(datetime(2026, 9, 1, 12, 30, 15, 999, tzinfo=UTC)) == "2026-09-01T12:30:15Z"
    assert parse_ts("2025-07-21T06:36:01.079567128Z") == datetime(2025, 7, 21, 6, 36, 1, 79567, tzinfo=UTC)
    assert parse_ts("2023-11-19T12:00:00.000Z").tzinfo is not None
    assert parse_ts(None) is None and parse_ts("garbage") is None


def test_regions_include_beta():
    assert set(REGIONS) == {"us", "de", "au", "in", "ae", "beta"}
    assert base_url_for("beta") == "https://api.beta.etd.cisco.com"
    assert ETDClient("beta", "cid", "secret", "apikey").base_url == "https://api.beta.etd.cisco.com"
    with pytest.raises(ValueError):
        base_url_for("mars")


def test_rate_limiter_spaces_requests():
    from app.etd.client import RateLimiter

    clock = {"t": 100.0}
    slept: list[float] = []

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds

    limiter = RateLimiter(2.0, clock=lambda: clock["t"], sleep=fake_sleep)
    for _ in range(5):
        limiter.wait()
    assert slept and abs(sum(slept) - 2.0) < 1e-6, "5 requests at 2/s need 2 s of waiting in total"
    assert all(abs(d - 0.5) < 1e-6 for d in slept)


def test_client_uses_shared_limiter_per_tenant():
    from app.etd.client import limiter_for

    fake = MockETD()
    a = ETDClient("de", "cid", "secret", "apikey", transport=fake.transport)
    b = ETDClient("de", "cid", "secret", "apikey", transport=fake.transport)
    c = ETDClient("de", "other", "secret", "apikey", transport=fake.transport)
    assert a._limiter is b._limiter is limiter_for("https://api.de.etd.cisco.com|cid")
    assert c._limiter is not a._limiter


def test_iter_pages_yields_per_page_and_stops_early():
    from app.etd.client import RateLimiter

    fake = MockETD(n_messages=250)
    c = ETDClient("de", "cid", "secret", "apikey", transport=fake.transport, rate_limiter=RateLimiter(0))
    now = datetime.now(UTC)
    pages = c.iter_pages(now - timedelta(days=3), now, verdicts=["malicious"])
    first = next(pages)
    assert len(first) == 100
    assert len([1 for p, _ in fake.calls if p == "/v1/messages/search"]) == 1, "no request until the next page is asked for"
    rest = list(pages)
    assert [len(p) for p in rest] == [100, 50]
