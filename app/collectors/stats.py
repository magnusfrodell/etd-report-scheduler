# Copyright (c) 2026 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.
"""Daily statistics collector.

Three calls to ``/v1/messages/report`` (directions, verdicts, retroVerdicts,
``aggregationInterval=1d``) plus two calls to ``/v1/messages/report/top``
give everything the built-in Trends and Impact Report pages show. Rows are
upserted per UTC day, so re-running is idempotent and the trailing days are
refreshed every run (retrospective verdicts change yesterday's numbers).
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.etd.client import HISTORY_HORIZON_DAYS, ETDClient, parse_ts
from app.models import DailyStat, Tenant, TopEntry, utcnow

log = logging.getLogger(__name__)

TOP_PERIOD_DAYS = 30
BACKFILL_MONTHS = 3


def _day_start(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, tzinfo=UTC)


def collect_daily_stats(session: Session, tenant: Tenant, client: ETDClient, *, days_back: int = 3, now: datetime | None = None) -> int:
    """Upsert ``days_back`` trailing days (plus today so far) for one tenant. Returns rows touched.

    The first run for a tenant (``stats_backfilled`` false) fetches the whole 90-day horizon
    instead - it costs the same three calls, the Reporting API returns one bucket per day.
    """
    now = now or utcnow()
    today = now.date()
    backfill = not tenant.stats_backfilled
    if backfill:
        days_back = HISTORY_HORIZON_DAYS - 1
    start = _day_start(today - timedelta(days=days_back))
    end = now

    directions = client.report("directions", start, end, "1d")
    verdicts = client.report("verdicts", start, end, "1d")
    retro = client.report("retroVerdicts", start, end, "1d")

    rows: dict[date, DailyStat] = {}

    def row_for(day: date) -> DailyStat:
        if day not in rows:
            existing = session.execute(
                select(DailyStat).where(DailyStat.tenant_id == tenant.id, DailyStat.day == day)
            ).scalar_one_or_none()
            if existing is None:
                existing = DailyStat(tenant_id=tenant.id, day=day)
                session.add(existing)
            rows[day] = existing
        return rows[day]

    for bucket in directions.get("aggregations") or []:
        ts = parse_ts(bucket.get("startTimestamp"))
        if not ts:
            continue
        r = row_for(ts.date())
        counts = bucket.get("messages") or {}
        r.incoming = int(counts.get("incoming") or 0)
        r.outgoing = int(counts.get("outgoing") or 0)
        r.internal = int(counts.get("internal") or 0)
        r.total_messages = int(bucket.get("messageCount") or (r.incoming + r.outgoing + r.internal))

    for bucket in verdicts.get("aggregations") or []:
        ts = parse_ts(bucket.get("startTimestamp"))
        if not ts:
            continue
        r = row_for(ts.date())
        counts = bucket.get("messages") or {}
        for key in ("malicious", "phishing", "bec", "scam", "spam", "graymail"):
            setattr(r, key, int(counts.get(key) or 0))

    for bucket in retro.get("aggregations") or []:
        ts = parse_ts(bucket.get("startTimestamp"))
        if not ts:
            continue
        r = row_for(ts.date())
        r.retro_verdicts = int(bucket.get("messageCount") or 0)

    for r in rows.values():
        r.collected_at = now

    _collect_top(session, tenant, client, now, months=BACKFILL_MONTHS if backfill else 1)
    tenant.stats_collected_at = now
    tenant.stats_backfilled = True
    session.flush()
    log.info("Tenant %s: daily stats upserted for %d day(s)%s", tenant.name, len(rows), " (90-day backfill)" if backfill else "")
    return len(rows)


def _month_bounds(day: date, months_back: int) -> tuple[date, date]:
    """Inclusive (first, last) day of the calendar month ``months_back`` months before ``day``'s month."""
    first = day.replace(day=1)
    for _ in range(months_back):
        first = (first - timedelta(days=1)).replace(day=1)
    nxt = (first.replace(day=28) + timedelta(days=4)).replace(day=1)
    return first, nxt - timedelta(days=1)


def _collect_top(session: Session, tenant: Tenant, client: ETDClient, now: datetime, months: int = 1) -> None:
    """Trailing-30-day lists (replaced daily) plus exact lists for previous complete calendar months
    (stored once, so the monthly executive summary gets the real month rather than a trailing window)."""
    today = now.date()
    horizon = today - timedelta(days=HISTORY_HORIZON_DAYS - 1)
    _store_top(session, tenant, client, today - timedelta(days=TOP_PERIOD_DAYS), today, now, replace=True)
    for months_back in range(1, months + 1):
        first, last = _month_bounds(today, months_back)
        if first < horizon:
            break
        exists = session.query(TopEntry.id).filter(
            TopEntry.tenant_id == tenant.id, TopEntry.period_start == first, TopEntry.period_end == last
        ).first()
        if exists is None:
            _store_top(session, tenant, client, first, last, now, replace=False)


def _store_top(session: Session, tenant: Tenant, client: ETDClient, period_start: date, period_end: date, now: datetime, *, replace: bool) -> None:
    start = _day_start(period_start)
    end = min(_day_start(period_end) + timedelta(days=1), now)
    for kind in ("targets", "threatSenders"):
        entries = client.report_top(kind, start, end)
        if replace:
            session.query(TopEntry).filter(
                TopEntry.tenant_id == tenant.id, TopEntry.kind == kind, TopEntry.period_end == period_end
            ).delete(synchronize_session=False)
        for rank, entry in enumerate(entries, start=1):
            malicious = int(entry.get("malicious") or 0)
            phishing = int(entry.get("phishing") or 0)
            bec = int(entry.get("bec") or 0)
            scam = int(entry.get("scam") or 0)
            total = int(entry.get("total") or (malicious + phishing + bec + scam))
            session.add(
                TopEntry(
                    tenant_id=tenant.id,
                    kind=kind,
                    period_start=period_start,
                    period_end=period_end,
                    rank=rank,
                    email_address=str(entry.get("emailAddress") or "")[:320],
                    malicious=malicious,
                    phishing=phishing,
                    bec=bec,
                    scam=scam,
                    total=total,
                    collected_at=now,
                )
            )
    session.flush()
