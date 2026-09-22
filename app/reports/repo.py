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
"""Query helpers used by report builders.

Isolation rule: every function here takes ``tenant_id`` as a *required*
positional argument, except the ``*_all_tenants`` functions, which exist only
for the cross-tenant roll-up and return rows keyed by tenant. Report builders
never touch the ORM directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ConvictedMessage, DailyStat, Tenant, TopEntry

STAT_FIELDS = ("total_messages", "incoming", "outgoing", "internal", "malicious", "phishing", "bec", "scam", "spam", "graymail", "retro_verdicts")


@dataclass
class StatTotals:
    total_messages: int = 0
    incoming: int = 0
    outgoing: int = 0
    internal: int = 0
    malicious: int = 0
    phishing: int = 0
    bec: int = 0
    scam: int = 0
    spam: int = 0
    graymail: int = 0
    retro_verdicts: int = 0
    days_with_data: int = 0

    @property
    def threats(self) -> int:
        return self.malicious + self.phishing + self.bec + self.scam

    @property
    def unwanted(self) -> int:
        return self.spam + self.graymail

    @property
    def threat_rate_pct(self) -> float:
        return round(self.threats / self.total_messages * 100.0, 3) if self.total_messages else 0.0

    def as_dict(self) -> dict[str, int | float]:
        d = {f: getattr(self, f) for f in STAT_FIELDS}
        d["threats"] = self.threats
        d["unwanted"] = self.unwanted
        d["days_with_data"] = self.days_with_data
        d["threat_rate_pct"] = self.threat_rate_pct
        return d


def _totals_from_rows(rows: list[DailyStat]) -> StatTotals:
    t = StatTotals(days_with_data=len(rows))
    for r in rows:
        for f in STAT_FIELDS:
            setattr(t, f, getattr(t, f) + int(getattr(r, f) or 0))
    return t


def daily_stats(session: Session, tenant_id: int, start_day: date, end_day: date) -> list[DailyStat]:
    """Rows for ``tenant_id`` with ``start_day <= day <= end_day`` (inclusive), ordered by day."""
    stmt = (
        select(DailyStat)
        .where(DailyStat.tenant_id == tenant_id, DailyStat.day >= start_day, DailyStat.day <= end_day)
        .order_by(DailyStat.day)
    )
    return list(session.execute(stmt).scalars())


def stat_totals(session: Session, tenant_id: int, start_day: date, end_day: date) -> StatTotals:
    return _totals_from_rows(daily_stats(session, tenant_id, start_day, end_day))


def latest_top_entries(session: Session, tenant_id: int, kind: str, limit: int = 10) -> list[TopEntry]:
    latest_end = session.execute(
        select(func.max(TopEntry.period_end)).where(TopEntry.tenant_id == tenant_id, TopEntry.kind == kind)
    ).scalar_one_or_none()
    if latest_end is None:
        return []
    stmt = (
        select(TopEntry)
        .where(TopEntry.tenant_id == tenant_id, TopEntry.kind == kind, TopEntry.period_end == latest_end)
        .order_by(TopEntry.rank)
        .limit(limit)
    )
    return list(session.execute(stmt).scalars())


def top_entries_for_period(session: Session, tenant_id: int, kind: str, start_day: date, end_day: date, limit: int = 10) -> tuple[list[TopEntry], str]:
    """Exact lists for the period when they were collected, otherwise the latest trailing list.
    Returns the entries and a label describing which period they cover."""
    stmt = (
        select(TopEntry)
        .where(TopEntry.tenant_id == tenant_id, TopEntry.kind == kind, TopEntry.period_start == start_day, TopEntry.period_end == end_day)
        .order_by(TopEntry.rank)
        .limit(limit)
    )
    exact = list(session.execute(stmt).scalars())
    if exact:
        return exact, f"{start_day:%Y-%m-%d} – {end_day:%Y-%m-%d}"
    latest = latest_top_entries(session, tenant_id, kind, limit)
    if latest:
        return latest, f"trailing 30 days to {latest[0].period_end:%Y-%m-%d}"
    return [], ""


def convicted_messages(
    session: Session,
    tenant_id: int,
    start: datetime,
    end: datetime,
    *,
    directions: list[str] | None = None,
    verdicts: list[str] | None = None,
    limit: int | None = None,
) -> list[ConvictedMessage]:
    stmt = select(ConvictedMessage).where(
        ConvictedMessage.tenant_id == tenant_id,
        ConvictedMessage.timestamp >= start,
        ConvictedMessage.timestamp < end,
    )
    if directions:
        stmt = stmt.where(ConvictedMessage.direction.in_(directions))
    if verdicts:
        stmt = stmt.where(ConvictedMessage.verdict.in_(verdicts))
    stmt = stmt.order_by(ConvictedMessage.timestamp.desc())
    if limit:
        stmt = stmt.limit(limit)
    return list(session.execute(stmt).scalars())


def tenant_by_id(session: Session, tenant_id: int) -> Tenant | None:
    return session.get(Tenant, tenant_id)


# ------------------------------------------------------------- cross-tenant
def enabled_tenants(session: Session) -> list[Tenant]:
    return list(session.execute(select(Tenant).where(Tenant.enabled.is_(True)).order_by(Tenant.name)).scalars())


def stat_totals_all_tenants(session: Session, start_day: date, end_day: date) -> dict[int, StatTotals]:
    """Totals per tenant id. Only the cross-tenant roll-up may call this."""
    stmt = select(DailyStat).where(DailyStat.day >= start_day, DailyStat.day <= end_day)
    grouped: dict[int, list[DailyStat]] = {}
    for row in session.execute(stmt).scalars():
        grouped.setdefault(row.tenant_id, []).append(row)
    return {tid: _totals_from_rows(rows) for tid, rows in grouped.items()}
