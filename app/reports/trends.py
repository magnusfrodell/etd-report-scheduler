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
"""Trends over time: twelve months of threat rate, verdict mix, retrospective verdicts, dwell time and
remediation per tenant, techniques on the rise and in decline - and the same trend across tenants.

Rates are per 10 000 messages, so a busier month is not a worse one. A month with less than 80 % of its
days collected is shown but never compared: a gap in collection must not look like an improvement."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ConvictedMessage, DailyStat
from app.reports.analysis import by_count, fmt_hours, hours_between, percentile, technique_types
from app.reports.base import ReportContext
from app.reports.repo import STAT_FIELDS, StatTotals
from app.settings_store import THREAT_VERDICTS

WINDOW = 12  # months shown
COMPARE = 3  # months compared with the three before
FULL = 0.8  # share of a month's days that must be collected for it to count in a comparison
MIN_TECHNIQUE = 3  # a technique must be seen this often to be called rising or falling
BLOCKS = "▁▂▃▄▅▆▇█"


@dataclass
class MonthData:
    start: date
    end: date  # the last day that belongs to the report (the period may end mid-month)
    stats: StatTotals = field(default_factory=StatTotals)
    messages: list[ConvictedMessage] = field(default_factory=list)

    @property
    def expected_days(self) -> int:
        return (self.end - self.start).days + 1

    @property
    def complete(self) -> bool:
        return self.stats.days_with_data >= FULL * self.expected_days


def months_ending(end_day: date, count: int) -> list[tuple[date, date]]:
    """``count`` calendar months ending with the month of ``end_day``; the last one ends on ``end_day``."""
    first = end_day.replace(day=1)
    out = []
    for i in range(count):
        nxt = (first.replace(day=28) + timedelta(days=4)).replace(day=1)
        out.append((first, end_day if i == 0 else nxt - timedelta(days=1)))
        first = (first - timedelta(days=1)).replace(day=1)
    return list(reversed(out))


def monthly_stats(session: Session, start_day: date, end_day: date, tenant_ids: list[int]) -> dict[tuple[int, date], StatTotals]:
    """Daily statistics summed per tenant and month, in one query."""
    out: dict[tuple[int, date], StatTotals] = {}
    if not tenant_ids:
        return out
    columns = [getattr(DailyStat, f) for f in STAT_FIELDS]
    rows = session.execute(select(DailyStat.tenant_id, DailyStat.day, *columns)
                           .where(DailyStat.tenant_id.in_(tenant_ids), DailyStat.day >= start_day, DailyStat.day <= end_day))
    for row in rows:
        key = (row[0], row[1].replace(day=1))
        totals = out.setdefault(key, StatTotals())
        for i, name in enumerate(STAT_FIELDS):
            setattr(totals, name, getattr(totals, name) + (row[2 + i] or 0))
        totals.days_with_data += 1
    return out


def _per_10k(threats: int, messages: int) -> float | None:
    return round(threats / messages * 10000, 1) if messages else None


def _window(months: list[MonthData]) -> dict[str, Any] | None:
    """Rates for a run of months, from its complete months only - None when fewer than two are complete."""
    usable = [m for m in months if m.complete]
    if len(usable) < 2:
        return None
    messages = sum(m.stats.total_messages for m in usable)
    threats = sum(m.stats.threats for m in usable)
    convicted = [msg for m in usable for msg in m.messages]
    retro = [msg for msg in convicted if msg.is_retro_verdict]
    dwell = [h for msg in retro if msg.action_timestamp and (h := hours_between(msg.timestamp, msg.action_timestamp)) is not None]
    return {"per_10k": _per_10k(threats, messages), "threats": threats, "messages": messages,
            "retro_share": round(len(retro) / len(convicted) * 100, 1) if convicted else None,
            "dwell_hours": percentile(dwell, 0.5) if dwell else None, "months": len(usable)}


def _change(now: float | None, before: float | None) -> float | None:
    if now is None or before is None or before == 0:
        return None
    return round((now - before) / before * 100, 1)


def sparkline(values: list[float | None]) -> str:
    """Twelve months as block characters - they survive every mail client, unlike SVG. · is a month without
    complete data."""
    known = [v for v in values if v is not None]
    if not known:
        return "·" * len(values)
    low, high = min(known), max(known)
    out = []
    for v in values:
        if v is None:
            out.append("·")
        elif high == low:
            out.append(BLOCKS[3])
        else:
            out.append(BLOCKS[round((v - low) / (high - low) * (len(BLOCKS) - 1))])
    return "".join(out)


def _load(session: Session, tenant_id: int, end_day: date, count: int) -> list[MonthData]:
    spans = months_ending(end_day, count)
    stats = monthly_stats(session, spans[0][0], end_day, [tenant_id])
    months = [MonthData(start, end, stats.get((tenant_id, start), StatTotals())) for start, end in spans]
    start_dt = datetime.combine(spans[0][0], time.min, tzinfo=UTC)
    end_dt = datetime.combine(end_day + timedelta(days=1), time.min, tzinfo=UTC)
    rows = session.execute(select(ConvictedMessage).where(
        ConvictedMessage.tenant_id == tenant_id, ConvictedMessage.timestamp >= start_dt, ConvictedMessage.timestamp < end_dt,
        ConvictedMessage.verdict.in_(THREAT_VERDICTS))).scalars()
    by_month = {m.start: m for m in months}
    for msg in rows:
        ts = msg.timestamp if msg.timestamp.tzinfo else msg.timestamp.replace(tzinfo=UTC)
        month = by_month.get(ts.date().replace(day=1))
        if month is not None:
            month.messages.append(msg)
    return months


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "trends is a per-tenant report"
    end_day = ctx.period.end_day
    months = _load(session, ctx.tenant.id, end_day, WINDOW)
    rows = []
    for m in months:
        t = m.stats
        retro = [msg for msg in m.messages if msg.is_retro_verdict]
        dwell = [h for msg in retro if msg.action_timestamp and (h := hours_between(msg.timestamp, msg.action_timestamp)) is not None]
        remediated = [msg for msg in m.messages if msg.action_timestamp]
        rows.append({
            "month": tr.short_month(m.start), "messages": t.total_messages, "threats": t.threats, "bec": t.bec, "phishing": t.phishing,
            "malicious": t.malicious, "scam": t.scam, "unwanted": t.unwanted, "per_10k": _per_10k(t.threats, t.total_messages),
            "retro_share": round(len(retro) / len(m.messages) * 100, 1) if m.messages else None,
            "dwell": fmt_hours(percentile(dwell, 0.5)) if dwell else "–",
            "auto_share": round(sum(1 for msg in remediated if msg.is_auto_remediated) / len(remediated) * 100, 1) if remediated else None,
            "days": t.days_with_data, "expected": m.expected_days, "complete": m.complete, "has_data": t.days_with_data > 0,
        })
    top_rate = max((r["per_10k"] or 0 for r in rows), default=0) or 1
    for r in rows:
        r["bar_pct"] = round((r["per_10k"] or 0) / top_rate * 100)

    now, before = _window(months[-COMPARE:]), _window(months[-2 * COMPARE:-COMPARE])
    rate_change = _change(now and now["per_10k"], before and before["per_10k"])
    retro_points = (round(now["retro_share"] - before["retro_share"], 1)
                    if now and before and now["retro_share"] is not None and before["retro_share"] is not None else None)

    # techniques: the last three months against the three before, and what is new against the nine before
    counts_now = Counter(t for m in months[-COMPARE:] for msg in m.messages for t in set(technique_types(msg)))
    counts_before = Counter(t for m in months[-2 * COMPARE:-COMPARE] for msg in m.messages for t in set(technique_types(msg)))
    seen_earlier = {t for m in months[:-COMPARE] for msg in m.messages for t in technique_types(msg)}
    # Only when both periods have usable data: a technique is not "rising" against months that were never collected.
    rising: list[dict[str, Any]] = []
    falling: list[dict[str, Any]] = []
    new: list[str] = []
    if now is not None and before is not None:
        rising = [{"technique": t, "now": n, "before": counts_before.get(t, 0)} for t, n in by_count(counts_now)
                  if n >= MIN_TECHNIQUE and n > counts_before.get(t, 0)]
        rising.sort(key=lambda r: (-(r["now"] - r["before"]), r["technique"]))
        falling = [{"technique": t, "now": counts_now.get(t, 0), "before": n} for t, n in by_count(counts_before)
                   if n >= MIN_TECHNIQUE and counts_now.get(t, 0) < n]
        falling.sort(key=lambda r: (-(r["before"] - r["now"]), r["technique"]))
        new = sorted(t for t in counts_now if t not in seen_earlier)

    # the latest month against the same month a year earlier
    last = months[-1]
    year_ago_start = last.start.replace(year=last.start.year - 1)
    year_ago = _load(session, ctx.tenant.id, (year_ago_start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1), 1)[0]
    yoy = None
    if last.complete and year_ago.complete:
        yoy = {"month": tr.short_month(last.start), "now": _per_10k(last.stats.threats, last.stats.total_messages),
               "year_ago_month": tr.short_month(year_ago.start), "before": _per_10k(year_ago.stats.threats, year_ago.stats.total_messages)}

    incomplete = sum(1 for m in months if m.stats.days_with_data and not m.complete)
    insights = []
    if rate_change is not None and abs(rate_change) >= 20:
        values = {"change": abs(rate_change), "now": now["per_10k"], "before": before["per_10k"]}
        insights.append(tr("The threat rate is {change} % higher than in the three months before: {now} against {before} threats per 10 000 messages.",
                           **values) if rate_change > 0 else
                        tr("The threat rate is {change} % lower than in the three months before: {now} against {before} threats per 10 000 messages.",
                           **values))
    if yoy and yoy["now"] is not None and yoy["before"] is not None:
        insights.append(tr("{month}: {now} threats per 10 000 messages, against {before} in {year_ago_month}.", **yoy))
    if retro_points is not None and retro_points >= 5:
        insights.append(tr("More threats are caught only after delivery: {now} % were convicted retrospectively, against {before} % in the three "
                           "months before - make sure retrospective verdicts trigger automatic remediation.",
                           now=now["retro_share"], before=before["retro_share"]))
    if now and before and now["dwell_hours"] and before["dwell_hours"] and now["dwell_hours"] >= 1.25 * before["dwell_hours"]:
        insights.append(tr("Retro-convicted mail stays longer in inboxes: median {now} against {before} in the three months before.",
                           now=fmt_hours(now["dwell_hours"]), before=fmt_hours(before["dwell_hours"])))
    if rising:
        insights.append(tr("{technique} is on the rise: {now} threats in the last three months against {before} before.", **rising[0]))
    if incomplete:
        insights.append(tr("{count} month(s) have less than 80 % of their days collected; they are marked and left out of the comparisons.",
                           count=incomplete))
    if now is None or before is None:
        insights.append(tr("There is not yet enough history for comparisons (six months with data). ETD provided 90 days back when the tenant "
                           "was added, and the tool keeps collecting."))

    return {
        "rows": rows, "months_with_data": sum(1 for r in rows if r["has_data"]),
        "now": now, "before": before, "rate_change": rate_change, "retro_points": retro_points,
        "threats_12m": sum(r["threats"] for r in rows), "rising": rising[:5], "falling": falling[:5], "new_techniques": new[:10],
        "insights": insights, "first_month": rows[0]["month"], "last_month": rows[-1]["month"],
        "dwell_now": fmt_hours(now["dwell_hours"]) if now and now["dwell_hours"] else None,
        "dwell_before": fmt_hours(before["dwell_hours"]) if before and before["dwell_hours"] else None,
    }


def build_all(session: Session, ctx: ReportContext) -> dict[str, Any]:
    """The trend of every tenant side by side, largest increase first, and the whole fleet month by month."""
    tr = ctx.tr
    end_day = ctx.period.end_day
    spans = months_ending(end_day, WINDOW)
    stats = monthly_stats(session, spans[0][0], end_day, [t.id for t in ctx.tenants])
    fleet = {start: StatTotals() for start, _end in spans}
    rows = []
    for tenant in ctx.tenants:
        months = [MonthData(start, end, stats.get((tenant.id, start), StatTotals())) for start, end in spans]
        for m in months:
            for name in STAT_FIELDS:
                setattr(fleet[m.start], name, getattr(fleet[m.start], name) + getattr(m.stats, name))
            fleet[m.start].days_with_data = max(fleet[m.start].days_with_data, m.stats.days_with_data)
        rates = [_per_10k(m.stats.threats, m.stats.total_messages) if m.complete else None for m in months]
        now, before = _window(months[-COMPARE:]), _window(months[-2 * COMPARE:-COMPARE])
        rows.append({"tenant": tenant.name, "spark": sparkline(rates), "now": now["per_10k"] if now else None,
                     "change": _change(now and now["per_10k"], before and before["per_10k"]),
                     "threats_12m": sum(m.stats.threats for m in months), "months": sum(1 for m in months if m.complete)})
    rows.sort(key=lambda r: (r["change"] is None, -(r["change"] or 0), r["tenant"]))
    fleet_rows = []
    for start, end in spans:
        t = fleet[start]
        fleet_rows.append({"month": tr.short_month(start), "messages": t.total_messages, "threats": t.threats,
                           "per_10k": _per_10k(t.threats, t.total_messages),
                           "partial": 0 < t.days_with_data < FULL * ((end - start).days + 1)})
    top_rate = max((r["per_10k"] or 0 for r in fleet_rows), default=0) or 1
    for r in fleet_rows:
        r["bar_pct"] = round((r["per_10k"] or 0) / top_rate * 100)
    rising = [r for r in rows if r["change"] is not None and r["change"] >= 20]
    fleet_months = [MonthData(start, end, fleet[start]) for start, end in spans]
    fleet_now, fleet_before = _window(fleet_months[-COMPARE:]), _window(fleet_months[-2 * COMPARE:-COMPARE])
    return {"rows": rows, "fleet": fleet_rows, "rising": rising, "tenants": len(rows),
            "fleet_now": fleet_now["per_10k"] if fleet_now else None,
            "fleet_change": _change(fleet_now and fleet_now["per_10k"], fleet_before and fleet_before["per_10k"]),
            "first_month": fleet_rows[0]["month"], "last_month": fleet_rows[-1]["month"]}
