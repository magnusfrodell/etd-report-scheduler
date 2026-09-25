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
"""Executive summary: everything on the built-in Trends/Impact pages, plus
period-over-period deltas and a daily series - the parts ETD never shows."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.base import ReportContext
from app.reports.periods import pct_change

VERDICT_ORDER = ("bec", "scam", "phishing", "malicious", "spam", "graymail")
DIRECTION_ORDER = ("incoming", "outgoing", "internal")


def _delta_row(label: str, current: int, previous: int) -> dict[str, Any]:
    return {"label": label, "current": current, "previous": previous, "delta": current - previous, "pct": pct_change(current, previous)}


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "executive_summary is a per-tenant report"
    p = ctx.period
    tid = ctx.tenant.id

    current = repo.stat_totals(session, tid, p.start_day, p.end_day)
    previous = repo.stat_totals(session, tid, p.previous_start_day, p.previous_end_day)
    series = repo.daily_stats(session, tid, p.start_day, p.end_day)

    verdict_rows = [_delta_row(v, getattr(current, v), getattr(previous, v)) for v in VERDICT_ORDER]
    direction_rows = [_delta_row(d, getattr(current, d), getattr(previous, d)) for d in DIRECTION_ORDER]

    headline = [
        _delta_row(tr("Messages scanned"), current.total_messages, previous.total_messages),
        _delta_row(tr("Threats caught"), current.threats, previous.threats),
        _delta_row(tr("Unwanted (spam + graymail)"), current.unwanted, previous.unwanted),
        _delta_row(tr("Retrospective verdicts"), current.retro_verdicts, previous.retro_verdicts),
    ]

    days_in_period = max(1, current.days_with_data or p.days)
    projections = {
        "threats_per_year": round(current.threats / days_in_period * 365),
        "unwanted_per_year": round(current.unwanted / days_in_period * 365),
    }

    top_targets, top_period = repo.top_entries_for_period(session, tid, "targets", p.start_day, p.end_day)
    top_senders, _ = repo.top_entries_for_period(session, tid, "threatSenders", p.start_day, p.end_day)

    max_threats = max((r.threats for r in series), default=0) or 1
    daily = [
        {
            "day": r.day.isoformat(),
            "total": r.total_messages,
            "threats": r.threats,
            "unwanted": r.unwanted,
            "bar_pct": round(r.threats / max_threats * 100),
        }
        for r in series
    ]

    return {
        "headline": headline,
        "verdict_rows": verdict_rows,
        "direction_rows": direction_rows,
        "current": current.as_dict(),
        "previous": previous.as_dict(),
        "projections": projections,
        "daily": daily,
        "top_targets": top_targets,
        "top_senders": top_senders,
        "top_period": top_period,
        "coverage_note": (
            None
            if current.days_with_data >= p.days
            else tr("Statistics exist for {days_with_data} of {days} days in this period.", days_with_data=current.days_with_data, days=p.days)
        ),
    }
