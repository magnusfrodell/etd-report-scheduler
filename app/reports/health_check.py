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
"""Health check.

Compares yesterday's scanned volume with the trailing 30-day average.
Volume near zero means a broken journal rule or connector - something ETD
itself does not alert on. Also surfaces collector errors and threat spikes.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.base import ReportContext

BASELINE_DAYS = 30
WARN_RATIO = 0.5
CRITICAL_RATIO = 0.1
SPIKE_FACTOR = 3.0


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    assert ctx.tenant is not None, "health_check is a per-tenant report"
    p = ctx.period
    tenant = ctx.tenant

    day_rows = repo.daily_stats(session, tenant.id, p.start_day, p.end_day)
    today_total = sum(r.total_messages for r in day_rows)
    today_threats = sum(r.threats for r in day_rows)

    baseline_end = p.start_day - timedelta(days=1)
    baseline_start = baseline_end - timedelta(days=BASELINE_DAYS - 1)
    baseline_rows = [r for r in repo.daily_stats(session, tenant.id, baseline_start, baseline_end) if r.total_messages > 0]
    baseline_avg = sum(r.total_messages for r in baseline_rows) / len(baseline_rows) if baseline_rows else 0.0
    baseline_threat_avg = sum(r.threats for r in baseline_rows) / len(baseline_rows) if baseline_rows else 0.0

    checks: list[dict[str, Any]] = []

    if not day_rows:
        checks.append({"name": "Statistics collected", "status": "critical", "detail": "No statistics stored for the period - collector has not run or failed."})
    else:
        checks.append({"name": "Statistics collected", "status": "ok", "detail": f"{len(day_rows)} day(s) of data present."})

    if baseline_avg > 0 and day_rows:
        ratio = today_total / baseline_avg
        if ratio <= CRITICAL_RATIO:
            status, detail = "critical", f"Volume {today_total} is {ratio:.0%} of the 30-day average ({baseline_avg:.0f}). Check journaling/connector."
        elif ratio <= WARN_RATIO:
            status, detail = "warning", f"Volume {today_total} is {ratio:.0%} of the 30-day average ({baseline_avg:.0f})."
        else:
            status, detail = "ok", f"Volume {today_total} vs 30-day average {baseline_avg:.0f} ({ratio:.0%})."
        checks.append({"name": "Message volume", "status": status, "detail": detail})
    elif day_rows:
        checks.append({"name": "Message volume", "status": "ok", "detail": f"Volume {today_total}; no baseline yet (fewer than one day of history)."})

    if baseline_threat_avg > 0 and today_threats >= SPIKE_FACTOR * baseline_threat_avg and today_threats >= 5:
        checks.append({"name": "Threat spike", "status": "warning", "detail": f"{today_threats} threats vs 30-day average {baseline_threat_avg:.1f} - possible campaign."})
    else:
        checks.append({"name": "Threat spike", "status": "ok", "detail": f"{today_threats} threats vs 30-day average {baseline_threat_avg:.1f}."})

    if tenant.last_error:
        checks.append({"name": "Collector errors", "status": "warning", "detail": f"{tenant.last_error} (at {tenant.last_error_at:%Y-%m-%d %H:%M} UTC)"})
    else:
        checks.append({"name": "Collector errors", "status": "ok", "detail": "No errors recorded."})

    order = {"critical": 0, "warning": 1, "ok": 2}
    overall = min((c["status"] for c in checks), key=lambda s: order[s])
    return {
        "checks": checks,
        "overall": overall,
        "today_total": today_total,
        "today_threats": today_threats,
        "baseline_avg": round(baseline_avg),
        "baseline_days": len(baseline_rows),
        "stats_collected_at": tenant.stats_collected_at,
        "convictions_collected_at": tenant.convictions_collected_at,
    }
