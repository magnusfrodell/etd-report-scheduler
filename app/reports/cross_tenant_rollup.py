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
"""Cross-tenant roll-up.

The only report allowed to read across tenants. Ranks every enabled tenant
by threats, shows period-over-period change and flags tenants whose threat
count spiked.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.base import ReportContext
from app.reports.periods import pct_change
from app.reports.repo import StatTotals

SPIKE_FACTOR = 2.0


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    p = ctx.period
    tenants = ctx.tenants or repo.enabled_tenants(session)
    current = repo.stat_totals_all_tenants(session, p.start_day, p.end_day)
    previous = repo.stat_totals_all_tenants(session, p.previous_start_day, p.previous_end_day)

    rows: list[dict[str, Any]] = []
    grand = StatTotals()
    for tenant in tenants:
        cur = current.get(tenant.id, StatTotals())
        prev = previous.get(tenant.id, StatTotals())
        for f in repo.STAT_FIELDS:
            setattr(grand, f, getattr(grand, f) + getattr(cur, f))
        spike = prev.threats > 0 and cur.threats >= SPIKE_FACTOR * prev.threats and cur.threats >= 10
        rows.append(
            {
                "tenant": tenant.name,
                "region": tenant.region,
                "total": cur.total_messages,
                "threats": cur.threats,
                "previous_threats": prev.threats,
                "threat_pct": pct_change(cur.threats, prev.threats),
                "threat_rate_pct": cur.threat_rate_pct,
                "unwanted": cur.unwanted,
                "retro": cur.retro_verdicts,
                "bec": cur.bec,
                "scam": cur.scam,
                "phishing": cur.phishing,
                "malicious": cur.malicious,
                "days_with_data": cur.days_with_data,
                "spike": spike,
                "last_error": tenant.last_error,
            }
        )
    rows.sort(key=lambda r: (-r["threats"], r["tenant"]))
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank

    return {
        "rows": rows,
        "tenant_count": len(rows),
        "grand": grand.as_dict(),
        "spikes": [r for r in rows if r["spike"]],
        "errors": [r for r in rows if r["last_error"]],
        "missing_data": [r for r in rows if r["days_with_data"] < p.days],
    }
