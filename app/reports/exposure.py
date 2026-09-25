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
"""Exposure report: dwell time and delivered-but-not-remediated.

Risk rather than volume. For messages that were delivered before their verdict
(retrospective verdicts) it measures how long they sat in inboxes until the
verdict and until remediation; for every threat it lists what is still not
remediated, with age.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.models import utcnow
from app.reports import repo
from app.reports.analysis import fmt_hours, hours_between, percentile
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS

BUCKETS = [("< 1 h", 1), ("1–4 h", 4), ("4–24 h", 24), ("1–7 d", 168), ("> 7 d", float("inf"))]
MAX_LIST = 100


def _bucket(hours: float) -> str:
    for label, limit in BUCKETS:
        if hours < limit:
            return label
    return BUCKETS[-1][0]


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "median": fmt_hours(percentile(values, 0.5)),
        "p90": fmt_hours(percentile(values, 0.9)),
        "max": fmt_hours(max(values) if values else None),
        "within_1h_pct": round(sum(1 for v in values if v < 1) / len(values) * 100) if values else None,
        "within_24h_pct": round(sum(1 for v in values if v < 24) / len(values) * 100) if values else None,
    }


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "exposure is a per-tenant report"
    p = ctx.period
    now = ctx.generated_at or utcnow()
    messages = repo.convicted_messages(session, ctx.tenant.id, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    previous = repo.convicted_messages(session, ctx.tenant.id, p.previous_start, p.previous_end, verdicts=list(THREAT_VERDICTS))

    retro = [m for m in messages if m.is_retro_verdict]
    to_verdict = [h for h in (hours_between(m.timestamp, m.verdict_timestamp) for m in retro) if h is not None]
    to_action = [h for h in (hours_between(m.timestamp, m.action_timestamp) for m in retro if m.action_timestamp) if h is not None]
    buckets = Counter(_bucket(h) for h in to_action)
    by_verdict: dict[str, list[float]] = {}
    for m in retro:
        h = hours_between(m.timestamp, m.action_timestamp) if m.action_timestamp else None
        if h is not None:
            by_verdict.setdefault(m.verdict or "unknown", []).append(h)

    unremediated = sorted((m for m in messages if not m.action_type), key=lambda m: m.timestamp)
    manual = [m for m in messages if m.action_type and m.is_auto_remediated is False]
    exposed_rows = [
        {
            "timestamp": m.timestamp,
            "age": fmt_hours(hours_between(m.timestamp, now)),
            "age_hours": hours_between(m.timestamp, now) or 0,
            "from": m.from_address or m.envelope_from,
            "to": sorted({str(r) for r in (m.mailboxes or m.to_addresses or [])})[:5],
            "subject": m.subject,
            "verdict": m.verdict,
            "retro": m.is_retro_verdict,
            "rule": m.rule_type,
        }
        for m in unremediated[:MAX_LIST]
    ]
    retro_rows = [
        {
            "timestamp": m.timestamp,
            "to_verdict": fmt_hours(hours_between(m.timestamp, m.verdict_timestamp)),
            "to_action": fmt_hours(hours_between(m.timestamp, m.action_timestamp)) if m.action_timestamp else tr("not remediated"),
            "from": m.from_address or m.envelope_from,
            "recipients": len(set(m.mailboxes or m.to_addresses or [])),
            "subject": m.subject,
            "verdict": m.verdict,
            "original_verdict": m.original_verdict,
            "action": f"{m.action_type} → {m.action_folder}" if m.action_type else tr.pgettext("action", "none"),
        }
        for m in sorted(retro, key=lambda m: -(hours_between(m.timestamp, m.action_timestamp) or hours_between(m.timestamp, now) or 0))[:MAX_LIST]
    ]
    overall = "critical" if len(unremediated) >= 10 or any(r["age_hours"] > 168 for r in exposed_rows) else ("warning" if unremediated or retro else "ok")
    return {
        "total_threats": len(messages),
        "retro_count": len(retro),
        "retro_share": round(len(retro) / len(messages) * 100) if messages else 0,
        "previous_retro_count": sum(1 for m in previous if m.is_retro_verdict),
        "to_verdict": _summary(to_verdict),
        "to_action": _summary(to_action),
        "buckets": [(label, buckets.get(label, 0)) for label, _ in BUCKETS],
        "by_verdict": {v: _summary(h) for v, h in sorted(by_verdict.items())},
        "unremediated_count": len(unremediated),
        "previous_unremediated_count": sum(1 for m in previous if not m.action_type),
        "manual_count": len(manual),
        "auto_count": sum(1 for m in messages if m.is_auto_remediated),
        "exposed": exposed_rows,
        "retro_rows": retro_rows,
        "truncated_exposed": len(unremediated) > MAX_LIST,
        "truncated_retro": len(retro) > MAX_LIST,
        "overall": overall,
    }
