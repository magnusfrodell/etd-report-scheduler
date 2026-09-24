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
"""Campaign clusters.

Groups the period's convicted messages into campaigns (shared normalised
subject + sender domain, URL host or attachment hash) and ranks them by how
many mailboxes they reached. Shows what ETD's message list cannot: that 63
messages were one campaign, and that two of them are still in inboxes.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.analysis import cluster_campaigns
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS

TOP_N = 20
SAMPLE_MESSAGES = 5


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    assert ctx.tenant is not None, "campaigns is a per-tenant report"
    p = ctx.period
    messages = repo.convicted_messages(session, ctx.tenant.id, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    previous = repo.convicted_messages(session, ctx.tenant.id, p.previous_start, p.previous_end, verdicts=list(THREAT_VERDICTS))
    campaigns, singletons = cluster_campaigns(messages, min_size=2)
    prev_campaigns, _ = cluster_campaigns(previous, min_size=2)

    rows = []
    for i, c in enumerate(campaigns[:TOP_N], start=1):
        rows.append(
            {
                "rank": i,
                "label": c.label[:120],
                "messages": len(c.messages),
                "recipients": len(c.recipients),
                "sender_domains": c.sender_domains,
                "verdicts": c.verdicts,
                "techniques": c.techniques,
                "url_hosts": c.url_hosts,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "days_active": c.days_active,
                "auto_remediated": c.auto_remediated,
                "not_remediated": c.not_remediated,
                "retro": c.retro,
                "severity": c.severity,
                "samples": [
                    {"timestamp": m.timestamp, "from": m.from_address or m.envelope_from, "subject": m.subject, "verdict": m.verdict, "action": m.action_type}
                    for m in sorted(c.messages, key=lambda m: m.timestamp)[:SAMPLE_MESSAGES]
                ],
            }
        )
    in_campaigns = sum(len(c.messages) for c in campaigns)
    return {
        "rows": rows,
        "campaign_count": len(campaigns),
        "previous_campaign_count": len(prev_campaigns),
        "total_threats": len(messages),
        "in_campaigns": in_campaigns,
        "singletons": singletons,
        "campaign_share": round(in_campaigns / len(messages) * 100) if messages else 0,
        "still_exposed": sum(c.not_remediated for c in campaigns),
        "critical": [r for r in rows if r["severity"] == "critical"],
        "truncated": len(campaigns) > TOP_N,
    }
