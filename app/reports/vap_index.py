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
"""Very Attacked People (VAP) index.

Per-mailbox attack index built from the threat messages that reached each
recipient in the period: verdict weight, technique severity, impersonation,
retro delivery, missing remediation and how targeted the message was. The
index is comparable across periods and tenants, so the report also shows rank
movement against the previous period and how concentrated the attacks are.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.analysis import (
    MASS_MIN_RECIPIENTS,
    TARGETED_MAX_RECIPIENTS,
    attack_score,
    by_count,
    cluster_campaigns,
    recipients_of,
    technique_types,
)
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS, load_settings
from app.tenant_profile import get_profile

TOP_N = 25


def _index_for(messages) -> dict[str, dict[str, Any]]:
    people: dict[str, dict[str, Any]] = {}
    campaigns, _ = cluster_campaigns(messages, min_size=1)
    campaign_of = {id(m): c.key for c in campaigns for m in c.messages}
    for m in messages:
        points, reasons = attack_score(m)
        for rcpt in recipients_of(m):
            p = people.setdefault(
                rcpt,
                {"mailbox": rcpt, "score": 0.0, "messages": 0, "verdicts": Counter(), "techniques": Counter(), "reasons": Counter(),
                 "campaigns": set(), "retro": 0, "unremediated": 0, "first_seen": m.timestamp, "last_seen": m.timestamp},
            )
            p["score"] += points
            p["messages"] += 1
            p["verdicts"][m.verdict or "unknown"] += 1
            p["techniques"].update(set(technique_types(m)))
            p["reasons"].update(r for r in reasons if r not in THREAT_VERDICTS)
            p["campaigns"].add(campaign_of.get(id(m)))
            p["retro"] += 1 if m.is_retro_verdict else 0
            p["unremediated"] += 0 if m.action_type else 1
            p["first_seen"] = min(p["first_seen"], m.timestamp)
            p["last_seen"] = max(p["last_seen"], m.timestamp)
    for p in people.values():
        p["index"] = min(1000, int(round(p["score"])))
    return people


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "vap_index is a per-tenant report"
    p = ctx.period
    tid = ctx.tenant.id
    settings = load_settings(session)
    vips = {v.strip().lower() for v in settings.vip_addresses.replace(";", ",").split(",") if v.strip()}
    vips |= {v.lower() for v in get_profile(ctx.tenant)["vip_addresses"]}

    current_msgs = repo.convicted_messages(session, tid, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    previous_msgs = repo.convicted_messages(session, tid, p.previous_start, p.previous_end, verdicts=list(THREAT_VERDICTS))
    current = _index_for(current_msgs)
    previous = _index_for(previous_msgs)
    prev_rank = {mb: i + 1 for i, mb in enumerate(sorted(previous, key=lambda k: -previous[k]["score"]))}

    ranked = sorted(current.values(), key=lambda e: (-e["score"], e["mailbox"]))
    total_threats = len(current_msgs)
    # Share of threat deliveries (message x recipient) that reached the ten most attacked mailboxes -
    # numerator and denominator in the same unit, so it cannot exceed 100 %.
    deliveries = sum(e["messages"] for e in ranked)
    top10_share = round(sum(e["messages"] for e in ranked[:10]) / deliveries * 100) if deliveries else 0

    rows = []
    for i, e in enumerate(ranked[:TOP_N], start=1):
        pr = prev_rank.get(e["mailbox"])
        rows.append(
            {
                "rank": i,
                "mailbox": e["mailbox"],
                "vip": e["mailbox"] in vips,
                "index": e["index"],
                "previous_index": previous[e["mailbox"]]["index"] if e["mailbox"] in previous else None,
                "movement": "new" if pr is None else ("up" if pr > i else ("down" if pr < i else "same")),
                "previous_rank": pr,
                "messages": e["messages"],
                "verdicts": dict(e["verdicts"]),
                "techniques": [t for t, _ in by_count(e["techniques"], 3)],
                "reasons": [r for r, _ in by_count(e["reasons"], 6)],
                "campaigns": len(e["campaigns"]),
                "retro": e["retro"],
                "unremediated": e["unremediated"],
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
            }
        )

    attacked_vips = [r for r in rows if r["vip"]] + [
        {"rank": None, "mailbox": mb, "vip": True, "index": current[mb]["index"], "messages": current[mb]["messages"], "unremediated": current[mb]["unremediated"], "retro": current[mb]["retro"], "campaigns": len(current[mb]["campaigns"]), "verdicts": dict(current[mb]["verdicts"]), "techniques": [], "reasons": [], "movement": "", "previous_rank": None, "previous_index": None, "first_seen": current[mb]["first_seen"], "last_seen": current[mb]["last_seen"]}
        for mb in vips if mb in current and mb not in {r["mailbox"] for r in rows}
    ]
    technique_totals = Counter()
    for e in current.values():
        technique_totals.update(e["techniques"])
    return {
        "rows": rows,
        "people_count": len(current),
        "previous_people_count": len(previous),
        "total_threats": total_threats,
        "top10_share": top10_share,
        "attacked_vips": attacked_vips,
        "vip_count": len(vips),
        "with_unremediated": sum(1 for e in current.values() if e["unremediated"]),
        "technique_totals": by_count(technique_totals, 8),
        "scoring": {"bec": 10, "malicious": 8, "phishing": 6, "scam": 5, "severity": tr("+2/+4/+5 medium/high/critical"), "impersonation": "+4", "retro": "+3", "unremediated": "+5", "targeted": tr("×{factor} (≤{n} recipients)", factor=1.5, n=TARGETED_MAX_RECIPIENTS),
                    "mass": tr("×{factor} (≥{n} recipients)", factor=0.5, n=MASS_MIN_RECIPIENTS)},
    }
