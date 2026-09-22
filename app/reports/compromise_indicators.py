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
"""Compromise indicators.

Threat verdicts on *outgoing* or *internal* mail almost always mean a
compromised account or an infected client. ETD shows internal threat senders
on the Impact Report but never pushes them to anyone; this report does,
daily, grouped by sender.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.reports import repo
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS

DIRECTIONS = ["outgoing", "internal"]
MAX_MESSAGES = 200


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    assert ctx.tenant is not None, "compromise_indicators is a per-tenant report"
    p = ctx.period
    messages = repo.convicted_messages(
        session, ctx.tenant.id, p.start, p.end, directions=DIRECTIONS, verdicts=list(THREAT_VERDICTS)
    )
    previous = repo.convicted_messages(
        session, ctx.tenant.id, p.previous_start, p.previous_end, directions=DIRECTIONS, verdicts=list(THREAT_VERDICTS)
    )

    by_sender: dict[str, dict[str, Any]] = {}
    for m in messages:
        sender = (m.from_address or m.envelope_from or "(unknown sender)").lower()
        entry = by_sender.setdefault(
            sender,
            {
                "sender": sender,
                "count": 0,
                "recipients": set(),
                "verdicts": defaultdict(int),
                "directions": defaultdict(int),
                "first_seen": m.timestamp,
                "last_seen": m.timestamp,
                "auto_remediated": 0,
                "not_remediated": 0,
            },
        )
        entry["count"] += 1
        for rcpt in (m.to_addresses or []) + (m.mailboxes or []):
            entry["recipients"].add(str(rcpt).lower())
        entry["verdicts"][m.verdict or "unknown"] += 1
        entry["directions"][m.direction or "unknown"] += 1
        entry["first_seen"] = min(entry["first_seen"], m.timestamp)
        entry["last_seen"] = max(entry["last_seen"], m.timestamp)
        if m.is_auto_remediated:
            entry["auto_remediated"] += 1
        elif not m.action_type:
            entry["not_remediated"] += 1

    senders = []
    for entry in sorted(by_sender.values(), key=lambda e: (-e["count"], e["sender"])):
        senders.append(
            {
                **entry,
                "recipient_count": len(entry["recipients"]),
                "recipients": sorted(entry["recipients"])[:10],
                "verdicts": dict(entry["verdicts"]),
                "directions": dict(entry["directions"]),
            }
        )

    return {
        "total": len(messages),
        "previous_total": len(previous),
        "sender_count": len(senders),
        "senders": senders,
        "messages": messages[:MAX_MESSAGES],
        "truncated": len(messages) > MAX_MESSAGES,
        "severity": "critical" if any(s["count"] >= 5 for s in senders) else ("warning" if senders else "ok"),
    }
