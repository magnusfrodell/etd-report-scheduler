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
"""Per-tenant reporting profile, stored in ``tenants.profile`` (JSON).

own_domains     the organisation's domains (blank = auto-detected from outgoing mail and recipients)
vendor_domains  suppliers and partners watched for compromise and look-alikes
vip_addresses   mailboxes flagged in the Very Attacked People report (added to the global list)
user_labels     names for ETD user ids - the audit log only records UUIDs
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ConvictedMessage, SenderDomainDaily, Tenant, utcnow
from app.reports.domains import FREEMAIL, registrable

_DOMAIN = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z0-9-]{2,}$")


def _tokens(text: str) -> list[str]:
    return [t.strip().strip("<>\"'").lower() for t in re.split(r"[\s,;]+", text or "") if t.strip()]


def parse_domains(text: str) -> tuple[list[str], list[str]]:
    ok: list[str] = []
    bad: list[str] = []
    for t in _tokens(text):
        t = t.split("@")[-1].strip(".")
        (ok if _DOMAIN.match(t) else bad).append(t)
    return list(dict.fromkeys(ok)), bad


def parse_addresses(text: str) -> tuple[list[str], list[str]]:
    ok: list[str] = []
    bad: list[str] = []
    for t in _tokens(text):
        (ok if _ADDRESS.match(t) else bad).append(t)
    return list(dict.fromkeys(ok)), bad


def parse_labels(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        sep = "=" if "=" in line else (":" if ":" in line else None)
        if not sep:
            continue
        key, _, value = line.partition(sep)
        if key.strip() and value.strip():
            out[key.strip()] = value.strip()[:80]
    return out


def get_profile(tenant: Tenant | None) -> dict[str, Any]:
    raw = tenant.profile if tenant is not None and isinstance(tenant.profile, dict) else {}
    return {
        "own_domains": list(raw.get("own_domains") or []),
        "vendor_domains": list(raw.get("vendor_domains") or []),
        "vip_addresses": list(raw.get("vip_addresses") or []),
        "user_labels": dict(raw.get("user_labels") or {}),
    }


def auto_own_domains(session: Session, tenant: Tenant, limit: int = 10) -> list[str]:
    """Outgoing sender domains (Log Export) first, then recipient domains of convicted mail."""
    since = (utcnow() - timedelta(days=60)).date()
    total = func.sum(SenderDomainDaily.messages)
    rows = session.execute(
        select(SenderDomainDaily.domain, total)
        .where(SenderDomainDaily.tenant_id == tenant.id, SenderDomainDaily.direction == "outgoing", SenderDomainDaily.day >= since)
        .group_by(SenderDomainDaily.domain)
        .order_by(total.desc())
        .limit(limit * 3)
    ).all()
    out: list[str] = []
    for domain, _ in rows:
        reg = registrable(domain)
        if reg and reg not in FREEMAIL and reg not in out:
            out.append(reg)
    if len(out) < limit:
        counter: Counter[str] = Counter()
        boxes = session.execute(
            select(ConvictedMessage.mailboxes)
            .where(ConvictedMessage.tenant_id == tenant.id, ConvictedMessage.direction == "incoming")
            .order_by(ConvictedMessage.timestamp.desc())
            .limit(2000)
        ).scalars()
        for mailboxes in boxes:
            for address in mailboxes or []:
                if "@" in str(address):
                    counter[registrable(str(address).rsplit("@", 1)[1])] += 1
        for reg, _ in counter.most_common(5):
            if reg and reg not in FREEMAIL and reg not in out:
                out.append(reg)
    return out[:limit]


def own_domains(session: Session, tenant: Tenant) -> tuple[list[str], bool]:
    """(domains, auto_detected)"""
    configured = get_profile(tenant)["own_domains"]
    if configured:
        return configured, False
    return auto_own_domains(session, tenant), True


def user_label(labels: dict[str, str], user_id: str | None) -> str:
    if not user_id:
        return "system"
    if user_id in labels:
        return labels[user_id]
    return user_id[:8] + "…" if len(user_id) > 12 else user_id
