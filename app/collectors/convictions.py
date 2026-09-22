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
"""Incremental collector for convicted messages.

Only the verdicts listed in the ``convictions_verdicts`` setting are pulled
(threats by default), which keeps volumes small enough to stay far inside
the 10 000 requests/day quota. Every run re-scans a trailing window
(``convictions_rescan_days``) so messages that received a retrospective
verdict after the previous run are picked up as well.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.etd.client import HISTORY_HORIZON_DAYS, ETDClient, parse_ts
from app.models import ConvictedMessage, Tenant, utcnow

log = logging.getLogger(__name__)


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def _as_list(value: Any) -> list[Any] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return value
    return [value]


def map_message(tenant_id: int, msg: dict[str, Any]) -> ConvictedMessage | None:
    """Map one Message Search result into a :class:`ConvictedMessage` (unsaved)."""
    etd_id = msg.get("id")
    ts = parse_ts(msg.get("timestamp"))
    if not etd_id or not ts:
        return None
    verdict = msg.get("verdict") or {}
    action = msg.get("action") or {}
    rule = msg.get("rule") or {}
    seg = msg.get("secureEmailGateway") or {}
    urls = msg.get("urls")
    if not urls and msg.get("urlMetadata"):
        urls = [u.get("url") if isinstance(u, dict) else u for u in msg.get("urlMetadata") or []]

    return ConvictedMessage(
        tenant_id=tenant_id,
        etd_id=str(etd_id),
        timestamp=ts,
        direction=msg.get("direction"),
        verdict=_first(verdict.get("verdict"), verdict.get("category"), verdict.get("originalVerdict")),
        original_verdict=verdict.get("originalVerdict"),
        is_retro_verdict=bool(verdict.get("isRetroVerdict")),
        verdict_timestamp=parse_ts(verdict.get("timestamp")),
        business_risk=verdict.get("businessRisk"),
        techniques=verdict.get("techniques"),
        rule_type=_first(verdict.get("ruleType"), rule.get("type")),
        from_address=_first(msg.get("fromAddress"), msg.get("fromAddresses")),
        envelope_from=_first(msg.get("envelopeFrom"), msg.get("returnPath")),
        to_addresses=_as_list(msg.get("toAddresses")),
        mailboxes=_as_list(msg.get("mailboxes")),
        subject=(msg.get("subject") or "")[:998] or None,
        urls=_as_list(urls),
        attachments=_as_list(msg.get("attachments")),
        secure_email_gateway=_first(seg.get("gatewayType"), seg.get("headerName")),
        action_type=_first(action.get("type"), action.get("action")),
        action_folder=action.get("folder"),
        action_timestamp=parse_ts(action.get("timestamp")),
        is_auto_remediated=(
            bool(action.get("isAutoRemediated"))
            if action.get("isAutoRemediated") is not None
            else (action.get("remediatedBy") == "automatic" if action.get("remediatedBy") else None)
        ),
        raw=msg,
    )


def upsert_message(session: Session, mapped: ConvictedMessage) -> bool:
    """Insert or update. Returns True when a new row was created."""
    existing = session.execute(
        select(ConvictedMessage).where(
            ConvictedMessage.tenant_id == mapped.tenant_id, ConvictedMessage.etd_id == mapped.etd_id
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(mapped)
        return True
    for column in ConvictedMessage.__table__.columns.keys():  # noqa: SIM118 - Table columns need .keys()
        if column in ("id", "tenant_id", "etd_id", "collected_at"):
            continue
        setattr(existing, column, getattr(mapped, column))
    existing.collected_at = utcnow()
    return False


def upsert_page(session: Session, tenant_id: int, page: list[dict[str, Any]]) -> tuple[int, int]:
    created = updated = 0
    for msg in page:
        mapped = map_message(tenant_id, msg)
        if mapped is None:
            continue
        if upsert_message(session, mapped):
            created += 1
        else:
            updated += 1
    return created, updated


def collect_convictions(
    session: Session,
    tenant: Tenant,
    client: ETDClient,
    *,
    verdicts: list[str],
    initial_days: int = 30,
    rescan_days: int = 7,
    now: datetime | None = None,
) -> dict[str, int]:
    now = now or utcnow()
    horizon = now - timedelta(days=HISTORY_HORIZON_DAYS - 1)
    if tenant.convictions_watermark:
        start = tenant.convictions_watermark - timedelta(days=rescan_days)
    else:
        start = now - timedelta(days=initial_days)
    start = max(start, horizon)

    created = updated = 0
    for page in client.iter_pages(start, now, verdicts=verdicts):
        c, u = upsert_page(session, tenant.id, page)
        created += c
        updated += u
        session.commit()  # one short transaction per API page

    tenant.convictions_watermark = now
    tenant.convictions_collected_at = now
    session.flush()
    log.info("Tenant %s: convictions collected (%d new, %d updated) from %s", tenant.name, created, updated, start.isoformat())
    return {"created": created, "updated": updated}
