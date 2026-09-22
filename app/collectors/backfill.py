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
"""History backfill for convicted messages.

Walks *backwards* from ``backfill_cursor`` towards the 90-day horizon in small windows
(``backfill_window_days``), newest first, so recent reports work immediately and older
history fills in behind them. Every completed window moves the cursor; a window that is
cut short by the daily API budget is simply redone next run (upserts are idempotent).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.collectors.convictions import upsert_page
from app.etd.client import HISTORY_HORIZON_DAYS, ETDClient
from app.models import ConvictedMessage, Tenant, utcnow

log = logging.getLogger(__name__)

MIN_BUDGET_TO_START = 25


def initial_cursor(session: Session, tenant: Tenant, now: datetime) -> datetime:
    """Where the backfill starts for a tenant that already has data: the oldest stored message,
    otherwise the conviction watermark, otherwise now."""
    oldest = session.execute(
        select(func.min(ConvictedMessage.timestamp)).where(ConvictedMessage.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if oldest is not None:
        return oldest if oldest.tzinfo else oldest.replace(tzinfo=now.tzinfo)
    return tenant.convictions_watermark or now


def backfill_convictions(
    session: Session,
    tenant: Tenant,
    client: ETDClient,
    *,
    verdicts: list[str],
    budget: int,
    window_days: int = 7,
    now: datetime | None = None,
) -> dict[str, object]:
    """Process windows until the horizon is reached or ``budget`` requests are used.

    Returns a summary dict with ``status`` in ``done`` | ``paused`` | ``skipped``.
    """
    now = now or utcnow()
    horizon = now - timedelta(days=HISTORY_HORIZON_DAYS - 1)
    if tenant.backfill_done_at is not None:
        return {"status": "skipped", "reason": "already complete"}
    if tenant.backfill_cursor is None:
        tenant.backfill_cursor = initial_cursor(session, tenant, now)
        session.commit()
    if budget < MIN_BUDGET_TO_START:
        return {"status": "paused", "reason": f"daily API budget exhausted ({budget} left)", "cursor": tenant.backfill_cursor}

    created = updated = windows = 0
    used_at_start = client.request_count
    while tenant.backfill_cursor > horizon:
        window_end = tenant.backfill_cursor
        window_start = max(window_end - timedelta(days=window_days), horizon)
        complete = True
        for page in client.iter_pages(window_start, window_end, verdicts=verdicts):
            c, u = upsert_page(session, tenant.id, page)
            created += c
            updated += u
            session.commit()
            if client.request_count - used_at_start >= budget:
                complete = False
                break
        if not complete:
            log.info("Tenant %s: backfill paused at %s (budget used)", tenant.name, window_start.date())
            return {"status": "paused", "reason": "daily API budget exhausted", "cursor": tenant.backfill_cursor,
                    "created": created, "updated": updated, "windows": windows}
        tenant.backfill_cursor = window_start
        windows += 1
        session.commit()

    tenant.backfill_done_at = now
    session.commit()
    log.info("Tenant %s: backfill complete to %s (%d windows, %d new, %d updated, %d requests)",
             tenant.name, horizon.date(), windows, created, updated, client.request_count - used_at_start)
    return {"status": "done", "created": created, "updated": updated, "windows": windows}
