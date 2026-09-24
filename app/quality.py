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
"""Collection health per tenant and data stream.

One model for the Data quality page and the alerts, so both always say the same thing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto import secret_box
from app.db import session_scope
from app.models import DailyStat, LogFile, Tenant, utcnow
from app.settings_store import RuntimeSettings
from app.web.presenters import ago

LABELS = {
    "stats": "Daily statistics",
    "convictions": "Convicted messages",
    "logs": "Log Export (audit and message events)",
    "backfill": "History backfill",
}
# How old the last success may get before a stream is late (warning) or stalled (critical).
# Statistics are collected once a day, convicted messages and Log Export every hour.
STALE = {
    "stats": (timedelta(hours=30), timedelta(hours=54)),
    "convictions": (timedelta(hours=3), timedelta(hours=12)),
    "logs": (timedelta(hours=3), timedelta(hours=12)),
}
STATUS_LABELS = {"ok": "OK", "warning": "Late", "critical": "Stalled", "pending": "Waiting", "off": "Off"}
CHIP = {"ok": "ok", "warning": "warning", "critical": "failed", "pending": "neutral", "off": "neutral"}
RANK = {"critical": 4, "warning": 3, "pending": 2, "ok": 1, "off": 0}


@dataclass
class StreamHealth:
    stream: str
    status: str  # ok | warning | critical | pending | off
    last_ok: datetime | None
    detail: str
    error: str | None = None

    @property
    def label(self) -> str:
        return LABELS[self.stream]

    @property
    def status_label(self) -> str:
        return "Error" if self.error and self.status == "warning" else STATUS_LABELS[self.status]

    @property
    def chip(self) -> str:
        return CHIP[self.status]

    @property
    def last_ok_text(self) -> str:
        return ago(self.last_ok) if self.last_ok else "never"


def _timed(stream: str, last_ok: datetime | None, now: datetime, errors: dict, detail: str) -> StreamHealth:
    warn_after, fail_after = STALE[stream]
    error = (errors.get(stream) or {}).get("error")
    if last_ok is None:
        status = "critical" if error else "pending"
        detail = detail or "Not collected yet."
    elif now - last_ok > fail_after:
        status = "critical"
        detail = f"No successful collection for {ago(last_ok, now).removesuffix(' ago')}. " + detail
    elif now - last_ok > warn_after or error:
        status = "warning"
    else:
        status = "ok"
    return StreamHealth(stream, status, last_ok, detail.strip(), error)


def tenant_health(session: Session, tenant: Tenant, settings: RuntimeSettings, now: datetime | None = None) -> list[StreamHealth]:
    now = now or utcnow()
    if not tenant.enabled:
        return [StreamHealth(s, "off", None, "The tenant is disabled.") for s in LABELS]
    errors = tenant.collector_errors or {}
    month_ago = (now - timedelta(days=30)).date()
    days = session.execute(
        select(func.count()).select_from(DailyStat).where(DailyStat.tenant_id == tenant.id, DailyStat.day > month_ago)
    ).scalar_one()
    out = [
        _timed("stats", tenant.stats_collected_at, now, errors, f"{days} of the last 30 days have statistics."),
        _timed("convictions", tenant.convictions_collected_at, now, errors, "Collected every hour."),
    ]
    if not settings.log_export_enabled:
        out.append(StreamHealth("logs", "off", tenant.logs_collected_at, "Switched off in Settings."))
    else:
        partial = session.execute(
            select(func.count()).select_from(LogFile).where(LogFile.tenant_id == tenant.id, LogFile.status == "partial", LogFile.log_date > month_ago)
        ).scalar_one()
        notes = [tenant.logs_note or ""]
        if partial:
            notes.append(f"{partial} file(s) in the last 30 days had unreadable lines.")
        if tenant.logs_gaps:
            notes.append(f"{len(tenant.logs_gaps)} collection gap(s) recorded.")
        health = _timed("logs", tenant.logs_collected_at, now, errors, " ".join(n for n in notes if n))
        if health.status == "ok" and (partial or tenant.logs_status == "no_data"):
            health.status = "warning"
        out.append(health)
    if tenant.backfill_done_at:
        out.append(StreamHealth("backfill", "ok", tenant.backfill_done_at, "History is complete."))
    elif tenant.backfill_cursor:
        out.append(StreamHealth("backfill", "pending", None, f"In progress: collected back to {tenant.backfill_cursor:%Y-%m-%d}.",
                                (errors.get("backfill") or {}).get("error")))
    else:
        out.append(StreamHealth("backfill", "pending", None, "Not started.", (errors.get("backfill") or {}).get("error")))
    return out


def worst(streams: list[StreamHealth]) -> str:
    return max((s.status for s in streams), key=lambda s: RANK[s], default="ok")


def encryption_key_problem() -> str | None:
    """None if the stored credentials can be decrypted (or there are none yet), else what is wrong."""
    with session_scope() as session:
        sample = session.execute(select(Tenant.client_secret_enc).where(Tenant.client_secret_enc.is_not(None)).limit(1)).scalar()
    if not sample:
        return None
    try:
        secret_box().decrypt(sample)
    except ValueError:
        return ("ENCRYPTION_KEY does not match the key the stored credentials were encrypted with, so no tenant can be "
                "collected and no e-mail can be sent. Start the service with the ENCRYPTION_KEY the data was created with.")
    return None
