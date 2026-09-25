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
"""Display helpers for report runs: human period labels, relative times and run view-models."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.i18n import LANGUAGE_NAMES
from app.models import ReportRun, utcnow


def zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


def period_label(start: datetime | None, end: datetime | None, tz: ZoneInfo) -> str:
    """'Tue 22 Sep 2026', 'Week 38 · 14 Sep – 20 Sep 2026', 'August 2026', 'Q2 2026' or a date range.

    Periods are stored as UTC instants of local midnights, so they are converted
    back to the configured timezone first (a Stockholm week starts 22:00 UTC)."""
    if start is None or end is None:
        return "–"
    s, e = start.astimezone(tz), end.astimezone(tz)
    days = round((e - s).total_seconds() / 86400)
    first, last = s.date(), (e - timedelta(hours=1)).date()
    if days <= 1:
        return f"{first:%a} {first.day} {first:%b %Y}"
    if days == 7 and first.weekday() == 0:
        return f"Week {first.isocalendar()[1]} · {first.day} {first:%b} – {last.day} {last:%b %Y}"
    if first.day == 1 and (last + timedelta(days=1)).day == 1:
        months = (last.year - first.year) * 12 + last.month - first.month + 1
        if months == 1:
            return f"{first:%B %Y}"
        if months == 3 and first.month in (1, 4, 7, 10):
            return f"Q{(first.month - 1) // 3 + 1} {first.year}"
    return f"{first.day} {first:%b %Y} – {last.day} {last:%b %Y}"


def ago(value: datetime | None, now: datetime | None = None) -> str:
    if value is None:
        return "–"
    secs = max(0.0, ((now or utcnow()) - value).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    days = int(secs // 86400)
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    if days < 365:
        months = days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    years = days // 365
    return f"{years} year{'s' if years > 1 else ''} ago"


def local_dt(value: datetime | None, tz: ZoneInfo) -> str:
    if value is None:
        return "–"
    v = value.astimezone(tz)
    return f"{v.day} {v:%b %Y %H:%M} {v.tzname() or ''}".strip()


def duration(start: datetime | None, end: datetime | None) -> str:
    if start is None or end is None:
        return ""
    secs = max(0, int((end - start).total_seconds()))
    if secs < 1:
        return ""
    if secs < 60:
        return f"{secs} s"
    if secs < 3600:
        return f"{secs // 60} min {secs % 60} s" if secs % 60 else f"{secs // 60} min"
    return f"{secs // 3600} h {secs % 3600 // 60} min"


TRIGGERS = {
    "schedule": "from a schedule",
    "catchup": "caught up after the service was down",
    "manual": "run manually",
    "api": "started via the API",
}


def run_view(run: ReportRun, *, definitions: dict[str, Any], tenant_names: dict[int, str], tz: ZoneInfo, now: datetime | None = None) -> dict[str, Any]:
    """Everything the archive shows about one run, as plain strings (also used for the data-* attributes)."""
    d = definitions.get(run.report_key)
    tenant = "All tenants" if run.tenant_id is None else tenant_names.get(run.tenant_id, "Unknown tenant")
    meta = [f"Generated {local_dt(run.started_at, tz)}"]
    took = duration(run.started_at, run.finished_at) if run.status != "running" else ""
    if took:
        meta.append(f"took {took}")
    trigger = run.triggered_by or ("schedule" if run.schedule_id else "manual")
    meta.append(TRIGGERS.get(trigger, "run manually"))
    if run.delivered_to:
        meta.append(f"sent to {run.delivered_to}")  # handed to the relay - not proof of mailbox delivery
    elif run.delivery_note:
        meta.append(run.delivery_note[0].lower() + run.delivery_note[1:].rstrip("."))
    elif not run.delivery_error:
        meta.append("archive only")
    if run.language and run.language != "en":
        meta.append(f"in {LANGUAGE_NAMES.get(run.language, run.language)}")
    return {
        "id": run.id,
        "report_key": run.report_key,
        "report_name": d.name if d else run.report_key,
        "icon": d.icon if d else "file",
        "category": d.category if d else "other",
        "tenant": tenant,
        "period": period_label(run.period_start, run.period_end, tz),
        "status": run.status,
        "ago": ago(run.started_at, now),
        "when": local_dt(run.started_at, tz),
        "month": f"{run.started_at.astimezone(tz):%B %Y}",
        "scheduled": trigger in ("schedule", "catchup"),
        "warning": run.delivery_error or "",
        "delivered_to": run.delivered_to or "",
        "html": f"/reports/{run.id}/html" if run.html_path else "",
        "pdf": f"/reports/{run.id}/pdf" if run.pdf_path else "",
        "error": run.error or "",
        "meta": " · ".join(meta),
    }
