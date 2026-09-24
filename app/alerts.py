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
"""E-mail alerts: failed scheduled reports and stalled data collection."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from markupsafe import escape
from sqlalchemy import select

from app.db import session_scope
from app.delivery.email import send_email
from app.models import AlertState, ReportRun, ReportSchedule, Tenant, utcnow
from app.quality import tenant_health
from app.reports.registry import REPORTS
from app.settings_store import RuntimeSettings, load_settings

log = logging.getLogger(__name__)
REPEAT_AFTER = timedelta(hours=24)  # a problem that lasts is reported again once a day


def _send(settings: RuntimeSettings, subject: str, lines: list[str], link: str = "") -> bool:
    to = settings.alert_recipient_list
    if not to or not settings.smtp_configured:
        return False
    items = "".join(f"<li>{escape(line)}</li>" for line in lines)
    more = f'<p><a href="{escape(link)}">{escape(link)}</a></p>' if link else ""
    html = f"<p>ETD Report Scheduler needs attention:</p><ul>{items}</ul>{more}<p style=\"color:#667\">Alert recipients are set under Settings.</p>"
    try:
        send_email(settings, to, subject, html)
    except Exception:  # noqa: BLE001 - an alert must never break the job that raised it
        log.exception("Could not send the alert '%s'", subject)
        return False
    return True


def alert_run_problem(run_id: int) -> bool:
    """Tell the alert recipients that a scheduled (or caught-up) report failed or was only partly delivered."""
    with session_scope() as session:
        run = session.get(ReportRun, run_id)
        if run is None or run.triggered_by not in ("schedule", "catchup") or (run.status != "failed" and not run.delivery_error):
            return False
        settings = load_settings(session)
        tenant = session.get(Tenant, run.tenant_id) if run.tenant_id else None
        name = REPORTS[run.report_key].name if run.report_key in REPORTS else run.report_key
        who = tenant.name if tenant else "all tenants"
        what = "failed" if run.status == "failed" else "was only partly delivered"
        detail = run.error if run.status == "failed" else run.delivery_error
        link = f"{settings.base_url.rstrip('/')}/archive?report={run.report_key}&tenant={run.tenant_id or 'all'}&run={run.id}" if settings.base_url else ""
    return _send(settings, f"[ETD] Scheduled report {what}: {name} - {who}", [f"{name} for {who} {what}.", detail or ""], link)


def alert_schedule_problems(schedule_id: int, run_ids: list[int], triggered_by: str) -> bool:
    """One alert for a schedule that covers many tenants, listing the tenants whose report failed or
    was only partly delivered - not one e-mail per tenant."""
    if triggered_by not in ("schedule", "catchup") or not run_ids:
        return False
    with session_scope() as session:
        runs = list(session.execute(select(ReportRun).where(ReportRun.id.in_(run_ids))).scalars())
        problems = [r for r in runs if r.status == "failed" or r.delivery_error]
        if not problems:
            return False
        settings = load_settings(session)
        schedule = session.get(ReportSchedule, schedule_id)
        key = schedule.report_key if schedule else problems[0].report_key
        name = REPORTS[key].name if key in REPORTS else key
        tenants = {t.id: t.name for t in session.execute(select(Tenant)).scalars()}
        lines = [f"{tenants.get(r.tenant_id, 'unknown tenant')}: " + (f"failed - {r.error}" if r.status == "failed" else f"partly delivered - {r.delivery_error}")
                 for r in problems]
        link = f"{settings.base_url.rstrip('/')}/archive?report={key}&tenant=all" if settings.base_url else ""
    return _send(settings, f"[ETD] Scheduled report: {len(problems)} of {len(runs)} tenant(s) need attention - {name}", lines, link)


def check_collection(now: datetime | None = None) -> int:
    """Hourly: e-mail stalled data collection, at most once a day per tenant and stream.

    A problem that clears is forgotten, so it is reported at once if it comes back."""
    now = now or utcnow()
    with session_scope() as session:
        settings = load_settings(session)
        if not settings.alert_recipient_list or not settings.smtp_configured:
            return 0
        due: list[tuple[str, str]] = []
        still_open: set[str] = set()
        for tenant in session.execute(select(Tenant).where(Tenant.enabled.is_(True)).order_by(Tenant.name)).scalars():
            for health in tenant_health(session, tenant, settings, now):
                if health.status != "critical":
                    continue
                key = f"collect:{tenant.id}:{health.stream}"
                still_open.add(key)
                state = session.get(AlertState, key)
                if state is None or now - state.last_sent_at >= REPEAT_AFTER:
                    due.append((key, f"{tenant.name} - {health.label}: {health.detail}" + (f" Last error: {health.error}" if health.error else "")))
        for state in session.execute(select(AlertState).where(AlertState.key.like("collect:%"))).scalars():
            if state.key not in still_open:
                session.delete(state)
        link = f"{settings.base_url.rstrip('/')}/quality" if settings.base_url else ""
    if not due or not _send(settings, f"[ETD] Data collection stalled for {len(due)} stream(s)", [text for _, text in due], link):
        return 0
    with session_scope() as session:
        for key, text in due:
            state = session.get(AlertState, key) or AlertState(key=key, last_sent_at=now)
            state.last_sent_at, state.detail = now, text
            session.add(state)
    return len(due)
