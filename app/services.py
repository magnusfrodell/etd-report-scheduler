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
"""Run a report end-to-end: build context -> render -> archive -> deliver -> record."""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_config
from app.db import session_scope
from app.delivery import archive, pdf
from app.delivery.email import send_email
from app.models import ReportRun, ReportSchedule, Tenant, utcnow
from app.reports import repo
from app.reports.base import SCOPE_ALL, ReportContext, ReportDefinition
from app.reports.periods import period_for
from app.reports.registry import get_report
from app.settings_store import load_settings

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env: Environment | None = None


def template_env() -> Environment:
    global _env
    if _env is None:
        _env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=select_autoescape(["html"]))
        _env.filters["fmt_dt"] = _fmt_dt
        _env.filters["fmt_int"] = _fmt_int
        _env.filters["fmt_pct"] = _fmt_pct
        _env.globals["app_version"] = __version__
    return _env


def _fmt_dt(value: datetime | None, tz: str | None = None) -> str:
    if value is None:
        return "–"
    if tz:
        from zoneinfo import ZoneInfo

        with contextlib.suppress(Exception):
            value = value.astimezone(ZoneInfo(tz))
    return value.strftime("%Y-%m-%d %H:%M")


def _fmt_int(value: int | float | None) -> str:
    if value is None:
        return "–"
    return f"{int(value):,}".replace(",", " ")


def _fmt_pct(value: float | None) -> str:
    if value is None:
        return "new"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.1f} %"


def render_report(session: Session, definition: ReportDefinition, ctx: ReportContext) -> str:
    data = definition.build(session, ctx)
    template = template_env().get_template(definition.template)
    return template.render(report=definition, ctx=ctx, data=data, generated_at=ctx.generated_at, tz=ctx.timezone)


def build_context(session: Session, definition: ReportDefinition, tenant: Tenant | None, now: datetime, tz_name: str, period_kind: str | None = None,
                  reference: datetime | None = None) -> ReportContext:
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(tz_name)
    period = period_for(period_kind or definition.period_kind, reference or now, tz)
    if definition.scope == SCOPE_ALL:
        return ReportContext(period=period, generated_at=now, timezone=tz_name, tenants=repo.enabled_tenants(session))
    if tenant is None:
        raise ValueError(f"Report {definition.key!r} needs a tenant")
    return ReportContext(period=period, generated_at=now, timezone=tz_name, tenant=tenant)


class DeliveryFailed(RuntimeError):
    """The report was rendered and archived, but e-mail delivery failed."""


def _smtp_reply(reply: object) -> str:
    try:
        code, text = reply  # type: ignore[misc]
    except (TypeError, ValueError):
        return str(reply)
    return f"{code} {text.decode('utf-8', 'replace') if isinstance(text, bytes) else text}".strip()


def run_report(
    report_key: str,
    *,
    tenant_id: int | None = None,
    schedule_id: int | None = None,
    recipients: list[str] | None = None,
    output_format: str = "pdf",
    deliver: bool = True,
    period_kind: str | None = None,
    now: datetime | None = None,
    reference: datetime | None = None,
    triggered_by: str | None = None,
) -> int:
    """Generate one report. Returns the ``ReportRun`` id. Never raises - failures are recorded.

    Three short database transactions: create the run row, build + render, finalize. PDF
    rendering, file writes and SMTP happen with no session open, so a slow relay or a
    big PDF never holds a database lock and concurrent runs never interfere.
    """
    definition = get_report(report_key)
    now = now or utcnow()
    cfg = get_config()
    to = list(recipients or [])

    trigger = triggered_by or ("schedule" if schedule_id else "manual")

    # Phase 1 - record the run (and validate the tenant for per-tenant reports).
    with session_scope() as session:
        tenant_missing = definition.scope != SCOPE_ALL and (tenant_id is None or session.get(Tenant, tenant_id) is None)
        run = ReportRun(
            schedule_id=schedule_id,
            triggered_by=trigger,
            tenant_id=None if tenant_missing else tenant_id,
            report_key=report_key,
            started_at=now,
            status="failed" if tenant_missing else "running",
            error="Tenant not found for a per-tenant report" if tenant_missing else None,
            finished_at=utcnow() if tenant_missing else None,
        )
        session.add(run)
        session.flush()
        run_id = run.id
        if tenant_missing:
            log.error("Report %s: tenant %s not found", report_key, tenant_id)
            return run_id

    result: dict[str, object] = {"status": "ok"}
    try:
        # Phase 2 - read data and render (short transaction, read-only).
        with session_scope() as session:
            settings = load_settings(session)
            tenant = session.get(Tenant, tenant_id) if tenant_id else None
            ctx = build_context(session, definition, tenant, now, settings.timezone, period_kind, reference)
            html = render_report(session, definition, ctx)
            tenant_name = tenant.name if tenant else None
            subject = definition.subject.format(tenant=ctx.tenant_name, period=ctx.period.label)
            result["period_start"], result["period_end"] = ctx.period.start, ctx.period.end

        # Phase 3 - files, PDF and e-mail with no database session open.
        html_path, pdf_path = archive.archive_paths(cfg.reports_dir, tenant_name, report_key, now, run_id)
        result["html_path"] = archive.write_bytes(html_path, html.encode("utf-8"))
        pdf_bytes = pdf.render_pdf(html) if output_format == "pdf" else None
        if pdf_bytes:
            result["pdf_path"] = archive.write_bytes(pdf_path, pdf_bytes)
        if deliver and to:
            attachments = [(pdf_path.name, pdf_bytes, "application/pdf")] if pdf_bytes else []
            try:
                refused = send_email(settings, to, subject, html, attachments)
            except Exception as exc:  # noqa: BLE001
                raise DeliveryFailed(f"The report was generated, but sending it failed: {type(exc).__name__}: {exc}") from exc
            # An SMTP relay can accept some recipients and refuse others without an error.
            result["delivered_to"] = ", ".join(r for r in to if r not in refused)
            if refused:
                result["delivery_error"] = "The relay refused " + "; ".join(f"{addr} ({_smtp_reply(reply)})" for addr, reply in refused.items())
        elif deliver and not to:
            log.info("Report %s run %d generated without recipients (archived only)", report_key, run_id)
    except Exception as exc:  # noqa: BLE001
        log.exception("Report %s run %d failed", report_key, run_id)
        result["status"] = "failed"
        result["error"] = (str(exc) if isinstance(exc, DeliveryFailed) else f"{type(exc).__name__}: {exc}")[:4000]

    # Phase 4 - finalize (retried, so a transient 'database is locked' cannot leave a run 'running' forever).
    _finalize_run(run_id, schedule_id, result)
    if trigger in ("schedule", "catchup") and (result["status"] == "failed" or result.get("delivery_error")):
        from app.alerts import (
            alert_run_problem,  # late import: alerts uses the mailer and the report registry
        )

        alert_run_problem(run_id)
    return run_id


def _finalize_run(run_id: int, schedule_id: int | None, result: dict[str, object], attempts: int = 5) -> None:
    import time

    for attempt in range(1, attempts + 1):
        try:
            with session_scope() as session:
                run = session.get(ReportRun, run_id)
                if run is None:
                    return
                for key in ("period_start", "period_end", "html_path", "pdf_path", "delivered_to", "error", "delivery_error"):
                    if key in result:
                        setattr(run, key, result[key])
                run.status = str(result["status"])
                run.finished_at = utcnow()
                if schedule_id:
                    schedule = session.get(ReportSchedule, schedule_id)
                    if schedule is not None:
                        schedule.last_run_at = run.finished_at
                        schedule.last_status = run.status
            return
        except Exception:  # noqa: BLE001
            if attempt == attempts:
                log.exception("Could not finalize report run %d after %d attempts", run_id, attempts)
                return
            time.sleep(0.5 * attempt)


def run_schedule(schedule_id: int, *, reference: datetime | None = None, triggered_by: str = "schedule") -> int | None:
    """Entry point used by the scheduler. ``reference`` is the time the run fell due (catch-up after an outage)."""
    with session_scope() as session:
        schedule = session.get(ReportSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            log.info("Schedule %s missing or disabled - skipping", schedule_id)
            return None
        settings = load_settings(session)
        definition = get_report(schedule.report_key)
        recipients = schedule.recipient_list or (settings.partner_recipient_list if definition.scope == SCOPE_ALL else [])
        params = dict(
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.id,
            recipients=recipients,
            output_format=schedule.output_format,
        )
    return run_report(schedule.report_key, reference=reference, triggered_by=triggered_by, **params)


def recover_interrupted_runs() -> int:
    """Runs left 'running' by a restart can never finish: mark them failed at start-up.

    The service runs as a single process, so at start-up nothing can still be generating."""
    with session_scope() as session:
        runs = list(session.execute(select(ReportRun).where(ReportRun.status == "running")).scalars())
        for run in runs:
            run.status = "failed"
            run.finished_at = utcnow()
            run.error = "Interrupted: the service stopped while this report was being generated. Run it again from the Reports page."
        return len(runs)
