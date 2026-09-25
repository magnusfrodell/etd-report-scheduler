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
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.branding import NEUTRAL, BrandView, brand_for
from app.config import get_config
from app.db import session_scope
from app.delivery import archive, pdf
from app.delivery.email import send_email
from app.models import ReportRun, ReportSchedule, Tenant, utcnow
from app.reports import repo
from app.reports.base import SCOPE_ALL, ReportContext, ReportDefinition
from app.reports.periods import period_for
from app.reports.registry import get_report
from app.settings_store import RuntimeSettings, load_settings
from app.tenant_profile import get_profile

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


def render_report(session: Session, definition: ReportDefinition, ctx: ReportContext, data: dict[str, Any] | None = None,
                  brand: BrandView | None = None) -> str:
    data = definition.build(session, ctx) if data is None else data
    template = template_env().get_template(definition.template)
    return template.render(report=definition, ctx=ctx, data=data, generated_at=ctx.generated_at, tz=ctx.timezone, brand=brand or NEUTRAL)


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
    only_with_findings: bool = False,
    delivery_note: str | None = None,
    alert: bool = True,
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
            data = definition.build(session, ctx)
            brand = brand_for(session, tenant)
            html = render_report(session, definition, ctx, data, brand)
            findings = definition.has_findings(data) if definition.has_findings else True
            tenant_name = tenant.name if tenant else None
            subject = definition.subject.format(tenant=ctx.tenant_name, period=ctx.period.label)
            if brand.subject_prefix:
                subject = f"{brand.subject_prefix} {subject}"
            result["period_start"], result["period_end"] = ctx.period.start, ctx.period.end

        # Phase 3 - files, PDF and e-mail with no database session open.
        html_path, pdf_path = archive.archive_paths(cfg.reports_dir, tenant_name, report_key, now, run_id)
        result["html_path"] = archive.write_bytes(html_path, html.encode("utf-8"))
        pdf_bytes = pdf.render_pdf(html) if output_format == "pdf" else None
        if pdf_bytes:
            result["pdf_path"] = archive.write_bytes(pdf_path, pdf_bytes)
        if deliver and to and only_with_findings and not findings:
            result["delivery_note"] = "Not sent: nothing to report - the schedule only sends reports with findings."
        elif deliver and to:
            attachments = [(pdf_path.name, pdf_bytes, "application/pdf")] if pdf_bytes else []
            email_html, inline = html, []
            if brand.logo_src:  # mail clients block data: images - send the logo as an inline part instead
                email_html = html.replace(brand.logo_src, "cid:brand-logo")
                inline = [("brand-logo", brand.logo_bytes, brand.logo_type)]
            try:
                refused = send_email(settings, to, subject, email_html, attachments, inline_images=inline,
                                     from_name=brand.sender_name or None, reply_to=brand.reply_to or None)
            except Exception as exc:  # noqa: BLE001
                raise DeliveryFailed(f"The report was generated, but sending it failed: {type(exc).__name__}: {exc}") from exc
            # An SMTP relay can accept some recipients and refuse others without an error.
            result["delivered_to"] = ", ".join(r for r in to if r not in refused)
            if refused:
                result["delivery_error"] = "The relay refused " + "; ".join(f"{addr} ({_smtp_reply(reply)})" for addr, reply in refused.items())
        elif deliver and not to:
            log.info("Report %s run %d generated without recipients (archived only)", report_key, run_id)
            if delivery_note:
                result["delivery_note"] = delivery_note
    except Exception as exc:  # noqa: BLE001
        log.exception("Report %s run %d failed", report_key, run_id)
        result["status"] = "failed"
        result["error"] = (str(exc) if isinstance(exc, DeliveryFailed) else f"{type(exc).__name__}: {exc}")[:4000]

    # Phase 4 - finalize (retried, so a transient 'database is locked' cannot leave a run 'running' forever).
    _finalize_run(run_id, schedule_id, result)
    if alert and trigger in ("schedule", "catchup") and (result["status"] == "failed" or result.get("delivery_error")):
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
                for key in ("period_start", "period_end", "html_path", "pdf_path", "delivered_to", "error", "delivery_error", "delivery_note"):
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


def schedule_targets(session: Session, schedule: ReportSchedule, definition: ReportDefinition) -> list[Tenant | None]:
    """The tenants one run of a schedule covers: ``[None]`` for a cross-tenant report, the tenant of a
    single-tenant schedule, or every enabled tenant (in the group) at the moment it runs - so tenants
    added later are included without touching the schedule."""
    if definition.scope == SCOPE_ALL:
        return [None]
    if schedule.target not in ("all", "group"):
        tenant = session.get(Tenant, schedule.tenant_id) if schedule.tenant_id else None
        return [tenant] if tenant is not None else []
    tenants = list(session.execute(select(Tenant).where(Tenant.enabled.is_(True)).order_by(Tenant.name)).scalars())
    if schedule.target == "group":
        wanted = (schedule.target_group or "").strip().lower()
        tenants = [t for t in tenants if get_profile(t)["group"].lower() == wanted]
    return tenants


def schedule_recipients(schedule: ReportSchedule, definition: ReportDefinition, tenant: Tenant | None,
                        settings: RuntimeSettings) -> tuple[list[str], str | None]:
    """Recipients of one tenant's run, and a note when the tenant's own contacts were expected but missing."""
    fixed = schedule.recipient_list
    if definition.scope == SCOPE_ALL:
        return fixed or settings.partner_recipient_list, None
    contacts = get_profile(tenant)["report_recipients"] if tenant is not None else []
    mode = schedule.recipient_mode or "fixed"
    to = contacts if mode == "tenant" else list(dict.fromkeys(fixed + contacts)) if mode == "both" else fixed
    note = "Not sent: the tenant profile has no report recipients." if not to and mode in ("tenant", "both") else None
    return to, note


def run_schedule(schedule_id: int, *, reference: datetime | None = None, triggered_by: str = "schedule",
                 only_missing: bool = False, force: bool = False, deliver: bool = True, output_format: str | None = None,
                 now: datetime | None = None) -> int | None:
    """Run a schedule for every tenant it covers. ``reference`` is when it fell due (catch-up), and
    ``only_missing`` skips tenants that already have a run for that period. Returns the last run id."""
    from zoneinfo import ZoneInfo

    with session_scope() as session:
        schedule = session.get(ReportSchedule, schedule_id)
        if schedule is None or (not schedule.enabled and not force):
            log.info("Schedule %s missing or disabled - skipping", schedule_id)
            return None
        settings = load_settings(session)
        definition = get_report(schedule.report_key)
        targets = schedule_targets(session, schedule, definition)
        if only_missing and reference is not None:
            period = period_for(definition.period_kind, reference, ZoneInfo(settings.timezone))
            done = set(session.execute(
                select(ReportRun.tenant_id).where(ReportRun.schedule_id == schedule.id, ReportRun.period_start == period.start)
            ).scalars())
            targets = [t for t in targets if (t.id if t is not None else None) not in done]
        jobs = [(t.id if t is not None else None, *schedule_recipients(schedule, definition, t, settings)) for t in targets]
        fan_out = schedule.target in ("all", "group") and definition.scope != SCOPE_ALL
        output_format, only_findings = output_format or schedule.output_format, schedule.only_with_findings
    run_ids = [
        run_report(definition.key, tenant_id=tid, schedule_id=schedule_id, recipients=to, output_format=output_format,
                   reference=reference, triggered_by=triggered_by, only_with_findings=only_findings, delivery_note=note,
                   alert=not fan_out, deliver=deliver, now=now)
        for tid, to, note in jobs
    ]
    if fan_out:
        log.info("Schedule %s covered %d tenant(s)", schedule_id, len(run_ids))
        if run_ids:
            from app.alerts import alert_schedule_problems  # late import, as in run_report

            alert_schedule_problems(schedule_id, run_ids, triggered_by)
    return run_ids[-1] if run_ids else None


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
