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
"""Server-rendered admin UI (Jinja2, no JavaScript framework)."""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.collectors import runner
from app.config import get_config
from app.crypto import secret_box
from app.db import get_db
from app.etd.factory import client_for_tenant
from app.etd.regions import REGIONS
from app.models import ConvictedMessage, DailyStat, ReportRun, ReportSchedule, Tenant, utcnow
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS, get_report
from app.scheduler import scheduler, validate_cron
from app.services import run_report
from app.settings_store import ALL_VERDICTS, load_settings, save_settings
from app.web.auth import (
    SESSION_COOKIE,
    TENANT_COOKIE,
    check_password,
    current_tenant_selection,
    require_auth,
    session_token,
)

log = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
templates.env.globals["app_version"] = __version__
templates.env.globals["REGIONS"] = REGIONS


# ---------------------------------------------------------------- helpers
def _redirect(url: str, msg: str | None = None, error: bool = False) -> RedirectResponse:
    if msg:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{'err' if error else 'msg'}={quote(msg)}"
    return RedirectResponse(url, status_code=303)


def _tenants(db: Session) -> list[Tenant]:
    return list(db.execute(select(Tenant).order_by(Tenant.name)).scalars())


def _selected_tenant(request: Request, db: Session) -> Tenant | None:
    sel = current_tenant_selection(request)
    if sel == "all":
        return None
    return db.get(Tenant, int(sel))


def _base_ctx(request: Request, db: Session, **extra: Any) -> dict[str, Any]:
    tenants = _tenants(db)
    selected = _selected_tenant(request, db)
    return {
        "request": request,
        "tenants": tenants,
        "selected_tenant": selected,
        "selection": current_tenant_selection(request),
        "msg": request.query_params.get("msg"),
        "err": request.query_params.get("err"),
        "reports": REPORTS,
        **extra,
    }


# ------------------------------------------------------------------ login
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"request": request, "err": request.query_params.get("err")})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")) -> Response:
    if not check_password(username, password):
        log.warning("Failed login for user %r from %s", username, request.client.host if request.client else "?")
        return _redirect("/login", "Wrong username or password.", error=True)
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    cfg = get_config()
    resp.set_cookie(SESSION_COOKIE, session_token(username), httponly=True, samesite="lax", secure=cfg.cookie_secure, max_age=cfg.session_max_age_seconds)
    return resp


@router.post("/logout")
def logout() -> Response:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.post("/select-tenant", dependencies=[Depends(require_auth)])
def select_tenant(tenant: str = Form("all"), next: str = Form("/")) -> Response:
    resp = RedirectResponse(next if next.startswith("/") else "/", status_code=303)
    resp.set_cookie(TENANT_COOKIE, tenant if tenant == "all" or tenant.isdigit() else "all", samesite="lax", max_age=365 * 24 * 3600)
    return resp


# -------------------------------------------------------------- dashboard
@router.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def dashboard(request: Request, db: Session = Depends(get_db)) -> Response:
    tenants = _tenants(db)
    selected = _selected_tenant(request, db)
    scope = [selected] if selected else tenants
    since = (utcnow() - timedelta(days=7)).date()
    cards = []
    for t in scope:
        stat = db.execute(
            select(
                func.coalesce(func.sum(DailyStat.total_messages), 0),
                func.coalesce(func.sum(DailyStat.malicious + DailyStat.phishing + DailyStat.bec + DailyStat.scam), 0),
                func.coalesce(func.sum(DailyStat.spam + DailyStat.graymail), 0),
                func.coalesce(func.sum(DailyStat.retro_verdicts), 0),
            ).where(DailyStat.tenant_id == t.id, DailyStat.day >= since)
        ).one()
        convictions = db.execute(
            select(func.count()).select_from(ConvictedMessage).where(ConvictedMessage.tenant_id == t.id, ConvictedMessage.timestamp >= utcnow() - timedelta(days=7))
        ).scalar_one()
        cards.append({"tenant": t, "total": stat[0], "threats": stat[1], "unwanted": stat[2], "retro": stat[3], "convictions": convictions})
    recent_runs = list(
        db.execute(select(ReportRun).order_by(ReportRun.started_at.desc()).limit(8)).scalars()
    )
    tenant_names = {t.id: t.name for t in tenants}
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _base_ctx(request, db, cards=cards, recent_runs=recent_runs, tenant_names=tenant_names, next_runs=scheduler.next_run_times() if scheduler.running else {}, scheduler_running=scheduler.running),
    )


# ---------------------------------------------------------------- tenants
@router.get("/tenants", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def tenants_page(request: Request, db: Session = Depends(get_db)) -> Response:
    settings = load_settings(db)
    return templates.TemplateResponse(
        request,
        "tenants.html",
        _base_ctx(request, db, history={t.id: _history_label(t) for t in _tenants(db)}, api_today={t.id: runner.api_calls_today(t) for t in _tenants(db)}, budget=min(settings.api_daily_budget, runner.ETD_DAILY_QUOTA)),
    )


def _history_label(t: Tenant) -> str:
    if t.backfill_done_at is not None:
        return "90 days"
    if t.backfill_cursor is not None:
        days = max(0, (utcnow() - t.backfill_cursor).days)
        return f"{min(days, 90)} of 90 days, backfilling"
    if t.convictions_collected_at is not None:
        return "recent only, backfill pending"
    return "not collected yet"


@router.post("/tenants", dependencies=[Depends(require_auth)])
def tenant_create(
    background: BackgroundTasks,
    name: str = Form(...),
    region: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    api_key: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    name = name.strip()
    if not name:
        return _redirect("/tenants", "Name is required.", error=True)
    if region not in REGIONS:
        return _redirect("/tenants", "Unknown region.", error=True)
    if db.execute(select(Tenant).where(Tenant.name == name)).scalar_one_or_none():
        return _redirect("/tenants", f"A tenant named '{name}' already exists.", error=True)
    box = secret_box()
    tenant = Tenant(
        name=name,
        region=region,
        client_id=client_id.strip(),
        client_secret_enc=box.encrypt(client_secret.strip()) or "",
        api_key_enc=box.encrypt(api_key.strip()) or "",
        enabled=True,
    )
    db.add(tenant)
    db.commit()
    log.info("Tenant created: %s (%s)", tenant.name, tenant.region)
    # Verify the credentials right away; on success start the initial collection in the background
    # (90 days of statistics, the latest convictions, then history backfill within the API budget).
    client = client_for_tenant(tenant, timeout=15)
    try:
        client.test_connection()
    except Exception as exc:  # noqa: BLE001
        tenant.last_error = f"{type(exc).__name__}: {exc}"[:2000]
        tenant.last_error_at = utcnow()
        return _redirect("/tenants", f"Tenant '{name}' saved, but the connection test failed: {exc}. Fix the credentials and use 'Test connection'.", error=True)
    finally:
        runner.record_api_usage(tenant, client)
        client.close()
        db.commit()
    background.add_task(runner.collect_all_for_tenant, tenant.id)
    return _redirect("/tenants", f"Tenant '{name}' added and verified. Collecting 90 days of history in the background - progress is shown in the History column.")


@router.post("/tenants/{tenant_id}/test", dependencies=[Depends(require_auth)])
def tenant_test(tenant_id: int, db: Session = Depends(get_db)) -> Response:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        return _redirect("/tenants", "Tenant not found.", error=True)
    client = client_for_tenant(tenant, timeout=15)
    try:
        client.test_connection()
        tenant.last_error = None
        tenant.last_error_at = None
        return _redirect("/tenants", f"Connection to {REGIONS[tenant.region]['base_url']} succeeded for '{tenant.name}'.")
    except Exception as exc:  # noqa: BLE001
        tenant.last_error = f"{type(exc).__name__}: {exc}"[:2000]
        tenant.last_error_at = utcnow()
        return _redirect("/tenants", f"Connection test failed for '{tenant.name}': {exc}", error=True)
    finally:
        runner.record_api_usage(tenant, client)
        client.close()
        db.commit()


@router.post("/tenants/{tenant_id}/collect", dependencies=[Depends(require_auth)])
def tenant_collect(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> Response:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        return _redirect("/tenants", "Tenant not found.", error=True)
    background.add_task(runner.collect_all_for_tenant, tenant_id)
    return _redirect("/tenants", f"Collection started for '{tenant.name}' - refresh in a minute to see the result.")


@router.post("/tenants/{tenant_id}/toggle", dependencies=[Depends(require_auth)])
def tenant_toggle(tenant_id: int, db: Session = Depends(get_db)) -> Response:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        return _redirect("/tenants", "Tenant not found.", error=True)
    tenant.enabled = not tenant.enabled
    db.commit()
    return _redirect("/tenants", f"Tenant '{tenant.name}' {'enabled' if tenant.enabled else 'disabled'}.")


@router.post("/tenants/{tenant_id}/delete", dependencies=[Depends(require_auth)])
def tenant_delete(tenant_id: int, db: Session = Depends(get_db)) -> Response:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        return _redirect("/tenants", "Tenant not found.", error=True)
    name = tenant.name
    db.delete(tenant)
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    resp = _redirect("/tenants", f"Tenant '{name}' and all its data were deleted.")
    resp.set_cookie(TENANT_COOKIE, "all", samesite="lax")
    return resp


# -------------------------------------------------------------- schedules
@router.get("/schedules", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def schedules_page(request: Request, db: Session = Depends(get_db)) -> Response:
    selected = _selected_tenant(request, db)
    stmt = select(ReportSchedule).order_by(ReportSchedule.tenant_id.nulls_first(), ReportSchedule.report_key)
    if selected:
        stmt = stmt.where((ReportSchedule.tenant_id == selected.id) | (ReportSchedule.tenant_id.is_(None)))
    schedules = list(db.execute(stmt).scalars())
    settings = load_settings(db)
    return templates.TemplateResponse(
        request,
        "schedules.html",
        _base_ctx(request, db, schedules=schedules, settings=settings, next_runs=scheduler.next_run_times() if scheduler.running else {}),
    )


@router.post("/schedules", dependencies=[Depends(require_auth)])
def schedule_create(
    report_key: str = Form(...),
    tenant_id: str = Form(""),
    cron: str = Form(""),
    recipients: str = Form(""),
    output_format: str = Form("pdf"),
    db: Session = Depends(get_db),
) -> Response:
    try:
        definition = get_report(report_key)
    except KeyError:
        return _redirect("/schedules", "Unknown report.", error=True)
    settings = load_settings(db)
    cron = cron.strip() or definition.default_cron
    try:
        validate_cron(cron, settings.timezone)
    except ValueError as exc:
        return _redirect("/schedules", str(exc), error=True)
    tid: int | None = None
    if definition.scope != SCOPE_ALL:
        if not tenant_id.isdigit() or db.get(Tenant, int(tenant_id)) is None:
            return _redirect("/schedules", f"'{definition.name}' is a per-tenant report - choose a tenant.", error=True)
        tid = int(tenant_id)
    schedule = ReportSchedule(
        tenant_id=tid,
        report_key=report_key,
        cron=cron,
        recipients=recipients.strip(),
        output_format="html" if output_format == "html" else "pdf",
        enabled=True,
    )
    db.add(schedule)
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", f"Schedule for '{definition.name}' created ({cron}, {settings.timezone}).")


@router.post("/schedules/{schedule_id}/run", dependencies=[Depends(require_auth)])
def schedule_run(schedule_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> Response:
    schedule = db.get(ReportSchedule, schedule_id)
    if schedule is None:
        return _redirect("/schedules", "Schedule not found.", error=True)
    settings = load_settings(db)
    definition = get_report(schedule.report_key)
    recipients = schedule.recipient_list or (settings.partner_recipient_list if definition.scope == SCOPE_ALL else [])
    background.add_task(
        run_report,
        schedule.report_key,
        tenant_id=schedule.tenant_id,
        schedule_id=schedule.id,
        recipients=recipients,
        output_format=schedule.output_format,
    )
    return _redirect("/reports", f"'{definition.name}' is being generated - it appears in the archive shortly.")


@router.post("/schedules/{schedule_id}/toggle", dependencies=[Depends(require_auth)])
def schedule_toggle(schedule_id: int, db: Session = Depends(get_db)) -> Response:
    schedule = db.get(ReportSchedule, schedule_id)
    if schedule is None:
        return _redirect("/schedules", "Schedule not found.", error=True)
    schedule.enabled = not schedule.enabled
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", f"Schedule {'enabled' if schedule.enabled else 'disabled'}.")


@router.post("/schedules/{schedule_id}/delete", dependencies=[Depends(require_auth)])
def schedule_delete(schedule_id: int, db: Session = Depends(get_db)) -> Response:
    schedule = db.get(ReportSchedule, schedule_id)
    if schedule is None:
        return _redirect("/schedules", "Schedule not found.", error=True)
    db.delete(schedule)
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", "Schedule deleted.")


# ---------------------------------------------------------------- reports
@router.get("/reports", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def reports_page(request: Request, db: Session = Depends(get_db)) -> Response:
    selected = _selected_tenant(request, db)
    stmt = select(ReportRun).order_by(ReportRun.started_at.desc()).limit(200)
    if selected:
        stmt = stmt.where((ReportRun.tenant_id == selected.id) | (ReportRun.tenant_id.is_(None)))
    runs = list(db.execute(stmt).scalars())
    tenant_names = {t.id: t.name for t in _tenants(db)}
    running_count = sum(1 for r in runs if r.status == "running")
    return templates.TemplateResponse(
        request, "reports.html", _base_ctx(request, db, runs=runs, tenant_names=tenant_names, running_count=running_count)
    )


@router.post("/reports/{report_key}/run", dependencies=[Depends(require_auth)])
def report_run_now(
    report_key: str,
    request: Request,
    background: BackgroundTasks,
    period_kind: str = Form(""),
    recipients: str = Form(""),
    output_format: str = Form("pdf"),
    db: Session = Depends(get_db),
) -> Response:
    """One 'Run now' per report. Tenant comes from the header switcher; 'All tenants' runs a per-tenant
    report for every enabled tenant. With recipients the report is e-mailed, without it is archived only."""
    try:
        definition = get_report(report_key)
    except KeyError:
        return _redirect("/reports", "Unknown report.", error=True)
    settings = load_settings(db)
    to = [r.strip() for r in recipients.replace(";", ",").split(",") if r.strip()]
    if to and not settings.smtp_configured:
        return _redirect("/reports", "Configure the SMTP relay under Settings before sending reports by e-mail.", error=True)
    period = period_kind if period_kind in ("daily", "weekly", "monthly") else None
    fmt = "html" if output_format == "html" else "pdf"

    if definition.scope == SCOPE_ALL:
        targets: list[int | None] = [None]
        label = "all tenants"
    else:
        selected = _selected_tenant(request, db)
        if selected is not None:
            targets = [selected.id]
            label = selected.name
        else:
            enabled = [t.id for t in _tenants(db) if t.enabled]
            if not enabled:
                return _redirect("/reports", "No enabled tenants - add one under Tenants first.", error=True)
            targets = list(enabled)
            label = f"{len(enabled)} tenant(s)"
    for tid in targets:
        background.add_task(
            run_report, report_key, tenant_id=tid, recipients=to, output_format=fmt, deliver=bool(to), period_kind=period
        )
    how = f"and sent to {', '.join(to)}" if to else "(archive only, no e-mail)"
    return _redirect("/reports", f"'{definition.name}' started for {label} {how}.")


@router.get("/reports/{run_id}/{fmt}", dependencies=[Depends(require_auth)])
def report_file(run_id: int, fmt: str, db: Session = Depends(get_db)) -> Response:
    run = db.get(ReportRun, run_id)
    if run is None:
        return _redirect("/reports", "Report not found.", error=True)
    path = run.pdf_path if fmt == "pdf" else run.html_path
    if not path or not Path(path).exists():
        return _redirect("/reports", "File is not available for this run.", error=True)
    media = "application/pdf" if fmt == "pdf" else "text/html"
    return FileResponse(path, media_type=media, filename=Path(path).name if fmt == "pdf" else None)


# --------------------------------------------------------------- settings
@router.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def settings_page(request: Request, db: Session = Depends(get_db)) -> Response:
    settings = load_settings(db)
    return templates.TemplateResponse(request, "settings.html", _base_ctx(request, db, settings=settings, all_verdicts=ALL_VERDICTS, pdf_available=_pdf_available()))


def _pdf_available() -> bool:
    from app.delivery.pdf import pdf_available

    return pdf_available()


@router.post("/settings", dependencies=[Depends(require_auth)])
async def settings_save(request: Request, db: Session = Depends(get_db)) -> Response:
    form = await request.form()
    values: dict[str, Any] = {
        "timezone": str(form.get("timezone", "UTC")).strip() or "UTC",
        "smtp_host": str(form.get("smtp_host", "")).strip(),
        "smtp_port": int(str(form.get("smtp_port", "587")) or 587),
        "smtp_username": str(form.get("smtp_username", "")).strip(),
        "smtp_password": str(form.get("smtp_password", "")),
        "smtp_from": str(form.get("smtp_from", "")).strip(),
        "smtp_starttls": form.get("smtp_starttls") == "on",
        "partner_recipients": str(form.get("partner_recipients", "")).strip(),
        "retention_days": max(30, int(str(form.get("retention_days", "400")) or 400)),
        "api_daily_budget": max(100, min(10000, int(str(form.get("api_daily_budget", "8000")) or 8000))),
        "backfill_window_days": max(1, min(31, int(str(form.get("backfill_window_days", "7")) or 7))),
        "convictions_verdicts": [v for v in form.getlist("convictions_verdicts") if v in ALL_VERDICTS],
        "base_url": str(form.get("base_url", "")).strip(),
    }
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(values["timezone"])
    except Exception:  # noqa: BLE001
        return _redirect("/settings", f"Unknown timezone '{values['timezone']}'. Use an IANA name such as Europe/Stockholm.", error=True)
    save_settings(db, values)
    db.commit()
    if scheduler.running:
        scheduler.set_timezone(values["timezone"])
    return _redirect("/settings", "Settings saved.")


@router.post("/settings/test-email", dependencies=[Depends(require_auth)])
def settings_test_email(to: str = Form(...), db: Session = Depends(get_db)) -> Response:
    from app.delivery.email import send_email

    settings = load_settings(db)
    try:
        send_email(settings, [to.strip()], "[ETD] Test message", "<p>ETD Report Scheduler can send e-mail.</p>")
    except Exception as exc:  # noqa: BLE001
        return _redirect("/settings", f"Test e-mail failed: {exc}", error=True)
    return _redirect("/settings", f"Test e-mail sent to {to.strip()}.")
