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
"""Server-rendered admin UI (Jinja2, no JavaScript framework).

Every handler receives a :class:`Principal` and checks it before acting; the
templates only *hide* what the principal cannot do, the handlers *enforce* it.
"""

from __future__ import annotations

import logging
import ssl
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app import __version__
from app.collectors import runner
from app.collectors.runner import ETD_DAILY_QUOTA, api_calls_today
from app.config import get_config
from app.crypto import secret_box
from app.db import get_db
from app.delivery import archive as report_files
from app.etd.factory import client_for_tenant
from app.etd.regions import REGIONS
from app.models import (
    GLOBAL_ROLES,
    TENANT_ROLES,
    ConvictedMessage,
    DailyStat,
    ReportRun,
    ReportSchedule,
    Tenant,
    TenantGrant,
    User,
    utcnow,
)
from app.reports.base import CATEGORIES, CATEGORY_KEYS, SCOPE_ALL, ReportDefinition
from app.reports.periods import PERIOD_KINDS
from app.reports.registry import REPORTS, get_report
from app.scheduler import scheduler, validate_cron
from app.services import run_report
from app.settings_store import ALL_VERDICTS, load_settings, save_settings
from app.tenant_profile import get_profile, parse_addresses, parse_domains, parse_labels
from app.web.auth import (
    SESSION_COOKIE,
    TENANT_COOKIE,
    authenticate,
    current_tenant_selection,
    hash_password,
    session_token,
    validate_new_password,
    verify_password,
)
from app.web.authz import Principal, ensure, forbid, get_principal, require_admin, require_tenant_admin
from app.web.icons import icon
from app.web.presenters import ago, period_label, run_view, zone
from app.web.security import login_limiter, safe_next

log = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
templates.env.globals["app_version"] = __version__
templates.env.globals["REGIONS"] = REGIONS
templates.env.globals["icon"] = icon
templates.env.globals["GLOBAL_ROLES"] = GLOBAL_ROLES
templates.env.globals["TENANT_ROLES"] = TENANT_ROLES


# ---------------------------------------------------------------- helpers
def _redirect(url: str, msg: str | None = None, error: bool = False) -> RedirectResponse:
    if msg:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{'err' if error else 'msg'}={quote(msg)}"
    return RedirectResponse(url, status_code=303)


def _selected_tenant(request: Request, db: Session, p: Principal) -> Tenant | None:
    sel = current_tenant_selection(request)
    if sel == "all":
        return None
    tenant = db.get(Tenant, int(sel))
    if tenant is None or not p.can(tenant.id, "viewer"):
        return None
    return tenant


def _base_ctx(request: Request, db: Session, p: Principal, **extra: Any) -> dict[str, Any]:
    return {
        "request": request,
        "principal": p,
        "tenants": p.visible_tenants(db),
        "selected_tenant": _selected_tenant(request, db, p),
        "selection": current_tenant_selection(request),
        "msg": request.query_params.get("msg"),
        "key_problem": getattr(request.app.state, "key_problem", None),
        "err": request.query_params.get("err"),
        "reports": REPORTS,
        **extra,
    }


def _tenant_or_404(db: Session, tenant_id: int, p: Principal, role: str) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or not p.can(tenant.id, "viewer"):
        raise forbid("Tenant not found or not visible to you.")
    ensure(p, tenant.id, role)
    return tenant


# ------------------------------------------------------------------ login
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"request": request, "err": request.query_params.get("err")})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"), db: Session = Depends(get_db)) -> Response:
    client = request.client.host if request.client else "?"
    wait = login_limiter.retry_after(username, client)
    if wait:
        log.warning("Sign-in for user %r from %s refused: too many failed attempts", username, client)
        return _redirect("/login", f"Too many failed sign-ins. Try again in {max(1, -(-wait // 60))} min.", error=True)
    user = authenticate(db, username, password)
    if user is None:
        login_limiter.failed(username, client)
        log.warning("Failed login for user %r from %s", username, client)
        return _redirect("/login", "Wrong username or password.", error=True)
    login_limiter.succeeded(username, client)
    db.commit()
    target = safe_next(next)
    resp = RedirectResponse(target, status_code=303)
    cfg = get_config()
    resp.set_cookie(SESSION_COOKIE, session_token(user), httponly=True, samesite="lax", secure=cfg.cookie_secure, max_age=cfg.session_max_age_seconds)
    resp.set_cookie(TENANT_COOKIE, "all", samesite="lax", max_age=365 * 24 * 3600)
    return resp


@router.post("/logout")
def logout() -> Response:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    resp.delete_cookie(TENANT_COOKIE)
    return resp


@router.post("/select-tenant")
def select_tenant(tenant: str = Form("all"), next: str = Form("/"), p: Principal = Depends(get_principal)) -> Response:
    value = tenant if tenant == "all" or (tenant.isdigit() and p.can(int(tenant), "viewer")) else "all"
    resp = RedirectResponse(safe_next(next), status_code=303)
    resp.set_cookie(TENANT_COOKIE, value, samesite="lax", max_age=365 * 24 * 3600)
    return resp


# -------------------------------------------------------------- dashboard
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenants = p.visible_tenants(db)
    selected = _selected_tenant(request, db, p)
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
    visible_ids = [t.id for t in tenants]
    runs_stmt = select(ReportRun).order_by(ReportRun.started_at.desc()).limit(8)
    runs_stmt = runs_stmt.where(ReportRun.tenant_id.in_(visible_ids) | ReportRun.tenant_id.is_(None)) if p.can_cross_tenant else runs_stmt.where(ReportRun.tenant_id.in_(visible_ids))
    recent_runs = list(db.execute(runs_stmt).scalars())
    tenant_names = {t.id: t.name for t in tenants}
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _base_ctx(request, db, p, cards=cards, recent_runs=recent_runs, tenant_names=tenant_names, next_runs=scheduler.next_run_times() if (scheduler.running and p.is_tenant_admin) else {}, scheduler_running=scheduler.running),
    )


# ---------------------------------------------------------------- tenants
def _history_label(t: Tenant) -> str:
    if t.backfill_done_at is not None:
        return "90 days"
    if t.backfill_cursor is not None:
        days = max(0, (utcnow() - t.backfill_cursor).days)
        return f"{min(days, 90)} of 90 days, backfilling"
    if t.convictions_collected_at is not None:
        return "recent only, backfill pending"
    return "not collected yet"


@router.get("/tenants", response_class=HTMLResponse)
def tenants_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    settings = load_settings(db)
    tenants = p.visible_tenants(db)
    grants: dict[int, list[TenantGrant]] = {t.id: [] for t in tenants}
    for g in db.execute(select(TenantGrant).where(TenantGrant.tenant_id.in_([t.id for t in tenants]))).scalars():
        grants.setdefault(g.tenant_id, []).append(g)
    users = list(db.execute(select(User).where(User.enabled.is_(True)).order_by(User.username)).scalars()) if any(p.can(t.id, "manager") for t in tenants) else []
    return templates.TemplateResponse(
        request,
        "tenants.html",
        _base_ctx(
            request,
            db,
            p,
            history={t.id: _history_label(t) for t in tenants},
            api_today={t.id: runner.api_calls_today(t) for t in tenants},
            budget=min(settings.api_daily_budget, runner.ETD_DAILY_QUOTA),
            grants=grants,
            users=users,
            profiles={t.id: get_profile(t) for t in tenants},
        ),
    )


@router.post("/tenants")
def tenant_create(
    background: BackgroundTasks,
    name: str = Form(...),
    region: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    api_key: str = Form(...),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_tenant_admin),
) -> Response:
    name = name.strip()
    if not name:
        return _redirect("/tenants", "Name is required.", error=True)
    if region not in REGIONS:
        return _redirect("/tenants", "Unknown region.", error=True)
    if db.execute(select(Tenant).where(Tenant.name == name)).scalar_one_or_none():
        return _redirect("/tenants", f"A tenant named '{name}' already exists.", error=True)
    box = secret_box()
    tenant = Tenant(name=name, region=region, client_id=client_id.strip(), client_secret_enc=box.encrypt(client_secret.strip()) or "", api_key_enc=box.encrypt(api_key.strip()) or "", enabled=True)
    db.add(tenant)
    db.commit()
    log.info("Tenant created: %s (%s) by %s", tenant.name, tenant.region, p.user.username)
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


@router.post("/tenants/{tenant_id}/edit")
def tenant_edit(
    tenant_id: int,
    name: str = Form(...),
    region: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(""),
    api_key: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    name = name.strip()
    if not name or region not in REGIONS:
        return _redirect("/tenants", "Name and a valid region are required.", error=True)
    clash = db.execute(select(Tenant).where(Tenant.name == name, Tenant.id != tenant.id)).scalar_one_or_none()
    if clash:
        return _redirect("/tenants", f"A tenant named '{name}' already exists.", error=True)
    box = secret_box()
    tenant.name, tenant.region, tenant.client_id = name, region, client_id.strip()
    if client_secret.strip():
        tenant.client_secret_enc = box.encrypt(client_secret.strip()) or ""
    if api_key.strip():
        tenant.api_key_enc = box.encrypt(api_key.strip()) or ""
    db.commit()
    log.info("Tenant %s edited by %s", tenant.name, p.user.username)
    return _redirect("/tenants", f"Tenant '{tenant.name}' updated. Run 'Test connection' if you changed the credentials.")


@router.post("/tenants/{tenant_id}/profile")
def tenant_profile(
    tenant_id: int,
    own_domains: str = Form(""),
    vendor_domains: str = Form(""),
    vip_addresses: str = Form(""),
    user_labels: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    own, bad_own = parse_domains(own_domains)
    vendors, bad_vendors = parse_domains(vendor_domains)
    vips, bad_vips = parse_addresses(vip_addresses)
    tenant.profile = {"own_domains": own, "vendor_domains": vendors, "vip_addresses": vips, "user_labels": parse_labels(user_labels)}
    db.commit()
    ignored = bad_own + bad_vendors + bad_vips
    if ignored:
        return _redirect("/tenants", f"Profile for '{tenant.name}' saved. Ignored invalid entries: {', '.join(ignored[:10])}", error=True)
    return _redirect("/tenants", f"Reporting profile for '{tenant.name}' saved.")


@router.post("/tenants/{tenant_id}/test")
def tenant_test(tenant_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "operator")
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


@router.post("/tenants/{tenant_id}/collect")
def tenant_collect(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "operator")
    background.add_task(runner.collect_all_for_tenant, tenant_id)
    return _redirect("/tenants", f"Collection started for '{tenant.name}' - refresh in a minute to see the result.")


@router.post("/tenants/{tenant_id}/toggle")
def tenant_toggle(tenant_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    tenant.enabled = not tenant.enabled
    db.commit()
    return _redirect("/tenants", f"Tenant '{tenant.name}' {'enabled' if tenant.enabled else 'disabled'}.")


@router.post("/tenants/{tenant_id}/delete")
def tenant_delete(tenant_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    name = tenant.name
    files = [f for r in db.execute(select(ReportRun).where(ReportRun.tenant_id == tenant.id)).scalars() for f in (r.html_path, r.pdf_path) if f]
    db.delete(tenant)
    db.commit()
    removed, failed = report_files.remove_files(files, get_config().reports_dir)
    log.warning("Tenant %s deleted by %s (%d report file(s) removed, %d failed)", name, p.user.username, removed, failed)
    if scheduler.running:
        scheduler.reload_report_jobs()
    note = f"Tenant '{name}' and all its data, including {removed} archived report file(s), were deleted."
    if failed:
        note += f" {failed} file(s) could not be removed now; the nightly clean-up tries again."
    resp = _redirect("/tenants", note)
    resp.set_cookie(TENANT_COOKIE, "all", samesite="lax")
    return resp


@router.post("/tenants/{tenant_id}/access")
def tenant_grant(tenant_id: int, user_id: int = Form(...), role: str = Form(...), db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    user = db.get(User, user_id)
    if user is None or role not in TENANT_ROLES:
        return _redirect("/tenants", "Unknown user or role.", error=True)
    grant = db.execute(select(TenantGrant).where(TenantGrant.tenant_id == tenant.id, TenantGrant.user_id == user.id)).scalar_one_or_none()
    if grant is None:
        db.add(TenantGrant(tenant_id=tenant.id, user_id=user.id, role=role))
    else:
        grant.role = role
    db.commit()
    log.info("Access: %s is now %s on %s (by %s)", user.username, role, tenant.name, p.user.username)
    return _redirect("/tenants", f"{user.label} is now {role} on '{tenant.name}'.")


@router.post("/tenants/{tenant_id}/access/{user_id}/revoke")
def tenant_revoke(tenant_id: int, user_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant = _tenant_or_404(db, tenant_id, p, "manager")
    deleted = db.query(TenantGrant).filter(TenantGrant.tenant_id == tenant.id, TenantGrant.user_id == user_id).delete(synchronize_session=False)
    db.commit()
    return _redirect("/tenants", "Access revoked." if deleted else "No such access grant.", error=not deleted)


# -------------------------------------------------------------- schedules
def _schedule_or_403(db: Session, schedule_id: int, p: Principal) -> ReportSchedule:
    schedule = db.get(ReportSchedule, schedule_id)
    if schedule is None:
        raise forbid("Schedule not found.")
    if schedule.tenant_id is None:
        if not p.can_cross_tenant:
            raise forbid("Cross-tenant schedules need the tenant administrator role.")
    else:
        ensure(p, schedule.tenant_id, "operator")
    return schedule


@router.get("/schedules", response_class=HTMLResponse)
def schedules_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    selected = _selected_tenant(request, db, p)
    visible_ids = p.visible_tenant_ids(db)
    stmt = select(ReportSchedule).order_by(ReportSchedule.tenant_id.nulls_first(), ReportSchedule.report_key)
    cond = (ReportSchedule.tenant_id == selected.id) if selected else ReportSchedule.tenant_id.in_(visible_ids)
    if p.can_cross_tenant:
        cond = cond | ReportSchedule.tenant_id.is_(None)
    schedules = list(db.execute(stmt.where(cond)).scalars())
    settings = load_settings(db)
    return templates.TemplateResponse(
        request,
        "schedules.html",
        _base_ctx(request, db, p, schedules=schedules, settings=settings, operator_tenants=p.tenants_where(db, "operator"), next_runs=scheduler.next_run_times() if (scheduler.running and p.is_tenant_admin) else {}),
    )


@router.post("/schedules")
def schedule_create(
    report_key: str = Form(...),
    tenant_id: str = Form(""),
    cron: str = Form(""),
    recipients: str = Form(""),
    output_format: str = Form("pdf"),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
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
    if definition.scope == SCOPE_ALL:
        if not p.can_cross_tenant:
            raise forbid("Cross-tenant schedules need the tenant administrator role.")
    else:
        if not tenant_id.isdigit() or db.get(Tenant, int(tenant_id)) is None:
            return _redirect("/schedules", f"'{definition.name}' is a per-tenant report - choose a tenant.", error=True)
        tid = int(tenant_id)
        ensure(p, tid, "operator")
    schedule = ReportSchedule(tenant_id=tid, report_key=report_key, cron=cron, recipients=recipients.strip(), output_format="html" if output_format == "html" else "pdf", enabled=True)
    db.add(schedule)
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", f"Schedule for '{definition.name}' created ({cron}, {settings.timezone}).")


@router.post("/schedules/{schedule_id}/run")
def schedule_run(schedule_id: int, background: BackgroundTasks, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    schedule = _schedule_or_403(db, schedule_id, p)
    settings = load_settings(db)
    definition = get_report(schedule.report_key)
    recipients = schedule.recipient_list or (settings.partner_recipient_list if definition.scope == SCOPE_ALL else [])
    background.add_task(run_report, schedule.report_key, tenant_id=schedule.tenant_id, schedule_id=schedule.id, recipients=recipients, output_format=schedule.output_format, triggered_by="manual")
    return _redirect("/reports", f"'{definition.name}' is being generated - it appears in the archive shortly.")


@router.post("/schedules/{schedule_id}/toggle")
def schedule_toggle(schedule_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    schedule = _schedule_or_403(db, schedule_id, p)
    schedule.enabled = not schedule.enabled
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", f"Schedule {'enabled' if schedule.enabled else 'disabled'}.")


@router.post("/schedules/{schedule_id}/delete")
def schedule_delete(schedule_id: int, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    schedule = _schedule_or_403(db, schedule_id, p)
    db.delete(schedule)
    db.commit()
    if scheduler.running:
        scheduler.reload_report_jobs()
    return _redirect("/schedules", "Schedule deleted. Its archived reports are kept.")


# ---------------------------------------------------------------- reports
PERIOD_NAMES = {"daily": "Daily", "weekly": "Weekly", "monthly": "Monthly", "quarterly": "Quarterly"}
PERIOD_CHOICES = (("daily", "Yesterday"), ("weekly", "Last week"), ("monthly", "Last month"), ("quarterly", "Last quarter"))
CARD_ORDER = (
    "executive_summary", "posture_effectiveness", "cross_tenant_rollup",
    "techniques", "campaigns", "vap_index", "compromise_indicators",
    "exposure", "vendor_risk", "auth_posture",
    "health_check", "audit_compliance",
)
ARCHIVE_PAGE_SIZE = 50


def _ordered_reports(p: Principal) -> list[ReportDefinition]:
    rank = {k: i for i, k in enumerate(CARD_ORDER)}
    visible = [r for r in REPORTS.values() if r.scope != SCOPE_ALL or p.can_cross_tenant]
    return sorted(visible, key=lambda r: rank.get(r.key, len(rank)))


def _category_of(r: ReportDefinition) -> str:
    return r.category if r.category in CATEGORY_KEYS else "other"


def _runs_scope(p: Principal, visible_ids: list[int], tenant_id: int | None = None) -> Any:
    cond = (ReportRun.tenant_id == tenant_id) if tenant_id is not None else ReportRun.tenant_id.in_(visible_ids)
    return (cond | ReportRun.tenant_id.is_(None)) if p.can_cross_tenant else cond


def _can_view_run(run: ReportRun, p: Principal, visible: dict[int, str]) -> bool:
    return p.can_cross_tenant if run.tenant_id is None else run.tenant_id in visible


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    """Report catalogue: one card per report, grouped by category, for the tenant in the header switcher."""
    settings = load_settings(db)
    tz = zone(settings.timezone)
    selected = _selected_tenant(request, db, p)
    visible_ids = p.visible_tenant_ids(db)
    cond = _runs_scope(p, visible_ids, selected.id if selected else None)
    counts = dict(db.execute(select(ReportRun.report_key, func.count()).where(cond).group_by(ReportRun.report_key)).all())
    ranked = (
        select(
            ReportRun.id,
            func.row_number().over(partition_by=ReportRun.report_key, order_by=(ReportRun.started_at.desc(), ReportRun.id.desc())).label("rn"),
        )
        .where(cond)
        .subquery()
    )
    latest = {
        r.report_key: r
        for r in db.execute(select(ReportRun).join(ranked, ReportRun.id == ranked.c.id).where(ranked.c.rn == 1)).scalars()
    }
    sched = (ReportSchedule.tenant_id == selected.id) if selected else ReportSchedule.tenant_id.in_(visible_ids)
    if p.can_cross_tenant:
        sched = sched | ReportSchedule.tenant_id.is_(None)
    schedules = dict(
        db.execute(
            select(ReportSchedule.report_key, func.count()).where(sched, ReportSchedule.enabled.is_(True)).group_by(ReportSchedule.report_key)
        ).all()
    )
    running_count = db.execute(select(func.count()).select_from(ReportRun).where(cond, ReportRun.status == "running")).scalar_one()
    can_run_tenant = p.can(selected.id, "operator") if selected else any(t.enabled for t in p.tenants_where(db, "operator"))
    now = utcnow()
    groups = []
    for cat in CATEGORIES:
        cards = []
        for r in _ordered_reports(p):
            if _category_of(r) != cat.key:
                continue
            last = latest.get(r.key)
            cards.append({
                "def": r,
                "count": counts.get(r.key, 0),
                "schedules": schedules.get(r.key, 0),
                "latest": last,
                "latest_ago": ago(last.started_at, now) if last else "",
                "latest_period": period_label(last.period_start, last.period_end, tz) if last else "",
                "can_run": p.can_cross_tenant if r.scope == SCOPE_ALL else can_run_tenant,
            })
        if cards:
            groups.append({"key": cat.key, "label": cat.label, "blurb": cat.blurb, "cards": cards})
    return templates.TemplateResponse(
        request,
        "reports.html",
        _base_ctx(request, db, p, groups=groups, running_count=running_count, period_names=PERIOD_NAMES, period_choices=PERIOD_CHOICES),
    )


@router.get("/quality", response_class=HTMLResponse)
def quality_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    """Collection health per tenant and data stream (the same model the alerts use)."""
    from app.quality import tenant_health, worst

    settings = load_settings(db)
    selected = _selected_tenant(request, db, p)
    tenants = [selected] if selected else p.visible_tenants(db)
    now = utcnow()
    rows = []
    for t in tenants:
        streams = tenant_health(db, t, settings, now)
        status = worst(streams)
        rows.append({"tenant": t, "streams": streams, "status": status, "dot": {"critical": "failed", "warning": "warning"}.get(status, status),
                     "api_calls": api_calls_today(t), "budget": min(settings.api_daily_budget, ETD_DAILY_QUOTA),
                     "can_collect": p.can(t.id, "operator") and t.enabled})
    attention = sum(1 for r in rows if r["status"] in ("warning", "critical"))
    alerts_on = bool(settings.alert_recipient_list and settings.smtp_configured)
    return templates.TemplateResponse(
        request, "quality.html", _base_ctx(request, db, p, rows=rows, attention=attention, alerts_on=alerts_on)
    )


@router.get("/archive", response_class=HTMLResponse)
def archive_page(
    request: Request,
    report: str = "",
    tenant: str = "",
    status: str = "",
    run: str = "",
    page: str = "1",
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
) -> Response:
    """Every generated report, filtered by report, tenant and status, with the selected one previewed."""
    settings = load_settings(db)
    tz = zone(settings.timezone)
    tenants = p.visible_tenants(db)
    names = {t.id: t.name for t in tenants}
    definition = REPORTS.get(report) if report else None
    if definition is not None and definition.scope == SCOPE_ALL and not p.can_cross_tenant:
        definition = None
    report = definition.key if definition else ""
    if definition is not None and definition.scope == SCOPE_ALL:
        tenant = "all"  # cross-tenant runs belong to no single tenant
    elif tenant == "":
        header = _selected_tenant(request, db, p)
        tenant = str(header.id) if header else "all"
    if tenant == "x" and not p.can_cross_tenant or tenant not in ("all", "x") and not (tenant.isdigit() and int(tenant) in names):
        tenant = "all"
    status = status if status in ("ok", "failed", "running") else ""
    page_no = max(1, int(page)) if page.isdigit() else 1

    base = _runs_scope(p, list(names))

    def where(*, by_report: bool = True, by_tenant: bool = True, by_status: bool = True) -> Any:
        conds = [base]
        if by_report and report:
            conds.append(ReportRun.report_key == report)
        if by_tenant and tenant == "x":
            conds.append(ReportRun.tenant_id.is_(None))
        elif by_tenant and tenant.isdigit():
            conds.append(ReportRun.tenant_id == int(tenant))
        if by_status and status:
            conds.append(ReportRun.status == status)
        return and_(*conds)

    report_counts = dict(db.execute(select(ReportRun.report_key, func.count()).where(where(by_report=False)).group_by(ReportRun.report_key)).all())
    tenant_counts = dict(db.execute(select(ReportRun.tenant_id, func.count()).where(where(by_tenant=False)).group_by(ReportRun.tenant_id)).all())
    status_counts = dict(db.execute(select(ReportRun.status, func.count()).where(where(by_status=False)).group_by(ReportRun.status)).all())
    rows = list(
        db.execute(
            select(ReportRun).where(where()).order_by(ReportRun.started_at.desc(), ReportRun.id.desc())
            .offset((page_no - 1) * ARCHIVE_PAGE_SIZE).limit(ARCHIVE_PAGE_SIZE + 1)
        ).scalars()
    )
    has_more = len(rows) > ARCHIVE_PAGE_SIZE
    rows = rows[:ARCHIVE_PAGE_SIZE]
    view = partial(run_view, definitions=REPORTS, tenant_names=names, tz=tz, now=utcnow())
    items = [view(r) for r in rows]
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for item in items:
        if not groups or groups[-1][0] != item["month"]:
            groups.append((item["month"], []))
        groups[-1][1].append(item)

    selected = None
    if run.isdigit():
        candidate = db.get(ReportRun, int(run))
        if candidate is not None and _can_view_run(candidate, p, names):
            selected = view(candidate)
    if selected is None and items:
        selected = items[0]

    ordered = _ordered_reports(p)
    report_options = []
    for cat in CATEGORIES:
        opts = [{"key": r.key, "name": r.name, "count": report_counts.get(r.key, 0)} for r in ordered if _category_of(r) == cat.key]
        if opts:
            report_options.append((cat.label, opts))
    tenant_options = [{"value": "all", "label": "All tenants" if p.is_tenant_admin else "All my tenants", "count": sum(tenant_counts.values())}]
    tenant_options += [{"value": str(t.id), "label": t.name, "count": tenant_counts.get(t.id, 0)} for t in tenants]
    if p.can_cross_tenant:
        tenant_options.append({"value": "x", "label": "Cross-tenant runs", "count": tenant_counts.get(None, 0)})
    status_options = [("", "All", sum(status_counts.values())), ("ok", "OK", status_counts.get("ok", 0)), ("failed", "Failed", status_counts.get("failed", 0))]
    if status_counts.get("running"):
        status_options.append(("running", "Running", status_counts["running"]))

    params = {"report": report, "tenant": tenant, "status": status}

    def url_with(**changes: Any) -> str:
        query = {k: v for k, v in {**params, **changes}.items() if v not in (None, "")}
        return "/archive?" + urlencode(query)

    can_run = False
    if definition is not None:
        can_run = p.can_cross_tenant if definition.scope == SCOPE_ALL else (tenant.isdigit() and p.can(int(tenant), "operator"))
    any_runs = db.execute(select(func.count()).select_from(ReportRun).where(base)).scalar_one() > 0
    return templates.TemplateResponse(
        request,
        "archive.html",
        _base_ctx(
            request, db, p,
            report=report, tenant=tenant, status=status, page=page_no, has_more=has_more,
            groups=groups, items=items, selected=selected, definition=definition,
            report_options=report_options, tenant_options=tenant_options, status_options=status_options,
            all_reports_count=sum(report_counts.values()), url_with=url_with, can_run=can_run, any_runs=any_runs,
            tenant_label=next((o["label"] for o in tenant_options if o["value"] == tenant), "All tenants"),
            tenant_filter_enabled=not (definition is not None and definition.scope == SCOPE_ALL),
            refresh=any(i["status"] == "running" for i in items), period_names=PERIOD_NAMES, tz_name=settings.timezone,
        ),
    )


@router.post("/reports/{report_key}/run")
def report_run_now(
    report_key: str,
    request: Request,
    background: BackgroundTasks,
    period_kind: str = Form(""),
    recipients: str = Form(""),
    output_format: str = Form("pdf"),
    tenant_id: str = Form(""),
    next: str = Form(""),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
) -> Response:
    """One 'Run now' per report. Tenant comes from the header switcher; 'All tenants' runs a per-tenant
    report for every enabled tenant the user may operate. With recipients the report is e-mailed."""
    back = safe_next(next, "/reports", ("/reports", "/archive"))
    try:
        definition = get_report(report_key)
    except KeyError:
        return _redirect(back, "Unknown report.", error=True)
    settings = load_settings(db)
    to = [r.strip() for r in recipients.replace(";", ",").split(",") if r.strip()]
    if to and not settings.smtp_configured:
        return _redirect(back, "Configure the SMTP relay under Settings before sending reports by e-mail.", error=True)
    period = period_kind if period_kind in PERIOD_KINDS else None
    fmt = "html" if output_format == "html" else "pdf"

    if definition.scope == SCOPE_ALL:
        if not p.can_cross_tenant:
            raise forbid("Cross-tenant reports need the tenant administrator role.")
        targets: list[int | None] = [None]
        label = "all tenants"
    else:
        selected = _tenant_or_404(db, int(tenant_id), p, "operator") if tenant_id.isdigit() else _selected_tenant(request, db, p)
        if selected is not None:
            ensure(p, selected.id, "operator")
            targets = [selected.id]
            label = selected.name
        else:
            allowed = [t.id for t in p.tenants_where(db, "operator") if t.enabled]
            if not allowed:
                return _redirect(back, "No enabled tenant you may run reports for - the operator role is required.", error=True)
            targets = list(allowed)
            label = f"{len(allowed)} tenant(s)"
    for tid in targets:
        background.add_task(run_report, report_key, tenant_id=tid, recipients=to, output_format=fmt, deliver=bool(to), period_kind=period)
    how = f"and sent to {', '.join(to)}" if to else "(archive only, no e-mail)"
    return _redirect(back, f"'{definition.name}' started for {label} {how}.")


@router.get("/reports/{run_id}/{fmt}")
def report_file(run_id: int, fmt: str, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    run = db.get(ReportRun, run_id)
    if run is None:
        return _redirect("/reports", "Report not found.", error=True)
    if run.tenant_id is None:
        if not p.can_cross_tenant:
            raise forbid("Cross-tenant reports need the tenant administrator role.")
    else:
        ensure(p, run.tenant_id, "viewer")
    path = run.pdf_path if fmt == "pdf" else run.html_path
    if not path or not Path(path).exists():
        return _redirect("/reports", "File is not available for this run.", error=True)
    media = "application/pdf" if fmt == "pdf" else "text/html"
    return FileResponse(path, media_type=media, filename=Path(path).name if fmt == "pdf" else None)


# --------------------------------------------------------------- settings
@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    from app.delivery.pdf import pdf_available

    settings = load_settings(db)
    from app.backup import storage_summary

    return templates.TemplateResponse(request, "settings.html", _base_ctx(request, db, p, settings=settings, all_verdicts=ALL_VERDICTS,
                                                                          pdf_available=pdf_available(), storage=storage_summary()))


@router.post("/settings/backup")
def settings_backup(db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    from app.backup import BackupNotSupported, create_backup

    keep = load_settings(db).backup_keep
    db.commit()
    try:
        path = create_backup(keep=keep or None)
    except BackupNotSupported as exc:
        return _redirect("/settings", str(exc), error=True)
    return _redirect("/settings", f"Backup written to {path}.")


@router.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    form = await request.form()
    values: dict[str, Any] = {
        "timezone": str(form.get("timezone", "UTC")).strip() or "UTC",
        "smtp_host": str(form.get("smtp_host", "")).strip(),
        "smtp_port": int(str(form.get("smtp_port", "587")) or 587),
        "smtp_username": str(form.get("smtp_username", "")).strip(),
        "smtp_password": str(form.get("smtp_password", "")),
        "smtp_from": str(form.get("smtp_from", "")).strip(),
        "smtp_starttls": form.get("smtp_starttls") == "on",
        "smtp_tls_verify": form.get("smtp_tls_verify") == "on",
        "smtp_ca_pem": str(form.get("smtp_ca_pem", "")).strip(),
        "partner_recipients": str(form.get("partner_recipients", "")).strip(),
        "retention_days": max(30, int(str(form.get("retention_days", "400")) or 400)),
        "api_daily_budget": max(100, min(10000, int(str(form.get("api_daily_budget", "8000")) or 8000))),
        "backfill_window_days": max(1, min(31, int(str(form.get("backfill_window_days", "7")) or 7))),
        "convictions_verdicts": [v for v in form.getlist("convictions_verdicts") if v in ALL_VERDICTS],
        "vip_addresses": str(form.get("vip_addresses", "")).strip(),
        "log_export_enabled": form.get("log_export_enabled") == "on",
        "audit_retention_days": max(90, int(str(form.get("audit_retention_days", "730")) or 730)),
        "archive_retention_days": max(30, int(str(form.get("archive_retention_days", "400")) or 400)),
        "alert_recipients": str(form.get("alert_recipients", "")).strip(),
        "backup_keep": max(0, min(60, int(str(form.get("backup_keep", "7")) or 7))),
        "base_url": str(form.get("base_url", "")).strip(),
    }
    if values["smtp_ca_pem"]:
        try:
            ssl.create_default_context().load_verify_locations(cadata=values["smtp_ca_pem"])
        except (ssl.SSLError, ValueError):
            return _redirect("/settings", "The extra CA certificate is not a valid PEM certificate.", error=True)
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


@router.post("/settings/test-email")
def settings_test_email(to: str = Form(...), db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    from app.delivery.email import send_email

    settings = load_settings(db)
    db.commit()
    try:
        send_email(settings, [to.strip()], "[ETD] Test message", "<p>ETD Report Scheduler can send e-mail.</p>")
    except ssl.SSLCertVerificationError as exc:
        return _redirect(
            "/settings",
            f"Test e-mail failed: the relay's certificate could not be verified ({exc.verify_message}). "
            "If the relay uses an internal CA, paste it under 'Extra trusted CA certificate'.",
            error=True,
        )
    except Exception as exc:  # noqa: BLE001
        return _redirect("/settings", f"Test e-mail failed: {exc}", error=True)
    return _redirect("/settings", f"Test e-mail sent to {to.strip()}.")


# ------------------------------------------------------------------ users
def _admin_count(db: Session, exclude_id: int | None = None) -> int:
    stmt = select(func.count()).select_from(User).where(User.role == "admin", User.enabled.is_(True))
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return int(db.execute(stmt).scalar_one())


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    users = list(db.execute(select(User).order_by(User.username)).scalars())
    grants: dict[int, list[TenantGrant]] = {u.id: [] for u in users}
    for g in db.execute(select(TenantGrant)).scalars():
        grants.setdefault(g.user_id, []).append(g)
    tenant_names = {t.id: t.name for t in db.execute(select(Tenant)).scalars()}
    return templates.TemplateResponse(request, "users.html", _base_ctx(request, db, p, users=users, grants=grants, tenant_names=tenant_names))


@router.post("/users")
def user_create(
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    role: str = Form("user"),
    password: str = Form(...),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_admin),
) -> Response:
    username = username.strip().lower()
    if not username or " " in username:
        return _redirect("/users", "Username is required and may not contain spaces.", error=True)
    if role not in GLOBAL_ROLES:
        return _redirect("/users", "Unknown role.", error=True)
    if err := validate_new_password(password):
        return _redirect("/users", err, error=True)
    if db.execute(select(User).where(func.lower(User.username) == username)).scalar_one_or_none():
        return _redirect("/users", f"User '{username}' already exists.", error=True)
    db.add(User(username=username, display_name=display_name.strip(), email=email.strip() or None, password_hash=hash_password(password), role=role, enabled=True))
    db.commit()
    log.info("User %s (%s) created by %s", username, role, p.user.username)
    return _redirect("/users", f"User '{username}' created with role {role}. Give them tenant access on the Tenants page.")


@router.post("/users/{user_id}/role")
def user_role(user_id: int, role: str = Form(...), db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    user = db.get(User, user_id)
    if user is None or role not in GLOBAL_ROLES:
        return _redirect("/users", "Unknown user or role.", error=True)
    if user.id == p.user.id and role != user.role:
        return _redirect("/users", "You cannot change your own role - ask another administrator.", error=True)
    if user.role == "admin" and role != "admin" and _admin_count(db, exclude_id=user.id) == 0:
        return _redirect("/users", "Cannot demote the last enabled administrator.", error=True)
    user.role = role
    db.commit()
    return _redirect("/users", f"'{user.username}' is now {role}.")


@router.post("/users/{user_id}/password")
def user_password(user_id: int, password: str = Form(...), db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    user = db.get(User, user_id)
    if user is None:
        return _redirect("/users", "Unknown user.", error=True)
    if err := validate_new_password(password):
        return _redirect("/users", err, error=True)
    user.password_hash = hash_password(password)
    db.commit()
    log.info("Password reset for %s by %s", user.username, p.user.username)
    return _redirect("/users", f"Password for '{user.username}' reset; their existing sessions are signed out.")


@router.post("/users/{user_id}/toggle")
def user_toggle(user_id: int, db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    user = db.get(User, user_id)
    if user is None:
        return _redirect("/users", "Unknown user.", error=True)
    if user.id == p.user.id:
        return _redirect("/users", "You cannot disable your own account.", error=True)
    if user.enabled and user.role == "admin" and _admin_count(db, exclude_id=user.id) == 0:
        return _redirect("/users", "Cannot disable the last enabled administrator.", error=True)
    user.enabled = not user.enabled
    db.commit()
    return _redirect("/users", f"'{user.username}' {'enabled' if user.enabled else 'disabled'}.")


@router.post("/users/{user_id}/delete")
def user_delete(user_id: int, db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> Response:
    user = db.get(User, user_id)
    if user is None:
        return _redirect("/users", "Unknown user.", error=True)
    if user.id == p.user.id:
        return _redirect("/users", "You cannot delete your own account.", error=True)
    if user.role == "admin" and user.enabled and _admin_count(db, exclude_id=user.id) == 0:
        return _redirect("/users", "Cannot delete the last enabled administrator.", error=True)
    name = user.username
    db.delete(user)
    db.commit()
    log.warning("User %s deleted by %s", name, p.user.username)
    return _redirect("/users", f"User '{name}' deleted.")


# ---------------------------------------------------------------- account
@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> Response:
    tenant_names = {t.id: t.name for t in p.visible_tenants(db)}
    return templates.TemplateResponse(request, "account.html", _base_ctx(request, db, p, tenant_names=tenant_names))


@router.post("/account/password")
def account_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_principal),
) -> Response:
    user = db.get(User, p.user.id)
    assert user is not None
    if not verify_password(current_password, user.password_hash):
        return _redirect("/account", "Current password is wrong.", error=True)
    if new_password != confirm_password:
        return _redirect("/account", "The new passwords do not match.", error=True)
    if err := validate_new_password(new_password):
        return _redirect("/account", err, error=True)
    user.password_hash = hash_password(new_password)
    db.commit()
    resp = _redirect("/account", "Password changed. Other sessions of your account are signed out.")
    cfg = get_config()
    resp.set_cookie(SESSION_COOKIE, session_token(user), httponly=True, samesite="lax", secure=cfg.cookie_secure, max_age=cfg.session_max_age_seconds)
    return resp
