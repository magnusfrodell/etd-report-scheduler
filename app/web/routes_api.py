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
"""Small JSON API: health for Docker/monitoring, plus automation hooks.

Everything except ``/api/health`` requires the same session cookie as the UI
and is subject to the same roles.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.collectors import runner
from app.config import get_config
from app.db import get_db
from app.models import Tenant, User
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS, get_report
from app.scheduler import scheduler
from app.services import run_report
from app.web.authz import Principal, ensure, forbid, get_principal, require_admin, require_tenant_admin

router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request, db: Session = Depends(get_db)) -> dict:
    tenant_count = len(db.execute(select(Tenant.id)).scalars().all())
    return {"status": "ok", "version": __version__, "scheduler_running": scheduler.running, "tenants": tenant_count,
            "encryption_key": "mismatch" if getattr(request.app.state, "key_problem", None) else "ok",
            "demo_mode": get_config().demo_mode}


@router.get("/me")
def me(db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    return {
        "username": p.user.username,
        "display_name": p.user.label,
        "role": p.user.role,
        "tenants": [{"id": t.id, "name": t.name, "role": p.tenant_role(t.id)} for t in p.visible_tenants(db)],
    }


@router.get("/tenants")
def list_tenants(db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> list[dict]:
    return [
        {
            "id": t.id,
            "name": t.name,
            "region": t.region,
            "enabled": t.enabled,
            "your_role": p.tenant_role(t.id),
            "stats_collected_at": t.stats_collected_at,
            "convictions_collected_at": t.convictions_collected_at,
            "backfill_cursor": t.backfill_cursor,
            "backfill_done_at": t.backfill_done_at,
            "api_calls_today": runner.api_calls_today(t),
            "logs_status": t.logs_status,
            "logs_cursor": t.logs_cursor,
            "logs_collected_at": t.logs_collected_at,
            "logs_note": t.logs_note,
            "last_error": t.last_error,
        }
        for t in p.visible_tenants(db)
    ]


@router.get("/reports")
def list_reports(p: Principal = Depends(get_principal)) -> list[dict]:
    return [
        {"key": r.key, "name": r.name, "category": r.category, "scope": r.scope, "period": r.period_kind,
         "default_cron": r.default_cron, "summary": r.summary, "description": r.description}
        for r in REPORTS.values()
        if r.scope != SCOPE_ALL or p.can_cross_tenant
    ]


@router.post("/tenants/{tenant_id}/collect")
def api_collect(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    if db.get(Tenant, tenant_id) is None or not p.can(tenant_id, "viewer"):
        raise HTTPException(404, "Tenant not found")
    ensure(p, tenant_id, "operator")
    background.add_task(runner.collect_all_for_tenant, tenant_id)
    return {"status": "started", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/logs")
def api_logs(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    if db.get(Tenant, tenant_id) is None or not p.can(tenant_id, "viewer"):
        raise HTTPException(404, "Tenant not found")
    ensure(p, tenant_id, "operator")
    background.add_task(runner.collect_logs_for_tenant, tenant_id)
    return {"status": "started", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/backfill")
def api_backfill(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    if db.get(Tenant, tenant_id) is None or not p.can(tenant_id, "viewer"):
        raise HTTPException(404, "Tenant not found")
    ensure(p, tenant_id, "operator")
    background.add_task(runner.backfill_for_tenant, tenant_id)
    return {"status": "started", "tenant_id": tenant_id}


@router.post("/reports/{report_key}/run")
def api_run_report(report_key: str, background: BackgroundTasks, tenant_id: int | None = None, deliver: bool = False, db: Session = Depends(get_db), p: Principal = Depends(get_principal)) -> dict:
    try:
        definition = get_report(report_key)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    if definition.scope == SCOPE_ALL:
        if not p.can_cross_tenant:
            raise forbid("Cross-tenant reports need the tenant administrator role.")
        tenant_id = None
    else:
        if tenant_id is None or db.get(Tenant, tenant_id) is None:
            raise HTTPException(400, "tenant_id is required for a per-tenant report")
        ensure(p, tenant_id, "operator")
    background.add_task(run_report, report_key, tenant_id=tenant_id, deliver=deliver, triggered_by="api")
    return {"status": "started", "report": report_key, "tenant_id": tenant_id}


@router.get("/scheduler")
def scheduler_state(p: Principal = Depends(require_tenant_admin)) -> dict:
    return {"running": scheduler.running, "timezone": scheduler.timezone, "next_runs": scheduler.next_run_times()}


@router.get("/users")
def list_users(db: Session = Depends(get_db), p: Principal = Depends(require_admin)) -> list[dict]:
    return [
        {"id": u.id, "username": u.username, "display_name": u.display_name, "email": u.email, "role": u.role, "enabled": u.enabled, "last_login_at": u.last_login_at}
        for u in db.execute(select(User).order_by(User.username)).scalars()
    ]
