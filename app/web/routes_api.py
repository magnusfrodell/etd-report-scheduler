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

Everything except ``/api/health`` requires the same session cookie as the UI.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.collectors import runner
from app.db import get_db
from app.models import Tenant
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS, get_report
from app.scheduler import scheduler
from app.services import run_report
from app.web.auth import require_auth

router = APIRouter(prefix="/api")


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    tenant_count = len(db.execute(select(Tenant.id)).scalars().all())
    return {"status": "ok", "version": __version__, "scheduler_running": scheduler.running, "tenants": tenant_count}


@router.get("/tenants", dependencies=[Depends(require_auth)])
def list_tenants(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": t.id,
            "name": t.name,
            "region": t.region,
            "enabled": t.enabled,
            "stats_collected_at": t.stats_collected_at,
            "convictions_collected_at": t.convictions_collected_at,
            "backfill_cursor": t.backfill_cursor,
            "backfill_done_at": t.backfill_done_at,
            "api_calls_today": runner.api_calls_today(t),
            "last_error": t.last_error,
        }
        for t in db.execute(select(Tenant).order_by(Tenant.name)).scalars()
    ]


@router.get("/reports", dependencies=[Depends(require_auth)])
def list_reports() -> list[dict]:
    return [
        {"key": r.key, "name": r.name, "scope": r.scope, "period": r.period_kind, "default_cron": r.default_cron, "description": r.description}
        for r in REPORTS.values()
    ]


@router.post("/tenants/{tenant_id}/collect", dependencies=[Depends(require_auth)])
def api_collect(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    if db.get(Tenant, tenant_id) is None:
        raise HTTPException(404, "Tenant not found")
    background.add_task(runner.collect_all_for_tenant, tenant_id)
    return {"status": "started", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/backfill", dependencies=[Depends(require_auth)])
def api_backfill(tenant_id: int, background: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    if db.get(Tenant, tenant_id) is None:
        raise HTTPException(404, "Tenant not found")
    background.add_task(runner.backfill_for_tenant, tenant_id)
    return {"status": "started", "tenant_id": tenant_id}


@router.post("/reports/{report_key}/run", dependencies=[Depends(require_auth)])
def api_run_report(report_key: str, background: BackgroundTasks, tenant_id: int | None = None, deliver: bool = False, db: Session = Depends(get_db)) -> dict:
    try:
        definition = get_report(report_key)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    if definition.scope != SCOPE_ALL and (tenant_id is None or db.get(Tenant, tenant_id) is None):
        raise HTTPException(400, "tenant_id is required for a per-tenant report")
    background.add_task(run_report, report_key, tenant_id=tenant_id if definition.scope != SCOPE_ALL else None, deliver=deliver)
    return {"status": "started", "report": report_key, "tenant_id": tenant_id}


@router.get("/scheduler", dependencies=[Depends(require_auth)])
def scheduler_state() -> dict:
    return {"running": scheduler.running, "timezone": scheduler.timezone, "next_runs": scheduler.next_run_times()}
