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
"""Run collectors for one or all tenants. A failing tenant never stops the others."""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select

from app.collectors.backfill import backfill_convictions
from app.collectors.convictions import collect_convictions
from app.collectors.stats import collect_daily_stats
from app.db import session_scope
from app.etd.client import ETDClient
from app.etd.factory import client_for_tenant
from app.models import ConvictedMessage, DailyStat, ReportRun, Tenant, TopEntry, utcnow
from app.settings_store import RuntimeSettings, load_settings

log = logging.getLogger(__name__)

ETD_DAILY_QUOTA = 10_000


def api_calls_today(tenant: Tenant) -> int:
    return tenant.api_calls_count if tenant.api_calls_day == utcnow().date() else 0


def record_api_usage(tenant: Tenant, client: ETDClient) -> None:
    today = utcnow().date()
    if tenant.api_calls_day != today:
        tenant.api_calls_day = today
        tenant.api_calls_count = 0
    tenant.api_calls_count += client.request_count


def budget_left(tenant: Tenant, settings: RuntimeSettings) -> int:
    return max(0, min(settings.api_daily_budget, ETD_DAILY_QUOTA) - api_calls_today(tenant))


def _record_error(tenant: Tenant, exc: Exception) -> None:
    tenant.last_error = f"{type(exc).__name__}: {exc}"[:2000]
    tenant.last_error_at = utcnow()


def _clear_error(tenant: Tenant) -> None:
    tenant.last_error = None
    tenant.last_error_at = None


def collect_stats_for_tenant(tenant_id: int) -> dict[str, object]:
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            return {"tenant_id": tenant_id, "status": "missing"}
        settings = load_settings(session)
        client = client_for_tenant(tenant)
        try:
            days = collect_daily_stats(session, tenant, client, days_back=settings.stats_days_back)
            _clear_error(tenant)
            return {"tenant_id": tenant_id, "status": "ok", "days": days}
        except Exception as exc:  # noqa: BLE001 - we want every failure recorded, not raised
            log.exception("Tenant %s: stats collection failed", tenant.name)
            _record_error(tenant, exc)
            return {"tenant_id": tenant_id, "status": "failed", "error": str(exc)}
        finally:
            record_api_usage(tenant, client)
            client.close()


def collect_convictions_for_tenant(tenant_id: int) -> dict[str, object]:
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            return {"tenant_id": tenant_id, "status": "missing"}
        settings = load_settings(session)
        client = client_for_tenant(tenant)
        try:
            result = collect_convictions(
                session,
                tenant,
                client,
                verdicts=settings.convictions_verdicts,
                initial_days=settings.convictions_initial_days,
                rescan_days=settings.convictions_rescan_days,
            )
            _clear_error(tenant)
            return {"tenant_id": tenant_id, "status": "ok", **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Tenant %s: conviction collection failed", tenant.name)
            _record_error(tenant, exc)
            return {"tenant_id": tenant_id, "status": "failed", "error": str(exc)}
        finally:
            record_api_usage(tenant, client)
            client.close()


def backfill_for_tenant(tenant_id: int) -> dict[str, object]:
    """Fill history back to the 90-day horizon within today's remaining API budget."""
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            return {"tenant_id": tenant_id, "status": "missing"}
        if tenant.backfill_done_at is not None:
            return {"tenant_id": tenant_id, "status": "skipped"}
        settings = load_settings(session)
        client = client_for_tenant(tenant)
        try:
            result = backfill_convictions(
                session,
                tenant,
                client,
                verdicts=settings.convictions_verdicts,
                budget=budget_left(tenant, settings),
                window_days=settings.backfill_window_days,
            )
            _clear_error(tenant)
            return {"tenant_id": tenant_id, **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Tenant %s: backfill failed", tenant.name)
            _record_error(tenant, exc)
            return {"tenant_id": tenant_id, "status": "failed", "error": str(exc)}
        finally:
            record_api_usage(tenant, client)
            client.close()


def collect_all_for_tenant(tenant_id: int) -> list[dict[str, object]]:
    """Initial collection and 'Collect now': statistics (90 days on first run), a quick pull of
    the most recent convictions, then history backfill within today's budget."""
    results = [collect_stats_for_tenant(tenant_id), collect_convictions_for_tenant(tenant_id)]
    if results[-1].get("status") == "ok":
        results.append(backfill_for_tenant(tenant_id))
    return results


def backfill_all() -> list[dict[str, object]]:
    return [backfill_for_tenant(tid) for tid in enabled_tenant_ids()]


def enabled_tenant_ids() -> list[int]:
    with session_scope() as session:
        return list(session.execute(select(Tenant.id).where(Tenant.enabled.is_(True)).order_by(Tenant.id)).scalars())


def collect_stats_all() -> list[dict[str, object]]:
    return [collect_stats_for_tenant(tid) for tid in enabled_tenant_ids()]


def collect_convictions_all() -> list[dict[str, object]]:
    return [collect_convictions_for_tenant(tid) for tid in enabled_tenant_ids()]


def purge_old_data() -> dict[str, int]:
    """Delete rows older than ``retention_days``. Report archives on disk are kept."""
    with session_scope() as session:
        settings = load_settings(session)
        cutoff = utcnow() - timedelta(days=settings.retention_days)
        deleted = {
            "daily_stats": session.query(DailyStat).filter(DailyStat.day < cutoff.date()).delete(synchronize_session=False),
            "top_entries": session.query(TopEntry).filter(TopEntry.period_end < cutoff.date()).delete(synchronize_session=False),
            "convicted_messages": session.query(ConvictedMessage)
            .filter(ConvictedMessage.timestamp < cutoff)
            .delete(synchronize_session=False),
            "report_runs": session.query(ReportRun).filter(ReportRun.started_at < cutoff).delete(synchronize_session=False),
        }
    log.info("Retention purge (%d days): %s", settings.retention_days, deleted)
    return deleted
