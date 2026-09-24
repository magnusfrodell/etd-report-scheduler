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
from datetime import datetime, timedelta

from sqlalchemy import case, select, update
from sqlalchemy.orm import Session, object_session

from app.collectors.backfill import backfill_convictions
from app.collectors.convictions import collect_convictions
from app.collectors.logs import collect_logs
from app.collectors.stats import collect_daily_stats
from app.config import get_config
from app.db import session_scope
from app.delivery import archive as report_files
from app.etd.client import ETDClient
from app.etd.factory import client_for_tenant
from app.models import (
    AuditEvent,
    ConvictedMessage,
    DailyStat,
    DnsCache,
    LogFile,
    MessageEvent,
    ReportRun,
    SenderDomainDaily,
    Tenant,
    TopEntry,
    utcnow,
)
from app.settings_store import RuntimeSettings, load_settings

log = logging.getLogger(__name__)

ETD_DAILY_QUOTA = 10_000


def api_calls_today(tenant: Tenant) -> int:
    return tenant.api_calls_count if tenant.api_calls_day == utcnow().date() else 0


def record_api_usage(tenant: Tenant, client: ETDClient) -> None:
    """Add this client's requests to today's count with one atomic UPDATE.

    Collectors for the same tenant can overlap (the hourly jobs, backfill, "Collect now"); a
    read-modify-write on the loaded object would let one overwrite the other's usage."""
    used = client.request_count
    if not used:
        return
    session = object_session(tenant)
    today = utcnow().date()
    session.execute(
        update(Tenant)
        .where(Tenant.id == tenant.id)
        .values(
            api_calls_count=case((Tenant.api_calls_day == today, Tenant.api_calls_count + used), else_=used),
            api_calls_day=today,
        )
        .execution_options(synchronize_session=False)
    )
    session.refresh(tenant, ["api_calls_count", "api_calls_day"])


def budget_left(tenant: Tenant, settings: RuntimeSettings) -> int:
    return max(0, min(settings.api_daily_budget, ETD_DAILY_QUOTA) - api_calls_today(tenant))


def _set_stream_error(tenant: Tenant, stream: str, error: str | None) -> None:
    """Each collector keeps its own error; ``last_error`` shows the most recent one still open,
    so a collector that succeeds no longer hides another one's failure."""
    errors = dict(tenant.collector_errors or {})
    if error:
        errors[stream] = {"error": error[:2000], "at": utcnow().isoformat()}
    else:
        errors.pop(stream, None)
    tenant.collector_errors = errors or None
    latest = max(errors.values(), key=lambda e: e["at"], default=None)
    tenant.last_error = latest["error"] if latest else None
    tenant.last_error_at = datetime.fromisoformat(latest["at"]) if latest else None


def _record_error(tenant: Tenant, exc: Exception, stream: str) -> None:
    _set_stream_error(tenant, stream, f"{type(exc).__name__}: {exc}")


def _clear_error(tenant: Tenant, stream: str) -> None:
    _set_stream_error(tenant, stream, None)


def collect_stats_for_tenant(tenant_id: int) -> dict[str, object]:
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            return {"tenant_id": tenant_id, "status": "missing"}
        settings = load_settings(session)
        client = client_for_tenant(tenant)
        try:
            days = collect_daily_stats(session, tenant, client, days_back=settings.stats_days_back)
            _clear_error(tenant, "stats")
            return {"tenant_id": tenant_id, "status": "ok", "days": days}
        except Exception as exc:  # noqa: BLE001 - we want every failure recorded, not raised
            log.exception("Tenant %s: stats collection failed", tenant.name)
            _record_error(tenant, exc, "stats")
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
            _clear_error(tenant, "convictions")
            return {"tenant_id": tenant_id, "status": "ok", **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Tenant %s: conviction collection failed", tenant.name)
            _record_error(tenant, exc, "convictions")
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
            _clear_error(tenant, "backfill")
            return {"tenant_id": tenant_id, **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Tenant %s: backfill failed", tenant.name)
            _record_error(tenant, exc, "backfill")
            return {"tenant_id": tenant_id, "status": "failed", "error": str(exc)}
        finally:
            record_api_usage(tenant, client)
            client.close()


def collect_logs_for_tenant(tenant_id: int) -> dict[str, object]:
    """Log Export (audit + message events) within today's remaining API budget."""
    with session_scope() as session:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            return {"tenant_id": tenant_id, "status": "missing"}
        settings = load_settings(session)
        if not settings.log_export_enabled:
            tenant.logs_status = "disabled"
            tenant.logs_note = "Log Export collection is switched off in Settings."
            return {"tenant_id": tenant_id, "status": "disabled"}
        client = client_for_tenant(tenant)
        try:
            result = collect_logs(session, tenant, client, budget=budget_left(tenant, settings))
            tenant.logs_status = str(result["status"])
            tenant.logs_note = str(result.get("note") or "")[:2000]
            tenant.logs_collected_at = utcnow()
            _clear_error(tenant, "logs")
            return {"tenant_id": tenant_id, **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Tenant %s: Log Export collection failed", tenant.name)
            session.rollback()
            tenant = session.get(Tenant, tenant_id)
            tenant.logs_status = "error"
            tenant.logs_note = f"{type(exc).__name__}: {exc}"[:2000]
            _record_error(tenant, exc, "logs")
            return {"tenant_id": tenant_id, "status": "failed", "error": str(exc)}
        finally:
            record_api_usage(tenant, client)
            client.close()


def collect_all_for_tenant(tenant_id: int) -> list[dict[str, object]]:
    """Initial collection and 'Collect now': statistics (90 days on first run), a quick pull of
    the most recent convictions, history backfill, then 30 days of Log Export - all within budget."""
    results = [collect_stats_for_tenant(tenant_id), collect_convictions_for_tenant(tenant_id)]
    if results[-1].get("status") == "ok":
        results.append(backfill_for_tenant(tenant_id))
        results.append(collect_logs_for_tenant(tenant_id))
    return results


def collect_logs_all() -> list[dict[str, object]]:
    return [collect_logs_for_tenant(tid) for tid in enabled_tenant_ids()]


def backfill_all() -> list[dict[str, object]]:
    return [backfill_for_tenant(tid) for tid in enabled_tenant_ids()]


def enabled_tenant_ids() -> list[int]:
    with session_scope() as session:
        return list(session.execute(select(Tenant.id).where(Tenant.enabled.is_(True)).order_by(Tenant.id)).scalars())


def collect_stats_all() -> list[dict[str, object]]:
    return [collect_stats_for_tenant(tid) for tid in enabled_tenant_ids()]


def collect_convictions_all() -> list[dict[str, object]]:
    return [collect_convictions_for_tenant(tid) for tid in enabled_tenant_ids()]


def _purge_report_runs(session: Session, cutoff: datetime, doomed_files: list[str]) -> int:
    """Delete finished runs started before ``cutoff`` and note their files for removal after commit."""
    runs = list(session.execute(select(ReportRun).where(ReportRun.started_at < cutoff, ReportRun.status != "running")).scalars())
    for run in runs:
        doomed_files.extend(p for p in (run.html_path, run.pdf_path) if p)
        session.delete(run)
    return len(runs)


def purge_old_data() -> dict[str, int]:
    """Delete rows older than ``retention_days``, archived reports - rows *and* files - older than
    ``archive_retention_days``, and report files that no run refers to any more."""
    with session_scope() as session:
        settings = load_settings(session)
        cutoff = utcnow() - timedelta(days=settings.retention_days)
        doomed_files: list[str] = []
        deleted = {
            "daily_stats": session.query(DailyStat).filter(DailyStat.day < cutoff.date()).delete(synchronize_session=False),
            "top_entries": session.query(TopEntry).filter(TopEntry.period_end < cutoff.date()).delete(synchronize_session=False),
            "convicted_messages": session.query(ConvictedMessage)
            .filter(ConvictedMessage.timestamp < cutoff)
            .delete(synchronize_session=False),
            "report_runs": _purge_report_runs(session, utcnow() - timedelta(days=settings.archive_retention_days), doomed_files),
            "sender_domain_daily": session.query(SenderDomainDaily).filter(SenderDomainDaily.day < cutoff.date()).delete(synchronize_session=False),
            "log_files": session.query(LogFile).filter(LogFile.processed_at < utcnow() - timedelta(days=40)).delete(synchronize_session=False),
            "dns_cache": session.query(DnsCache).filter(DnsCache.checked_at < utcnow() - timedelta(days=30)).delete(synchronize_session=False),
        }
        audit_cutoff = utcnow() - timedelta(days=max(settings.audit_retention_days, settings.retention_days))
        deleted["audit_events"] = session.query(AuditEvent).filter(AuditEvent.timestamp < audit_cutoff).delete(synchronize_session=False)
        deleted["message_events"] = session.query(MessageEvent).filter(MessageEvent.timestamp < audit_cutoff).delete(synchronize_session=False)
    reports_dir = get_config().reports_dir
    deleted["report_files"], failed = report_files.remove_files(doomed_files, reports_dir)
    with session_scope() as session:
        known_runs = set(session.execute(select(ReportRun.id)).scalars())
    deleted["orphan_report_files"] = report_files.sweep_orphans(reports_dir, known_runs)
    if failed:
        log.warning("Retention purge: %d report file(s) could not be removed", failed)
    log.info("Retention purge (%d days): %s", settings.retention_days, deleted)
    return deleted
