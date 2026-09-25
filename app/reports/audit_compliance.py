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
"""Audit and compliance.

Evidence for NIS2 / ISO 27001 style reviews: who did what in ETD (Log Export
``audit``), every verdict change and remediation (message update events), and
how completely the trail was collected - ETD keeps these logs for 30 days, this
tool keeps them for ``audit_retention_days``. Coverage shows what this tool fetched;
it cannot prove that ETD exported every event.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.i18n import N_
from app.models import AuditEvent, LogFile, Tenant
from app.reports import repo
from app.reports.analysis import by_count
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS, load_settings
from app.tenant_profile import get_profile, user_label

PRIVILEGED = (N_("API access"), N_("Policy and configuration"), N_("User administration"))
_API_AGENTS = ("python", "curl", "postman", "go-http", "java", "okhttp", "axios", "node", "powershell", "insomnia", "httpie", "requests")
MAX_ROWS = 100


def group_of(category: str, action: str) -> str:
    c, a = (category or "").lower(), (action or "").lower()
    if c == "email" and "reclass" in a:
        return N_("Reclassification")
    if c == "email" and any(k in a for k in ("remediat", "move", "delete", "quarantine", "restore", "release")):
        return N_("Remediation")
    if any(k in a for k in ("api_client", "apiclient", "api_key", "apikey", "public_api")):
        return N_("API access")
    if any(k in a for k in ("policy", "rule", "setting", "config", "business", "connector", "allow", "block", "list", "domain", "export")):
        return N_("Policy and configuration")
    if any(k in a for k in ("login", "logout", "sign", "token", "session", "sso", "auth")):
        return N_("Sign-in and session")
    if c in ("user", "users", "tenant") and any(k in a for k in ("create", "update", "delete", "invite", "role", "add", "remove", "disable", "enable")):
        return N_("User administration")
    if c == "email":
        return N_("Message handling")
    return (category or "other").replace("_", " ").capitalize()


def agent_kind(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if not ua:
        return N_("unknown")
    if any(k in ua for k in _API_AGENTS):
        return N_("API / automation")
    if "mozilla" in ua:
        return N_("Web UI")
    return N_("other")


def meta_summary(meta: Any) -> str:
    if not isinstance(meta, dict):
        return ""
    parts = []
    for k, v in meta.items():
        if k == "request" or v in (None, "", [], {}):
            continue
        text = v if isinstance(v, str) else str(v)
        parts.append(f"{k}={text[:60]}")
        if len(parts) == 4:
            break
    return ", ".join(parts)


def log_coverage(tenant: Tenant, start: datetime, end: datetime, session: Session | None = None) -> dict[str, Any]:
    """How much of [start, end) the Log Export collector has requested, minus recorded gaps - plus, with a
    session, log files in the period that had unreadable lines and how many audit files arrived at all."""
    total_h = max(1.0, (end - start).total_seconds() / 3600)
    first, cursor = tenant.logs_first_hour, tenant.logs_cursor
    covered = 0.0
    if first and cursor:
        s, e = max(start, first), min(end, cursor)
        covered = max(0.0, (e - s).total_seconds() / 3600)
    gaps = []
    for g in tenant.logs_gaps or []:
        try:
            gs, ge = datetime.fromisoformat(g[0]), datetime.fromisoformat(g[1])
        except (TypeError, ValueError, IndexError):
            continue
        s, e = max(start, gs), min(end, ge)
        if e > s:
            covered -= (e - s).total_seconds() / 3600
            gaps.append({"start": s, "end": e})
    covered = max(0.0, covered)
    partial_files = unreadable = audit_files = 0
    if session is not None:
        first_day, last_day = start.date(), (end - timedelta(seconds=1)).date()
        in_period = (LogFile.tenant_id == tenant.id, LogFile.log_date >= first_day, LogFile.log_date <= last_day)
        row = session.execute(
            select(func.count(), func.coalesce(func.sum(LogFile.parse_errors), 0)).where(*in_period, LogFile.status == "partial")
        ).one()
        partial_files, unreadable = int(row[0]), int(row[1])
        audit_files = session.execute(select(func.count()).select_from(LogFile).where(*in_period, LogFile.log_type == "audit")).scalar_one()
    return {"partial_files": partial_files, "unreadable_lines": unreadable, "audit_files": audit_files,
            "hours": round(total_h), "covered_hours": round(covered), "pct": round(covered / total_h * 100, 1),
            "first": first, "cursor": cursor, "gaps": gaps, "status": tenant.logs_status, "note": tenant.logs_note}


def _norm_method(method: str | None) -> str:
    m = (method or "").lower()
    return "manual" if m in ("user", "manual") else (m or "unknown")


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    assert ctx.tenant is not None, "audit_compliance is a per-tenant report"
    p = ctx.period
    tenant = ctx.tenant
    labels = get_profile(tenant)["user_labels"]
    events: list[AuditEvent] = repo.audit_events(session, tenant.id, p.start, p.end)
    previous = repo.audit_events(session, tenant.id, p.previous_start, p.previous_end)
    msg_events = repo.message_events(session, tenant.id, p.start, p.end)

    groups = Counter(group_of(e.category, e.action) for e in events)
    prev_groups = Counter(group_of(e.category, e.action) for e in previous)
    failed = [e for e in events if (e.status or "").lower() not in ("success", "ok", "")]

    actors: dict[str, dict[str, Any]] = {}
    for e in events:
        key = e.user_id or "system"
        a = actors.setdefault(key, {"label": user_label(labels, e.user_id), "user_id": e.user_id, "events": 0, "groups": Counter(),
                                    "ips": set(), "agents": Counter(), "failed": 0, "first": e.timestamp, "last": e.timestamp})
        a["events"] += 1
        a["groups"][group_of(e.category, e.action)] += 1
        if e.user_ip:
            a["ips"].add(e.user_ip)
        a["agents"][agent_kind(e.user_agent)] += 1
        a["failed"] += 0 if (e.status or "").lower() in ("success", "ok", "") else 1
        a["first"], a["last"] = min(a["first"], e.timestamp), max(a["last"], e.timestamp)
    actor_rows = sorted(
        ({**a, "groups": dict(by_count(a["groups"], 4)), "ips": sorted(a["ips"])[:5], "ip_count": len(a["ips"]),
          "agents": dict(a["agents"])} for a in actors.values()),
        key=lambda r: -r["events"],
    )

    def row(e: AuditEvent) -> dict[str, Any]:
        return {"timestamp": e.timestamp, "who": user_label(labels, e.user_id), "ip": e.user_ip, "via": agent_kind(e.user_agent),
                "group": group_of(e.category, e.action), "action": e.action, "status": e.status, "detail": meta_summary(e.meta) or (e.comments or "")}

    privileged = [row(e) for e in events if group_of(e.category, e.action) in PRIVILEGED]

    reclass = [e for e in msg_events if e.kind == "reclassify"]
    remed = [e for e in msg_events if e.kind == "remediate"]
    human_reclass = [e for e in reclass if _norm_method(e.method) in ("manual", "api")]
    to_neutral = [e for e in human_reclass if (e.verdict or "").lower() == "neutral"]
    to_threat = [e for e in human_reclass if (e.verdict or "").lower() in THREAT_VERDICTS]
    per_user: dict[str, dict[str, int]] = defaultdict(lambda: {"reclassified": 0, "to_neutral": 0, "to_threat": 0, "remediated": 0})
    for e in human_reclass:
        u = per_user[user_label(labels, e.user_id or e.api_client_id)]
        u["reclassified"] += 1
        u["to_neutral"] += 1 if (e.verdict or "").lower() == "neutral" else 0
        u["to_threat"] += 1 if (e.verdict or "").lower() in THREAT_VERDICTS else 0
    for e in remed:
        if _norm_method(e.method) in ("manual", "api"):
            per_user[user_label(labels, e.user_id or e.api_client_id)]["remediated"] += 1

    threats = repo.convicted_messages(session, tenant.id, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    settings = load_settings(session)
    coverage = log_coverage(tenant, p.start, p.end, session)

    return {
        "coverage": coverage,
        "retention_days": max(settings.audit_retention_days, settings.retention_days),
        "log_export_enabled": settings.log_export_enabled,
        "total": len(events),
        "previous_total": len(previous),
        "group_rows": [{"group": g, "events": n, "previous": prev_groups.get(g, 0)} for g, n in by_count(groups)],
        "failed": [row(e) for e in failed[:MAX_ROWS]],
        "failed_count": len(failed),
        "actors": actor_rows[:MAX_ROWS],
        "privileged": privileged[:MAX_ROWS],
        "privileged_count": len(privileged),
        "reclass_by_method": dict(Counter(_norm_method(e.method) for e in reclass)),
        "remed_by_method": dict(Counter(_norm_method(e.method) for e in remed)),
        "remed_by_folder": dict(Counter((e.folder or e.action or "unknown") for e in remed)),
        "to_neutral": len(to_neutral),
        "to_threat": len(to_threat),
        "fp_rate": round(len(to_neutral) / len(threats) * 100, 2) if threats else None,
        "threats": len(threats),
        "per_user": sorted(({"who": k, **v} for k, v in per_user.items()), key=lambda r: -(r["reclassified"] + r["remediated"])),
        "unlabelled_users": sorted({e.user_id for e in events if e.user_id and e.user_id not in labels})[:20],
    }
