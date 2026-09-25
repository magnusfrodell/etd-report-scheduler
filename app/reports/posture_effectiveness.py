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
"""Posture and effectiveness - the one-page quarterly for management.

A score (0-100) from weighted checks - remediation coverage, dwell time,
allow-list exposure, own-domain authentication, audit-trail completeness,
data quality, VIP coverage and false-positive rate - plus effectiveness KPIs,
a six-month trend and the threat landscape in brief. Unknown checks (no data)
are excluded from the score rather than counted as failures, checks that do not apply
(no threats, no retro verdicts) are marked n/a, and when less than 80 % of the weight could be
assessed no score or grade is given - missing data never earns points.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.i18n import Translator
from app.reports import audit_compliance, auth_posture, repo, techniques, vendor_risk
from app.reports.analysis import cluster_campaigns, fmt_hours, hours_between, percentile
from app.reports.base import ReportContext
from app.reports.periods import pct_change
from app.settings_store import THREAT_VERDICTS, load_settings
from app.tenant_profile import get_profile

STATUS_FACTOR = {"ok": 1.0, "warning": 0.5, "critical": 0.0}


EVIDENCE_FOR_GRADE = 80  # % of the scoring weight that must be assessable before a score and grade are shown


def _conviction_gap(tenant: Any, period: Any, stats_threats: int, convicted: int, tr: Translator | None = None) -> str | None:
    """Why the convicted-message data cannot be trusted for the period, or None.

    No convicted messages only means "no threats" when the collector covered the whole period and
    the daily statistics agree - otherwise it means "unknown", never "perfect"."""
    tr = tr or Translator()
    collected = tenant.convictions_collected_at
    if collected is None:
        return tr("Convicted messages have not been collected yet, so remediation cannot be assessed.")
    if collected < period.end:
        return tr("Convicted messages were last collected {collected:%Y-%m-%d %H:%M} UTC, before the period ended.", collected=collected)
    if stats_threats and not convicted:
        return tr("The daily statistics count {stats_threats} threat(s), but no convicted messages were collected for the period.", stats_threats=stats_threats)
    return None


def check(name: str, status: str, weight: int, detail: str, recommendation: str | None = None) -> dict[str, Any]:
    points = None if status in ("unknown", "na") else weight * STATUS_FACTOR[status]
    return {"name": name, "status": status, "weight": weight, "points": points, "detail": detail,
            "recommendation": recommendation if status in ("warning", "critical") else None}


def _months(end_day: date, count: int = 6) -> list[tuple[date, date]]:
    first = end_day.replace(day=1)
    out = []
    for _ in range(count):
        nxt = (first.replace(day=28) + timedelta(days=4)).replace(day=1)
        out.append((first, nxt - timedelta(days=1)))
        first = (first - timedelta(days=1)).replace(day=1)
    return list(reversed(out))


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "posture_effectiveness is a per-tenant report"
    p = ctx.period
    tenant = ctx.tenant
    tid = tenant.id
    settings = load_settings(session)

    cur = repo.stat_totals(session, tid, p.start_day, p.end_day)
    prev = repo.stat_totals(session, tid, p.previous_start_day, p.previous_end_day)
    threats = repo.convicted_messages(session, tid, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    remediated = [m for m in threats if m.action_type]
    automatic = [m for m in remediated if m.is_auto_remediated]
    retro = [m for m in threats if m.is_retro_verdict]
    dwell = [h for h in (hours_between(m.timestamp, m.action_timestamp) for m in retro if m.action_timestamp) if h is not None]
    median_dwell = percentile(dwell, 0.5)
    rule_data = [m for m in threats if m.rule_type]
    allow = [m for m in rule_data if any(k in (m.rule_type or "").lower() for k in ("allow", "safe", "trusted", "whitelist"))]

    auth = auth_posture.build(session, ctx)
    own_checks = [c for c in auth["own_checks"] if not c.get("error")]
    audit = audit_compliance.build(session, ctx)
    tech = techniques.build(session, ctx)
    vendor = vendor_risk.build(session, ctx)
    campaigns, _ = cluster_campaigns(threats, min_size=2)
    vips = [v for v in settings.vip_addresses.replace(";", ",").split(",") if v.strip()] + get_profile(tenant)["vip_addresses"]

    checks: list[dict[str, Any]] = []
    conviction_gap = _conviction_gap(tenant, p, cur.threats, len(threats), tr)
    if conviction_gap:
        checks.append(check(tr("Threats remediated"), "unknown", 20, conviction_gap))
        checks.append(check(tr("Remediation is automatic"), "unknown", 10, conviction_gap))
    elif threats:
        cov = len(remediated) / len(threats) * 100
        checks.append(check(tr("Threats remediated"), "ok" if cov >= 99 else ("warning" if cov >= 90 else "critical"), 20,
                            tr("{remediated_count} of {threats_count} threats were moved or deleted ({cov:.1f} %).", remediated_count=len(remediated), threats_count=len(threats), cov=cov),
                            tr("Some threat verdicts have no action - check for monitor-only policies and remediation errors in ETD.")))
        auto = len(automatic) / len(remediated) * 100 if remediated else 0.0
        checks.append(check(tr("Remediation is automatic"), "ok" if auto >= 90 else ("warning" if auto >= 70 else "critical"), 10,
                            tr("{auto:.0f} % of remediations were automatic.", auto=auto),
                            tr("Enable automatic remediation for every threat verdict so nothing waits for an analyst.")))
    else:
        checks.append(check(tr("Threats remediated"), "na", 20, tr("No threats in the period.")))
        checks.append(check(tr("Remediation is automatic"), "na", 10, tr("No threats in the period.")))
    # Retro-convicted mail that was never remediated counts with the time it has been exposed so far
    # (at least until the period ended) - leaving it out would flatter the median.
    open_retro = [m for m in retro if not m.action_timestamp]
    exposure = dwell + [h for h in (hours_between(m.timestamp, p.end) for m in open_retro) if h is not None]
    if conviction_gap:
        checks.append(check(tr("Dwell time for retro verdicts"), "unknown", 10, conviction_gap))
    elif exposure:
        median_exposure = percentile(exposure, 0.5)
        still_open = tr(", {open_retro_count} still not remediated", open_retro_count=len(open_retro)) if open_retro else ""
        checks.append(check(tr("Dwell time for retro verdicts"),
                            "ok" if median_exposure <= 1 and not open_retro else ("warning" if median_exposure <= 4 else "critical"), 10,
                            tr("Median {median_exposure} from delivery to remediation for {exposure_count} retro-convicted message(s){still_open}.", median_exposure=fmt_hours(median_exposure), exposure_count=len(exposure), still_open=still_open),
                            tr("Retro-convicted mail sits in inboxes too long - make sure retrospective verdicts trigger automatic remediation.")))
    else:
        checks.append(check(tr("Dwell time for retro verdicts"), "na", 10, tr("No retrospective verdicts in the period.")))
    if conviction_gap:
        checks.append(check(tr("No threats through allow-lists"), "unknown", 10, conviction_gap))
    elif not threats:
        checks.append(check(tr("No threats through allow-lists"), "na", 10, tr("No threats in the period.")))
    elif rule_data:
        checks.append(check(tr("No threats through allow-lists"), "ok" if not allow else ("warning" if len(allow) <= 3 else "critical"), 10,
                            tr("{allow_count} threat(s) matched an allow/safe rule.", allow_count=len(allow)),
                            tr("Review allow-list rules: threats were delivered because a rule trusted the sender.")))
    else:
        checks.append(check(tr("No threats through allow-lists"), "unknown", 10, tr("The API returned no rule information for this period.")))
    if own_checks:
        levels = [c["dmarc"]["level"] for c in own_checks]
        status = "ok" if all(x == "ok" for x in levels) else ("critical" if any(c["dmarc"].get("policy") in (None, "none") for c in own_checks) else "warning")
        checks.append(check(tr("DMARC enforcement on own domains"), status, 20,
                            ", ".join(f"{c['domain']}: {c['dmarc']['status']}" for c in own_checks),
                            tr("Move every own domain to DMARC p=reject - spoofing your own domain is the cheapest attack there is.")))
        spf_levels = [c["spf"]["level"] for c in own_checks]
        checks.append(check(tr("SPF on own domains"), "ok" if all(x == "ok" for x in spf_levels) else ("critical" if "critical" in spf_levels else "warning"), 5,
                            ", ".join(f"{c['domain']}: {c['spf']['status']}" for c in own_checks),
                            tr("Publish one SPF record per domain ending in -all or ~all, within 10 DNS lookups.")))
        with_tls = sum(1 for c in own_checks if c["mta_sts"] and c["tls_rpt"])
        checks.append(check(tr("MTA-STS and TLS-RPT"), "ok" if with_tls == len(own_checks) else ("warning" if with_tls else "critical"), 5,
                            tr("{with_tls} of {own_checks_count} domain(s) publish both.", with_tls=with_tls, own_checks_count=len(own_checks)),
                            tr("Publish MTA-STS and TLS-RPT so inbound TLS cannot be downgraded silently.")))
    else:
        checks.append(check(tr("DMARC enforcement on own domains"), "unknown", 20, tr("No own domains known or DNS unavailable.")))
    cov = audit["coverage"]
    if not settings.log_export_enabled or cov["status"] in ("no_data", "disabled"):
        checks.append(check(tr("Audit log collected"), "critical", 10, tr("Log Export is not collected, so there is no audit trail beyond ETD's 30 days."),
                            tr("Enable audit and message logs in ETD (Administration > Business > Export Log Preferences) and in Settings.")))
    else:
        partial = cov.get("partial_files", 0)
        checks.append(check(tr("Audit log collected"), "ok" if cov["pct"] >= 95 and not partial else ("warning" if cov["pct"] >= 50 else "critical"), 10,
                            tr("{pct} % of the period's hours collected, {gap_count} gap(s)", pct=cov['pct'], gap_count=len(cov['gaps']))
                            + (tr(", {partial} file(s) with unreadable lines", partial=partial) if partial else "") + ".",
                            tr("Keep the collector running - ETD deletes audit logs after 30 days, so gaps cannot be filled later.")))
    days_pct = cur.days_with_data / p.days * 100 if p.days else 0
    checks.append(check(tr("Data collection healthy"), "ok" if days_pct >= 95 and not tenant.last_error else ("warning" if days_pct >= 70 else "critical"), 5,
                        tr("Statistics for {days_with_data} of {days} days", days_with_data=cur.days_with_data, days=p.days) + (tr("; last error: {last_error}", last_error=tenant.last_error) if tenant.last_error else "") + ".",
                        tr("Fix collector errors on the Tenants page so reports cover the whole period.")))
    checks.append(check(tr("VIPs defined"), "ok" if vips else "warning", 5, tr("{vips_count} VIP mailbox(es) configured.", vips_count=len(vips)),
                        tr("List executives, finance and IT admins as VIPs so attacks on them are flagged.")))
    if audit["fp_rate"] is not None and (audit["to_neutral"] or audit["to_threat"] or audit["reclass_by_method"]):
        fp = audit["fp_rate"]
        checks.append(check(tr("False-positive rate"), "ok" if fp <= 2 else ("warning" if fp <= 5 else "critical"), 5,
                            tr("{to_neutral} manual reclassification(s) to neutral against {threats} threats ({fp} %).", to_neutral=audit['to_neutral'], threats=audit['threats'], fp=fp),
                            tr("Review what analysts release as neutral and tune policies or allow rules accordingly.")))
    else:
        checks.append(check(tr("False-positive rate"), "unknown", 5, tr("No verdict-change data (Log Export) for the period.")))

    scored = [c for c in checks if c["points"] is not None]
    score = round(sum(c["points"] for c in scored) / sum(c["weight"] for c in scored) * 100) if scored else None
    assessed_weight = sum(c["weight"] for c in scored)
    unknown_weight = sum(c["weight"] for c in checks if c["status"] == "unknown")
    evidence = round(assessed_weight / (assessed_weight + unknown_weight) * 100) if assessed_weight + unknown_weight else 0
    graded = score is not None and evidence >= EVIDENCE_FOR_GRADE
    recommendations = [c["recommendation"] for c in sorted(checks, key=lambda c: -(c["weight"] - (c["points"] or 0)) if c["points"] is not None else 0)
                       if c["recommendation"]]

    trend = []
    for start, end in _months(p.end_day):
        t = repo.stat_totals(session, tid, start, end)
        trend.append({"month": tr.short_month(start), "total": t.total_messages, "threats": t.threats,
                      "per_10k": round(t.threats / t.total_messages * 10000, 1) if t.total_messages else None,
                      "unwanted": t.unwanted, "days": t.days_with_data})

    return {
        "score": score,
        "evidence": evidence,
        "insufficient": score is not None and not graded,
        "provisional": graded and unknown_weight > 0,
        "grade": None if not graded else ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"),
        "checks": checks,
        "recommendations": recommendations[:8],
        "kpis": {
            "scanned": cur.total_messages, "scanned_prev": prev.total_messages,
            "threats": cur.threats, "threats_prev": prev.threats, "threats_change": pct_change(cur.threats, prev.threats),
            "per_10k": round(cur.threats / cur.total_messages * 10000, 1) if cur.total_messages else None,
            "unwanted": cur.unwanted, "retro": len(retro), "median_dwell": fmt_hours(median_dwell),
            "remediated_pct": round(len(remediated) / len(threats) * 100, 1) if threats else None,
            "auto_pct": round(len(automatic) / len(remediated) * 100, 1) if remediated else None,
        },
        "trend": trend,
        "landscape": {
            "families": tech["family_rows"][:4], "qr": tech["qr_count"], "callback": tech["callback_count"],
            "campaigns": len(campaigns), "compromised": vendor["counts"]["compromised"], "lookalikes": vendor["counts"]["lookalikes"],
            "spoofed": auth["spoofed_count"], "privileged_changes": audit["privileged_count"],
        },
    }
