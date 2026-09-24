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
"""Registry of available reports.

To add a report: write ``app/reports/<key>.py`` with a ``build(session, ctx)``
function, add ``app/templates/reports/<key>.html`` and append a
:class:`ReportDefinition` below.
"""

from __future__ import annotations

from app.reports import (
    audit_compliance,
    auth_posture,
    campaigns,
    compromise_indicators,
    cross_tenant_rollup,
    executive_summary,
    exposure,
    health_check,
    posture_effectiveness,
    techniques,
    vap_index,
    vendor_risk,
)
from app.reports.base import SCOPE_ALL, SCOPE_TENANT, ReportDefinition

REPORTS: dict[str, ReportDefinition] = {}


def register(definition: ReportDefinition) -> ReportDefinition:
    if definition.key in REPORTS:
        raise ValueError(f"Report {definition.key!r} already registered")
    REPORTS[definition.key] = definition
    return definition


register(
    ReportDefinition(
        key="executive_summary",
        name="Executive summary",
        description="Trends and Impact Report numbers with period-over-period comparison, daily series, top targets and top threat senders.",
        scope=SCOPE_TENANT,
        period_kind="monthly",
        default_cron="0 7 1 * *",
        template="reports/executive_summary.html",
        build=executive_summary.build,
        subject="[ETD] Executive summary - {tenant} - {period}",
        category="overview",
        icon="chart",
        summary="Volumes, verdicts and top targets with period-over-period change.",
    )
)

register(
    ReportDefinition(
        key="compromise_indicators",
        name="Compromise indicators",
        description="Threat verdicts on outgoing and internal mail, grouped by sender - the classic sign of a compromised account.",
        scope=SCOPE_TENANT,
        period_kind="daily",
        default_cron="0 6 * * *",
        template="reports/compromise_indicators.html",
        build=compromise_indicators.build,
        subject="[ETD] Compromise indicators - {tenant} - {period}",
        category="threats",
        icon="alert",
        summary="Threats sent from your own accounts - the sign of a compromised mailbox.",
        has_findings=lambda d: d["total"] > 0,
    )
)

register(
    ReportDefinition(
        key="health_check",
        name="Health check",
        description="Yesterday's volume against the 30-day baseline, threat spikes and collector errors. Catches broken journaling.",
        scope=SCOPE_TENANT,
        period_kind="daily",
        default_cron="30 6 * * *",
        template="reports/health_check.html",
        build=health_check.build,
        subject="[ETD] Health check - {tenant} - {period}",
        category="operations",
        icon="pulse",
        summary="Yesterday's volume against the baseline, threat spikes and collector errors.",
        has_findings=lambda d: d["overall"] != "ok",
    )
)

register(
    ReportDefinition(
        key="vap_index",
        name="Very Attacked People",
        description="Attack index per mailbox from verdicts, technique severity, impersonation, retro delivery and missing remediation - with VIP flags, rank movement and attack concentration.",
        scope=SCOPE_TENANT,
        period_kind="monthly",
        default_cron="30 7 1 * *",
        template="reports/vap_index.html",
        build=vap_index.build,
        subject="[ETD] Very Attacked People - {tenant} - {period}",
        category="threats",
        icon="target",
        summary="Very Attacked People: who is targeted most, with VIP flags and rank changes.",
    )
)

register(
    ReportDefinition(
        key="campaigns",
        name="Campaign clusters",
        description="Convicted messages grouped into campaigns by subject, sender domain, URL host and attachment hash - reach, remediation state and what is still in inboxes.",
        scope=SCOPE_TENANT,
        period_kind="daily",
        default_cron="15 6 * * *",
        template="reports/campaigns.html",
        build=campaigns.build,
        subject="[ETD] Campaigns - {tenant} - {period}",
        category="threats",
        icon="layers",
        summary="Related threats clustered into campaigns by sender, subject, URL and attachment.",
        has_findings=lambda d: d["campaign_count"] > 0,
    )
)

register(
    ReportDefinition(
        key="exposure",
        name="Exposure and dwell time",
        description="How long retro-convicted messages sat in inboxes before verdict and remediation, plus every threat that is still not remediated, with age.",
        scope=SCOPE_TENANT,
        period_kind="weekly",
        default_cron="45 6 * * 1",
        template="reports/exposure.html",
        build=exposure.build,
        subject="[ETD] Exposure and dwell time - {tenant} - {period}",
        category="risk",
        icon="clock",
        summary="How long retro-convicted threats sat in inboxes, and what is still there.",
        has_findings=lambda d: d["unremediated_count"] > 0,
    )
)

register(
    ReportDefinition(
        key="techniques",
        name="Techniques and business risk",
        description="ETD detection techniques grouped into families, business risk, QR codes, callback-style lures, attachment types and abused legitimate services - with gateway and awareness recommendations.",
        scope=SCOPE_TENANT,
        period_kind="weekly",
        default_cron="0 7 * * 1",
        template="reports/techniques.html",
        build=techniques.build,
        subject="[ETD] Techniques and business risk - {tenant} - {period}",
        category="threats",
        icon="crosshair",
        summary="Detection techniques, business risk, QR codes, callback lures and attachment types.",
    )
)

register(
    ReportDefinition(
        key="vendor_risk",
        name="Vendor risk",
        description="Possibly compromised suppliers and partners, look-alike domains (incl. delivered ones via Log Export), new or rare senders with BEC/scam lures and an inventory of listed vendors.",
        scope=SCOPE_TENANT,
        period_kind="weekly",
        default_cron="30 7 * * 1",
        template="reports/vendor_risk.html",
        build=vendor_risk.build,
        subject="[ETD] Vendor risk - {tenant} - {period}",
        category="risk",
        icon="briefcase",
        summary="Compromised suppliers, look-alike domains and new senders with payment lures.",
        has_findings=lambda d: bool(d["compromised"] or d["lookalikes"] or d["rare"]),
    )
)

register(
    ReportDefinition(
        key="auth_posture",
        name="Authentication posture",
        description="SPF, DMARC, MTA-STS, TLS-RPT and BIMI for own domains, spoofing of those domains, Return-Path/Reply-To alignment and the DMARC policies of threat senders.",
        scope=SCOPE_TENANT,
        period_kind="monthly",
        default_cron="0 8 2 * *",
        template="reports/auth_posture.html",
        build=auth_posture.build,
        subject="[ETD] Authentication posture - {tenant} - {period}",
        category="risk",
        icon="lock",
        summary="SPF, DMARC and MTA-STS for your domains, spoofing and sender alignment.",
    )
)

register(
    ReportDefinition(
        key="audit_compliance",
        name="Audit and compliance",
        description="Who did what in ETD: privileged changes, reclassifications, remediations, failed actions and proof that the audit trail is complete - kept beyond ETD's 30 days.",
        scope=SCOPE_TENANT,
        period_kind="monthly",
        default_cron="15 8 1 * *",
        template="reports/audit_compliance.html",
        build=audit_compliance.build,
        subject="[ETD] Audit and compliance - {tenant} - {period}",
        category="operations",
        icon="clipboard",
        summary="Who did what in ETD, verdict changes and how completely the audit log was collected.",
    )
)

register(
    ReportDefinition(
        key="posture_effectiveness",
        name="Posture and effectiveness",
        description="Quarterly one-pager for management: posture score from weighted checks, effectiveness KPIs, six-month trend and the threat landscape in brief.",
        scope=SCOPE_TENANT,
        period_kind="quarterly",
        default_cron="0 8 1 1,4,7,10 *",
        template="reports/posture_effectiveness.html",
        build=posture_effectiveness.build,
        subject="[ETD] Posture and effectiveness - {tenant} - {period}",
        category="overview",
        icon="gauge",
        summary="Quarterly posture score, KPIs and prioritised gaps for management.",
    )
)

register(
    ReportDefinition(
        key="cross_tenant_rollup",
        name="Cross-tenant roll-up",
        description="All tenants ranked by threats with period-over-period change, spikes, collector errors and data gaps.",
        scope=SCOPE_ALL,
        period_kind="weekly",
        default_cron="0 7 * * 1",
        template="reports/cross_tenant_rollup.html",
        build=cross_tenant_rollup.build,
        subject="[ETD] Cross-tenant roll-up - {period}",
        category="overview",
        icon="grid",
        summary="Every tenant ranked by threats, with spikes, errors and data gaps.",
    )
)


def get_report(key: str) -> ReportDefinition:
    try:
        return REPORTS[key]
    except KeyError as exc:
        raise KeyError(f"Unknown report {key!r}; available: {', '.join(REPORTS)}") from exc


def tenant_reports() -> list[ReportDefinition]:
    return [r for r in REPORTS.values() if r.scope == SCOPE_TENANT]


def cross_tenant_reports() -> list[ReportDefinition]:
    return [r for r in REPORTS.values() if r.scope == SCOPE_ALL]
