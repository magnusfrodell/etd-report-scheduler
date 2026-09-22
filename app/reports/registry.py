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

from app.reports import compromise_indicators, cross_tenant_rollup, executive_summary, health_check
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
