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
"""Report definitions.

A report is a small object: a key, a scope (``tenant`` or ``all``), a default
period kind, a Jinja template and a ``build`` function that turns database
rows into a template context. Adding a report means adding one module and
registering it in :mod:`app.reports.registry`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import Tenant
from app.reports.periods import Period

SCOPE_TENANT = "tenant"
SCOPE_ALL = "all"


@dataclass
class ReportContext:
    period: Period
    generated_at: datetime
    timezone: str
    tenant: Tenant | None = None  # set for scope=tenant
    tenants: list[Tenant] = field(default_factory=list)  # set for scope=all

    @property
    def tenant_name(self) -> str:
        if self.tenant is not None:
            return self.tenant.name
        return "All tenants"


BuildFn = Callable[[Session, ReportContext], dict[str, Any]]


@dataclass(frozen=True)
class ReportDefinition:
    key: str
    name: str
    description: str
    scope: str
    period_kind: str
    default_cron: str
    template: str
    build: BuildFn
    subject: str  # format string with {tenant} and {period}
    category: str = "other"  # key in CATEGORIES - groups the cards on the Reports page
    icon: str = "file"  # name in app.web.icons
    summary: str = ""  # one line for the card; the description is shown on hover and in the archive

    @property
    def is_cross_tenant(self) -> bool:
        return self.scope == SCOPE_ALL


@dataclass(frozen=True)
class ReportCategory:
    key: str
    label: str
    blurb: str


CATEGORIES: tuple[ReportCategory, ...] = (
    ReportCategory("overview", "Overview", "Summaries for management and the partner roll-up"),
    ReportCategory("threats", "Threats", "Who is attacked, how, and by which campaigns"),
    ReportCategory("risk", "Exposure and risk", "What got through, your suppliers and your own domains"),
    ReportCategory("operations", "Operations and compliance", "Collector health and the audit trail"),
    ReportCategory("other", "Other", ""),
)
CATEGORY_KEYS = {c.key for c in CATEGORIES}
