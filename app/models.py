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
"""ORM models.

The application is multi-tenant by construction: every table that holds ETD
data has a ``tenant_id`` column and every query helper in
:mod:`app.reports.repo` requires it. A deployment with a single ETD tenant
simply has one row in ``tenants``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Timezone-safe datetime column.

    SQLite drops tzinfo, PostgreSQL keeps it. This decorator always binds UTC
    and always returns timezone-aware UTC values, so application code never
    compares naive and aware datetimes.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """One ETD tenant = one set of API credentials in one region."""

    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    region: Mapped[str] = mapped_column(String(8), nullable=False, default="de")  # us|de|au|in|ae|beta
    client_id: Mapped[str] = mapped_column(String(200), nullable=False)
    client_secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_enc: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    etd_tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    # Collector bookkeeping
    stats_collected_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    convictions_collected_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    convictions_watermark: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # History backfill: convictions are complete from backfill_cursor forward; NULL = not started.
    backfill_cursor: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    backfill_done_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    stats_backfilled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    # API quota bookkeeping (ETD allows 10 000 requests per tenant and day).
    api_calls_day: Mapped[date | None] = mapped_column(Date, nullable=True)
    api_calls_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    schedules: Mapped[list[ReportSchedule]] = relationship(back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Tenant {self.id} {self.name!r} {self.region}>"


class Setting(Base):
    """Runtime settings editable from the UI (key/value, JSON encoded)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)


class DailyStat(Base):
    """One row per tenant and UTC day, filled from the Reporting API (aggregationInterval=1d)."""

    __tablename__ = "daily_stats"
    __table_args__ = (UniqueConstraint("tenant_id", "day", name="uq_daily_stats_tenant_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    day: Mapped[date] = mapped_column(Date, nullable=False)

    total_messages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incoming: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outgoing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    internal: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    malicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    phishing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bec: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scam: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    spam: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    graymail: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retro_verdicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)

    @property
    def threats(self) -> int:
        return self.malicious + self.phishing + self.bec + self.scam

    @property
    def unwanted(self) -> int:
        return self.spam + self.graymail


class TopEntry(Base):
    """Top-10 lists from ``/v1/messages/report/top`` for a trailing period."""

    __tablename__ = "top_entries"
    __table_args__ = (Index("ix_top_entries_lookup", "tenant_id", "kind", "period_end"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # targets | threatSenders
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    email_address: Mapped[str] = mapped_column(String(320), nullable=False)
    malicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    phishing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bec: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scam: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


class ConvictedMessage(Base):
    """Threat-convicted messages pulled through the Message Search API.

    Neutral traffic is never stored per message; only the verdicts configured
    in the ``convictions_verdicts`` setting are collected.
    """

    __tablename__ = "convicted_messages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "etd_id", name="uq_convicted_tenant_etd_id"),
        Index("ix_convicted_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_convicted_tenant_dir", "tenant_id", "direction"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    etd_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    direction: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    original_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_retro_verdict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verdict_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    business_risk: Mapped[str | None] = mapped_column(String(80), nullable=True)
    techniques: Mapped[Any] = mapped_column(JSON, nullable=True)
    rule_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    from_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    envelope_from: Mapped[str | None] = mapped_column(String(320), nullable=True)
    to_addresses: Mapped[Any] = mapped_column(JSON, nullable=True)
    mailboxes: Mapped[Any] = mapped_column(JSON, nullable=True)
    subject: Mapped[str | None] = mapped_column(String(998), nullable=True)
    urls: Mapped[Any] = mapped_column(JSON, nullable=True)
    attachments: Mapped[Any] = mapped_column(JSON, nullable=True)
    secure_email_gateway: Mapped[str | None] = mapped_column(String(80), nullable=True)

    action_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action_folder: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_auto_remediated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    raw: Mapped[Any] = mapped_column(JSON, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)


class ReportSchedule(Base):
    """A scheduled report. ``tenant_id`` is NULL for reports that span all tenants."""

    __tablename__ = "report_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    report_key: Mapped[str] = mapped_column(String(60), nullable=False)
    cron: Mapped[str] = mapped_column(String(120), nullable=False)
    recipients: Mapped[str] = mapped_column(Text, nullable=False, default="")
    output_format: Mapped[str] = mapped_column(String(10), nullable=False, default="pdf")  # html | pdf
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    tenant: Mapped[Tenant | None] = relationship(back_populates="schedules")
    runs: Mapped[list[ReportRun]] = relationship(back_populates="schedule", cascade="all, delete-orphan")

    @property
    def recipient_list(self) -> list[str]:
        return [r.strip() for r in self.recipients.replace(";", ",").split(",") if r.strip()]


class ReportRun(Base):
    """Every generated report (scheduled or manual) is recorded and archived."""

    __tablename__ = "report_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("report_schedules.id", ondelete="SET NULL"), nullable=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    report_key: Mapped[str] = mapped_column(String(60), nullable=False)
    period_start: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")  # running|ok|failed
    html_path: Mapped[str | None] = mapped_column(String(400), nullable=True)
    pdf_path: Mapped[str | None] = mapped_column(String(400), nullable=True)
    delivered_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    schedule: Mapped[ReportSchedule | None] = relationship(back_populates="runs")
