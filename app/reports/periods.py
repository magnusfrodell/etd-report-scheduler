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
"""Reporting periods.

A report always covers the *previous* complete period relative to "now" in
the configured timezone, plus the period before that for comparison. Daily
statistics are stored per UTC day (that is how ETD aggregates), so period
boundaries are expressed as UTC dates for the daily tables and as
timezone-aware datetimes for the message tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

PERIOD_KINDS = ("daily", "weekly", "monthly")


@dataclass(frozen=True)
class Period:
    kind: str
    start: datetime  # inclusive, tz-aware
    end: datetime  # exclusive, tz-aware
    previous_start: datetime
    previous_end: datetime

    @property
    def days(self) -> int:
        return max(1, (self.end - self.start).days)

    @property
    def start_day(self) -> date:
        return self.start.date()

    @property
    def end_day(self) -> date:
        """Inclusive last day."""
        return (self.end - timedelta(days=1)).date()

    @property
    def previous_start_day(self) -> date:
        return self.previous_start.date()

    @property
    def previous_end_day(self) -> date:
        return (self.previous_end - timedelta(days=1)).date()

    @property
    def label(self) -> str:
        if self.kind == "daily":
            return self.start.strftime("%Y-%m-%d")
        if self.kind == "monthly":
            return self.start.strftime("%B %Y")
        return f"{self.start:%Y-%m-%d} – {self.end_day:%Y-%m-%d}"

    @property
    def previous_label(self) -> str:
        if self.kind == "daily":
            return self.previous_start.strftime("%Y-%m-%d")
        if self.kind == "monthly":
            return self.previous_start.strftime("%B %Y")
        return f"{self.previous_start:%Y-%m-%d} – {self.previous_end_day:%Y-%m-%d}"


def _midnight(d: date, tz: ZoneInfo) -> datetime:
    return datetime(d.year, d.month, d.day, tzinfo=tz)


def _month_start(d: date) -> date:
    return d.replace(day=1)


def _prev_month_start(d: date) -> date:
    first = _month_start(d)
    return _month_start(first - timedelta(days=1))


def period_for(kind: str, now: datetime, tz: ZoneInfo) -> Period:
    """Previous complete period of ``kind`` ending before ``now`` (in ``tz``)."""
    if kind not in PERIOD_KINDS:
        raise ValueError(f"Unknown period kind {kind!r}")
    local_now = now.astimezone(tz)
    today = local_now.date()

    if kind == "daily":
        start_d = today - timedelta(days=1)
        end_d = today
        prev_start_d = start_d - timedelta(days=1)
        prev_end_d = start_d
    elif kind == "weekly":
        this_monday = today - timedelta(days=today.weekday())
        start_d = this_monday - timedelta(days=7)
        end_d = this_monday
        prev_start_d = start_d - timedelta(days=7)
        prev_end_d = start_d
    else:  # monthly
        end_d = _month_start(today)
        start_d = _prev_month_start(today)
        prev_end_d = start_d
        prev_start_d = _prev_month_start(start_d)

    return Period(
        kind=kind,
        start=_midnight(start_d, tz),
        end=_midnight(end_d, tz),
        previous_start=_midnight(prev_start_d, tz),
        previous_end=_midnight(prev_end_d, tz),
    )


def pct_change(current: float, previous: float) -> float | None:
    if previous == 0:
        return None  # no baseline - rendered as "new" rather than an inflated percentage
    return round((current - previous) / previous * 100.0, 1)
