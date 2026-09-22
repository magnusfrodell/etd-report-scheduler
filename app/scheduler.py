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
"""Scheduler.

System jobs (collectors, retention) are fixed; report jobs are loaded from
the ``report_schedules`` table and reloaded whenever a schedule or the
timezone setting changes. All jobs run in a small thread pool inside the
container - no external queue needed.
"""

from __future__ import annotations

import logging
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.collectors import runner
from app.db import session_scope
from app.models import ReportSchedule
from app.services import run_schedule
from app.settings_store import load_settings

log = logging.getLogger(__name__)

REPORT_JOB_PREFIX = "report:"


def validate_cron(expression: str, tz: str = "UTC") -> CronTrigger:
    """Raise ValueError for an invalid 5-field cron expression."""
    try:
        return CronTrigger.from_crontab(expression, timezone=ZoneInfo(tz))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid cron expression {expression!r}: {exc}") from exc


class ReportScheduler:
    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler(
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600},
            executors={"default": {"type": "threadpool", "max_workers": 4}},
        )
        self.timezone = "UTC"

    # ----------------------------------------------------------------- state
    @property
    def running(self) -> bool:
        return self._scheduler.running

    def start(self) -> None:
        with session_scope() as session:
            self.timezone = load_settings(session).timezone
        self._add_system_jobs()
        self._scheduler.start()
        self.reload_report_jobs()
        log.info("Scheduler started (timezone %s)", self.timezone)

    def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def set_timezone(self, tz: str) -> None:
        if tz != self.timezone:
            self.timezone = tz
            self._add_system_jobs()
            self.reload_report_jobs()

    # ------------------------------------------------------------------ jobs
    def _cron(self, expression: str) -> CronTrigger:
        return CronTrigger.from_crontab(expression, timezone=ZoneInfo(self.timezone))

    def _add_system_jobs(self) -> None:
        s = self._scheduler
        s.add_job(runner.collect_stats_all, self._cron("15 2 * * *"), id="collect:stats", name="Collect daily statistics", replace_existing=True)
        s.add_job(runner.collect_convictions_all, self._cron("20 * * * *"), id="collect:convictions", name="Collect convicted messages", replace_existing=True)
        s.add_job(runner.backfill_all, self._cron("40 * * * *"), id="collect:backfill", name="Backfill history within API budget", replace_existing=True)
        s.add_job(runner.purge_old_data, self._cron("30 3 * * *"), id="maintenance:retention", name="Retention purge", replace_existing=True)

    def reload_report_jobs(self) -> None:
        for job in list(self._scheduler.get_jobs()):
            if job.id.startswith(REPORT_JOB_PREFIX):
                job.remove()
        with session_scope() as session:
            schedules = list(session.execute(select(ReportSchedule).where(ReportSchedule.enabled.is_(True))).scalars())
            for schedule in schedules:
                try:
                    trigger = self._cron(schedule.cron)
                except Exception as exc:  # noqa: BLE001
                    log.error("Schedule %d has an invalid cron %r: %s", schedule.id, schedule.cron, exc)
                    continue
                self._scheduler.add_job(
                    run_schedule,
                    trigger,
                    args=[schedule.id],
                    id=f"{REPORT_JOB_PREFIX}{schedule.id}",
                    name=f"{schedule.report_key} #{schedule.id}",
                    replace_existing=True,
                )
        log.info("Loaded %d report schedule(s)", len(schedules))

    def next_run_times(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for job in self._scheduler.get_jobs():
            nrt = getattr(job, "next_run_time", None)
            out[job.id] = nrt.isoformat(timespec="minutes") if nrt else None
        return out

    def run_now(self, func, *args) -> None:
        """Fire a one-off job in the scheduler's thread pool (returns immediately)."""
        self._scheduler.add_job(func, args=list(args), misfire_grace_time=600)


scheduler = ReportScheduler()
