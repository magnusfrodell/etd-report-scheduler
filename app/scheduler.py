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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts import check_collection
from app.backup import nightly_backup
from app.collectors import runner
from app.config import get_config
from app.db import session_scope
from app.models import ReportRun, ReportSchedule, utcnow
from app.reports.base import SCOPE_ALL
from app.reports.periods import period_for
from app.reports.registry import get_report
from app.services import run_schedule, schedule_targets
from app.settings_store import load_settings

log = logging.getLogger(__name__)

REPORT_JOB_PREFIX = "report:"


_CRON_DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")  # standard cron: 0 (or 7) = Sunday, 1 = Monday


def _cron_day(token: str, *, upper: bool = False) -> int:
    token = token.strip().lower()
    if token[:3] in _CRON_DAYS and token.isalpha():
        day = _CRON_DAYS.index(token[:3])
        return 7 if upper and day == 0 else day  # "fri-sun" ends on Sunday = 7
    value = int(token)
    if not 0 <= value <= 7:
        raise ValueError(f"day of week {value} is outside 0-7")
    return value


def cron_days(field: str) -> str:
    """A standard cron day-of-week field (0 or 7 = Sunday, 1 = Monday ... 6 = Saturday; names, ranges,
    lists and steps allowed) as the day names APScheduler understands.

    APScheduler 3 numbers the days from Monday = 0, so passing the field through unchanged - as
    ``CronTrigger.from_crontab`` does - would run "1" on Tuesday and reject "7"."""
    if field.strip() in ("*", "?"):
        return "*"
    days: set[int] = set()
    for part in field.split(","):
        span, _, step_text = part.partition("/")
        step = int(step_text) if step_text else 1
        if step < 1:
            raise ValueError("a step must be at least 1")
        if span in ("*", ""):
            low, high = 0, 6
        elif "-" in span:
            first, last = span.split("-", 1)
            low, high = _cron_day(first), _cron_day(last, upper=True)
        else:
            low = _cron_day(span)
            high = 7 if step_text else low  # "1/2" runs from Monday to the end of the week
        if high < low:
            raise ValueError(f"the day range {span!r} runs backwards")
        days.update(day % 7 for day in range(low, high + 1, step))
    return ",".join(_CRON_DAYS[day] for day in sorted(days))


def cron_trigger(expression: str, tz: str | ZoneInfo = "UTC") -> CronTrigger:
    """A trigger for a standard 5-field cron expression (minute hour day month day-of-week)."""
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError(f"expected 5 fields, got {len(fields)}")
    minute, hour, day, month, day_of_week = fields
    return CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=cron_days(day_of_week),
                       timezone=tz if isinstance(tz, ZoneInfo) else ZoneInfo(tz))


def validate_cron(expression: str, tz: str = "UTC") -> CronTrigger:
    """Raise ValueError for an invalid 5-field cron expression."""
    try:
        return cron_trigger(expression, tz)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid cron expression {expression!r}: {exc}") from exc



CATCH_UP_LIMIT = 3  # per schedule: a long outage should not bury the recipients in old reports
HEARTBEAT_MINUTES = 5


def heartbeat_path() -> Path:
    return Path(get_config().data_dir) / "heartbeat"


def write_heartbeat(now: datetime | None = None) -> None:
    """Record that the service is alive; at start-up this tells what fell due while it was down."""
    try:
        heartbeat_path().write_text((now or utcnow()).isoformat(), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write the heartbeat file: %s", exc)


def read_heartbeat() -> datetime | None:
    try:
        value = datetime.fromisoformat(heartbeat_path().read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def missed_runs(session: Session, since: datetime, now: datetime, tz: str) -> list[tuple[int, datetime]]:
    """Scheduled runs that fell due in (since, now] - while the service was down - with no run for
    their period yet, as (schedule id, due time): oldest first, at most CATCH_UP_LIMIT per schedule.

    Only the outage counts: a schedule that was disabled, or a run that failed, is not caught up."""
    zone = ZoneInfo(tz)
    out: list[tuple[int, datetime]] = []
    for schedule in session.execute(select(ReportSchedule).where(ReportSchedule.enabled.is_(True)).order_by(ReportSchedule.id)).scalars():
        try:
            trigger = cron_trigger(schedule.cron, zone)
            definition = get_report(schedule.report_key)
        except (ValueError, KeyError):
            continue
        due: list[datetime] = []
        fire = trigger.get_next_fire_time(None, max(since, schedule.created_at) + timedelta(seconds=1))
        while fire is not None and fire <= now and len(due) < 10_000:
            due.append(fire)
            fire = trigger.get_next_fire_time(fire, fire + timedelta(seconds=1))
        for fire in due[-CATCH_UP_LIMIT:]:
            period = period_for(definition.period_kind, fire, zone)
            done = set(session.execute(
                select(ReportRun.tenant_id).where(ReportRun.schedule_id == schedule.id, ReportRun.period_start == period.start)
            ).scalars())
            if schedule.target in ("all", "group") and definition.scope != SCOPE_ALL:
                # a schedule for many tenants is only done when every tenant it covers has its report
                missing = bool({t.id for t in schedule_targets(session, schedule, definition)} - done)
            else:
                missing = not done
            if missing:
                out.append((schedule.id, fire))
    return out

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
        last_alive = read_heartbeat()
        self._add_system_jobs()
        self._scheduler.start()
        self.reload_report_jobs()
        write_heartbeat()
        if last_alive is not None:
            self.catch_up(last_alive)
        log.info("Scheduler started (timezone %s)", self.timezone)

    def shutdown(self) -> None:
        if self._scheduler.running:
            write_heartbeat()
            self._scheduler.shutdown(wait=False)

    def catch_up(self, since: datetime, now: datetime | None = None) -> int:
        """Queue the scheduled reports that fell due while the service was down (see ``missed_runs``)."""
        now = now or utcnow()
        with session_scope() as session:
            missed = missed_runs(session, since, now, self.timezone)
        for i, (schedule_id, due) in enumerate(missed):
            self._scheduler.add_job(
                run_schedule, "date", run_date=now + timedelta(seconds=30 + 15 * i), args=[schedule_id],
                kwargs={"reference": due, "triggered_by": "catchup", "only_missing": True}, id=f"catchup:{schedule_id}:{due.isoformat()}",
                name=f"Catch up schedule {schedule_id} due {due:%Y-%m-%d %H:%M}", replace_existing=True,
            )
        if missed:
            log.warning("The service was down since %s: queued %d missed scheduled report(s)", since.isoformat(), len(missed))
        return len(missed)

    def set_timezone(self, tz: str) -> None:
        if tz != self.timezone:
            self.timezone = tz
            self._add_system_jobs()
            self.reload_report_jobs()

    # ------------------------------------------------------------------ jobs
    def _cron(self, expression: str) -> CronTrigger:
        return cron_trigger(expression, self.timezone)

    def _add_system_jobs(self) -> None:
        s = self._scheduler
        s.add_job(runner.collect_stats_all, self._cron("15 2 * * *"), id="collect:stats", name="Collect daily statistics", replace_existing=True)
        s.add_job(runner.collect_convictions_all, self._cron("20 * * * *"), id="collect:convictions", name="Collect convicted messages", replace_existing=True)
        s.add_job(runner.backfill_all, self._cron("40 * * * *"), id="collect:backfill", name="Backfill history within API budget", replace_existing=True)
        s.add_job(runner.collect_logs_all, self._cron("50 * * * *"), id="collect:logs", name="Collect Log Export (audit + message events)", replace_existing=True)
        s.add_job(runner.purge_old_data, self._cron("30 3 * * *"), id="maintenance:retention", name="Retention purge", replace_existing=True)
        s.add_job(nightly_backup, self._cron("45 3 * * *"), id="maintenance:backup", name="Nightly database backup", replace_existing=True)
        s.add_job(check_collection, self._cron("55 * * * *"), id="alerts:collection", name="Alert on stalled collection", replace_existing=True)
        s.add_job(write_heartbeat, "interval", minutes=HEARTBEAT_MINUTES, id="maintenance:heartbeat", name="Heartbeat", replace_existing=True)

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
