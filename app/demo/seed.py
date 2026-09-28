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
"""Seed and warm up demo mode: tenants, profiles, a brand, schedules, history and an archive."""

from __future__ import annotations

import logging
import random
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.collectors import runner
from app.collectors.convictions import map_message
from app.crypto import secret_box
from app.db import session_scope
from app.demo import simulator
from app.demo.scenario import ANALYSTS, TENANTS, DemoTenant
from app.models import Brand, DailyStat, ReportSchedule, Tenant, utcnow
from app.reports.registry import get_report
from app.settings_store import load_settings, save_settings

log = logging.getLogger(__name__)

DEMO_LOGO_PNG_B64 = "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"

# (report, target, group, recipient mode, recipients, only with findings)
DEMO_SCHEDULES: tuple[tuple[str, str, str | None, str, str, bool], ...] = (
    ("vendor_risk", "all", None, "tenant", "", False),
    ("techniques", "all", None, "fixed", "noc@demo-partner.example", False),
    ("compromise_indicators", "all", None, "tenant", "", True),
    ("exposure", "all", None, "tenant", "", True),
    ("campaigns", "group", "Premium", "tenant", "", False),
    ("vap_index", "all", None, "tenant", "", False),
    ("executive_summary", "group", "Premium", "both", "noc@demo-partner.example", False),
    ("posture_effectiveness", "group", "Premium", "both", "noc@demo-partner.example", False),
    ("cross_tenant_rollup", "tenant", None, "fixed", "", False),  # one report across all tenants, to the partner recipients
    ("trends", "all", None, "tenant", "", False),
    ("trends_all", "tenant", None, "fixed", "", False),
)
HISTORY_DAYS = 395  # a year and a month, so Trends can set the latest month against the same month a year earlier
CALMER = 0.7  # older months keep this share of the threats, so the last quarter shows a rise worth reading about


def add_demo_tenant(session: Session, spec: DemoTenant) -> Tenant:
    box = secret_box()
    tenant = Tenant(name=spec.name, region=spec.region, client_id=spec.client_id,
                    client_secret_enc=box.encrypt("demo") or "", api_key_enc=box.encrypt("demo") or "")
    tenant.profile = {"own_domains": [spec.domain], "vendor_domains": list(spec.vendors),
                      "vip_addresses": [f"{v}@{spec.domain}" for v in spec.vips], "user_labels": dict(ANALYSTS),
                      "group": spec.group, "report_recipients": list(spec.contacts), "brand_id": None}
    session.add(tenant)
    session.flush()
    return tenant


def seed_demo() -> bool:
    """Create the demo world - only on an empty database, so demo data never mixes with real tenants."""
    with session_scope() as session:
        if session.execute(select(Tenant.id).limit(1)).first() is not None:
            log.info("Demo mode: the database already has tenants - nothing seeded")
            return False
        for spec in TENANTS:
            add_demo_tenant(session, spec)
        session.add(Brand(name="Nordic Demo Partner", logo_type="image/png", logo_b64=DEMO_LOGO_PNG_B64, primary_color="#123a5a",
                          accent_color="#1a9e75", subject_prefix="[Demo SOC]", sender_name="Demo Partner SOC",
                          reply_to="soc@demo-partner.example", is_default=True,
                          footer_text="Nordic Demo Partner AB · soc@demo-partner.example\nDemo data - the customers and domains are invented."))
        save_settings(session, {"timezone": "Europe/Stockholm", "smtp_host": "demo-outbox.invalid", "smtp_port": 25, "smtp_starttls": False,
                                "smtp_from": "reports@demo-partner.example", "partner_recipients": "noc@demo-partner.example",
                                "alert_recipients": "noc@demo-partner.example"})
        for key, target, group, mode, recipients, findings in DEMO_SCHEDULES:
            session.add(ReportSchedule(tenant_id=None, report_key=key, cron=get_report(key).default_cron, recipients=recipients,
                                       output_format="pdf", enabled=True, target=target, target_group=group, recipient_mode=mode,
                                       only_with_findings=findings, created_at=utcnow() - timedelta(days=120)))
    log.warning("Demo mode: seeded %d invented tenants, a brand and %d schedules", len(TENANTS), len(DEMO_SCHEDULES))
    return True


def collect_history(tenant_ids: list[int] | None = None) -> None:
    """Collect what the simulated API offers: 90 days of statistics and convicted messages, and Log Export."""
    with session_scope() as session:
        ids = tenant_ids or [t.id for t in session.execute(select(Tenant).where(Tenant.enabled.is_(True))).scalars()]
    for tid in ids:
        runner.collect_stats_for_tenant(tid)
        for _ in range(60):  # the backfill works through history a window at a time
            with session_scope() as session:
                if session.get(Tenant, tid).backfill_done_at is not None:
                    break
            runner.backfill_for_tenant(tid)
        runner.collect_convictions_for_tenant(tid)
        runner.collect_logs_for_tenant(tid)


def fill_archive_history(schedule_ids: list[int] | None = None, per_schedule: int = 6) -> int:
    """Run each schedule for the periods it would have covered recently, so the archive and the report
    cards show history from the first minute. Only the newest run of each schedule is e-mailed (to the
    demo outbox) and rendered as PDF."""
    from zoneinfo import ZoneInfo

    from app.scheduler import cron_trigger
    from app.services import run_schedule

    now = utcnow()
    with session_scope() as session:
        tz = ZoneInfo(load_settings(session).timezone)
        schedules = [(s.id, s.cron) for s in session.execute(select(ReportSchedule).order_by(ReportSchedule.id)).scalars()
                     if schedule_ids is None or s.id in schedule_ids]
    runs = 0
    for schedule_id, cron in schedules:
        trigger, fires = cron_trigger(cron, tz), []
        fire = trigger.get_next_fire_time(None, now - timedelta(days=120))
        while fire is not None and fire <= now:
            fires.append(fire)
            fire = trigger.get_next_fire_time(fire, fire + timedelta(seconds=1))
        recent = fires[-per_schedule:]
        for i, due in enumerate(recent):
            newest = i == len(recent) - 1
            run_schedule(schedule_id, reference=due, triggered_by="schedule", deliver=newest, output_format=None if newest else "html",
                         now=due)  # generated when the schedule would have run
            runs += 1
    return runs


def extend_history(tenant_ids: list[int] | None = None, days: int = HISTORY_DAYS) -> int:
    """History beyond the 90 days ETD (and the simulated API) offers, as if the tool had been collecting for a
    year - stored directly, with the statistics and messages the simulator gives for each day, so the trend
    reports have something to show. Returns the number of days added."""
    added = 0
    today = datetime.now(UTC).date()
    with session_scope() as session:
        query = select(Tenant).where(Tenant.enabled.is_(True))
        if tenant_ids:
            query = query.where(Tenant.id.in_(tenant_ids))
        for tenant in session.execute(query).scalars():
            key = simulator.simulator.spec_for(tenant).key
            first = session.execute(select(func.min(DailyStat.day)).where(DailyStat.tenant_id == tenant.id)).scalar_one() or today
            day = today - timedelta(days=days)
            while day < first:
                kept = [m for m in simulator.day_messages(key, day) if random.Random(f"{key}:{m['id']}:calmer").random() < CALMER]
                stats = simulator.day_stats(key, day)
                counts = Counter(m["verdict"]["category"] for m in kept)
                directions, verdicts = stats["directions"], stats["verdicts"]
                session.add(DailyStat(tenant_id=tenant.id, day=day, total_messages=stats["total"], incoming=directions["incoming"],
                                      outgoing=directions["outgoing"], internal=directions["internal"], malicious=counts["malicious"],
                                      phishing=counts["phishing"], bec=counts["bec"], scam=counts["scam"], spam=verdicts["spam"],
                                      graymail=verdicts["graymail"], retro_verdicts=sum(1 for m in kept if m["verdict"]["isRetroVerdict"])))
                for message in kept:
                    row = map_message(tenant.id, message)
                    if row is not None:
                        session.add(row)
                added += 1
                day += timedelta(days=1)
            session.flush()
    return added


def warm_up(*, fill_archive: bool) -> None:
    collect_history()
    extend_history()
    if fill_archive:
        log.warning("Demo mode: history collected - filling the archive")
        fill_archive_history()
    log.warning("Demo mode: ready")
