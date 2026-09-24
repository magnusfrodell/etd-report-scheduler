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
"""ETD Log Export collector.

Pulls ``audit`` and ``message`` logs through ``/v1/logs/downloadLinks`` and turns
them into:

* ``audit_events``        every admin and API action - kept for
                          ``audit_retention_days`` (ETD itself keeps 30 days);
* ``message_events``      reclassifications and remediations (update events);
* ``sender_domain_daily`` per sender domain, day and direction: volume, create-time
                          convictions and Return-Path / Reply-To misalignment.

Files come from pre-signed S3 URLs (plain GET, no API credentials) and are
deduplicated by path, so overlapping windows, late files and re-runs never
double count. Windows are 3 hours (the API maximum). The last six hours are
re-requested on every run because new files keep arriving for ~20 minutes.
Each window is written in one transaction together with the cursor.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import re
import zlib
from collections import defaultdict
from collections.abc import Iterator
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.etd.client import ETDClient, ETDError, parse_ts
from app.models import AuditEvent, LogFile, MessageEvent, SenderDomainDaily, Tenant, utcnow
from app.reports.analysis import email_domain
from app.reports.domains import registrable
from app.settings_store import THREAT_VERDICTS

log = logging.getLogger(__name__)

LOG_TYPES = ("message", "audit")
RETENTION_DAYS = 29  # ETD keeps 30 days; stay one day inside
WINDOW_HOURS = 3
LOOKBACK_HOURS = 6
MAX_LINKS = 200
DOWNLOAD_ATTEMPTS = 3  # a file with unreadable lines is fetched again before it is stored as partial
MIN_BUDGET = 5
_CHUNK = 500
_PATH_RE = re.compile(r"log_date=(\d{4}-\d{2}-\d{2})/hour=(\d{1,2})")
_THREATS = set(THREAT_VERDICTS)


def floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def canonical_path(url: str) -> str:
    return url.split("?", 1)[0]


def path_hash(url: str) -> str:
    return hashlib.sha256(canonical_path(url).encode("utf-8")).hexdigest()


def path_date_hour(url: str) -> tuple[date | None, int | None]:
    m = _PATH_RE.search(unquote(canonical_path(url)))
    if not m:
        return None, None
    try:
        return date.fromisoformat(m.group(1)), int(m.group(2))
    except ValueError:
        return None, None


def parse_log(data: bytes) -> tuple[list[dict[str, Any]], int]:
    """Events in a log file (JSON lines, a JSON array or gzip of either) and the number of unreadable
    lines. A file that cannot be decompressed counts as one unreadable line."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError, zlib.error):
            return [], 1
    text = data.decode("utf-8", "replace").strip()
    if not text:
        return [], 0
    if text.startswith("["):
        try:
            return [item for item in json.loads(text) if isinstance(item, dict)], 0
        except ValueError:
            pass
    events: list[dict[str, Any]] = []
    unreadable = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events, unreadable


def parse_lines(data: bytes) -> Iterator[dict[str, Any]]:
    """The readable events of a log file (see ``parse_log`` for the count of unreadable lines)."""
    yield from parse_log(data)[0]


def event_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _s(value: Any, n: int) -> str | None:
    return str(value)[:n] if value not in (None, "") else None


class WindowBatch:
    """Everything parsed from one window's files, written in a single transaction."""

    def __init__(self) -> None:
        self.domains: dict[tuple[date, str, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])
        self.audit: dict[str, dict[str, Any]] = {}
        self.message_events: dict[str, dict[str, Any]] = {}
        self.files: list[tuple[str, str, str, int, int]] = []  # (log_type, path, path_hash, events, unreadable lines)

    def add(self, obj: dict[str, Any], default_type: str) -> None:
        log_type = str(obj.get("logType") or default_type)
        if log_type == "message":
            self.add_message(obj)
        elif log_type == "audit":
            self.add_audit(obj)

    def add_message(self, obj: dict[str, Any]) -> None:
        msg = obj.get("message") if isinstance(obj.get("message"), dict) else obj
        kind = str(msg.get("eventType") or "").lower()
        if kind == "create":
            self._create(msg)
        elif kind == "update":
            self._update(msg)

    def _create(self, msg: dict[str, Any]) -> None:
        ts = parse_ts(msg.get("timestamp"))
        if ts is None:
            return
        sender = email_domain(_first(msg.get("fromAddresses")) or msg.get("envelopeFrom") or "") or "(none)"
        direction = str(msg.get("direction") or "unknown")[:16]
        verdict = msg.get("verdict") if isinstance(msg.get("verdict"), dict) else {}
        convicted = str(verdict.get("verdict") or verdict.get("category") or "").lower() in _THREATS
        base = registrable(sender) if sender != "(none)" else ""
        rp = email_domain(msg.get("returnPath") or msg.get("envelopeFrom") or "")
        rt = email_domain(_first(msg.get("replyTo")) or "")
        rp_mis = bool(rp and base and registrable(rp) != base)
        rt_mis = bool(rt and base and registrable(rt) != base)
        row = self.domains[(ts.date(), sender[:253], direction)]
        row[0] += 1
        row[1] += int(convicted)
        row[2] += int(rp_mis)
        row[3] += int(rt_mis)
        row[4] += int(convicted and rt_mis)

    def _update(self, msg: dict[str, Any]) -> None:
        common = {"message_id": _s(msg.get("id"), 64), "internet_message_id": _s(msg.get("internetMessageId"), 998)}
        verdict = msg.get("verdict")
        if isinstance(verdict, dict) and verdict:
            ts = parse_ts(verdict.get("timestamp")) or parse_ts(msg.get("timestamp"))
            if ts:
                self.message_events[event_hash({"k": "reclassify", "m": msg.get("id"), "v": verdict})] = {
                    **common, "timestamp": ts, "kind": "reclassify",
                    "method": str(verdict.get("reclassifiedBy") or "").lower()[:20],
                    "user_id": _s(verdict.get("user"), 64), "api_client_id": _s(verdict.get("publicApiClientId"), 64),
                    "verdict": _s(verdict.get("verdict") or verdict.get("category"), 32), "action": None, "folder": None,
                }
        action = msg.get("action")
        if isinstance(action, dict) and action:
            ts = parse_ts(action.get("timestamp")) or parse_ts(msg.get("timestamp"))
            if ts:
                self.message_events[event_hash({"k": "remediate", "m": msg.get("id"), "a": action})] = {
                    **common, "timestamp": ts, "kind": "remediate",
                    "method": str(action.get("remediatedBy") or "").lower()[:20],
                    "user_id": _s(action.get("user"), 64), "api_client_id": _s(action.get("publicApiClientId"), 64),
                    "verdict": None, "action": _s(action.get("action"), 32), "folder": _s(action.get("folder"), 32),
                }

    def add_audit(self, obj: dict[str, Any]) -> None:
        ts = parse_ts(str(obj.get("timestamp") or ""))
        if ts is None:
            return
        user = obj.get("user") if isinstance(obj.get("user"), dict) else {}
        self.audit[event_hash(obj)] = {
            "timestamp": ts,
            "category": str(obj.get("category") or "")[:40],
            "action": str(obj.get("action") or "")[:120],
            "status": str(obj.get("status") or "")[:20],
            "user_id": _s(user.get("id"), 64),
            "user_ip": _s(user.get("ip"), 64),
            "user_agent": _s(user.get("userAgent"), 400),
            "comments": _s(obj.get("comments"), 4000),
            "meta": obj.get("metadata"),
        }


def _existing_hashes(session: Session, model: Any, tenant_id: int, hashes: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(hashes), _CHUNK):
        chunk = hashes[i : i + _CHUNK]
        found |= set(session.execute(select(model.event_hash).where(model.tenant_id == tenant_id, model.event_hash.in_(chunk))).scalars())
    return found


def store_batch(session: Session, tenant_id: int, batch: WindowBatch) -> None:
    if batch.domains:
        days = sorted({k[0] for k in batch.domains})
        existing = {
            (r.day, r.domain, r.direction): r
            for r in session.execute(select(SenderDomainDaily).where(SenderDomainDaily.tenant_id == tenant_id, SenderDomainDaily.day.in_(days))).scalars()
        }
        for key, (msgs, conv, rp, rt, crt) in batch.domains.items():
            row = existing.get(key)
            if row is None:
                row = SenderDomainDaily(tenant_id=tenant_id, day=key[0], domain=key[1], direction=key[2], messages=0, convicted=0,
                                        rp_mismatch=0, reply_to_mismatch=0, convicted_reply_to_mismatch=0)
                session.add(row)
                existing[key] = row
            row.messages += msgs
            row.convicted += conv
            row.rp_mismatch += rp
            row.reply_to_mismatch += rt
            row.convicted_reply_to_mismatch += crt
    if batch.audit:
        known = _existing_hashes(session, AuditEvent, tenant_id, list(batch.audit))
        for h, ev in batch.audit.items():
            if h not in known:
                session.add(AuditEvent(tenant_id=tenant_id, event_hash=h, **ev))
    if batch.message_events:
        known = _existing_hashes(session, MessageEvent, tenant_id, list(batch.message_events))
        for h, ev in batch.message_events.items():
            if h not in known:
                session.add(MessageEvent(tenant_id=tenant_id, event_hash=h, **ev))
    for log_type, path, ph, n, unreadable in batch.files:
        d, hour = path_date_hour(path)
        session.add(LogFile(tenant_id=tenant_id, log_type=log_type, path=path, path_hash=ph, log_date=d, log_hour=hour, events=n,
                            parse_errors=unreadable, status="partial" if unreadable else "ok"))


def _unique(urls: list[str]) -> list[str]:
    return list({canonical_path(u): u for u in urls}.values())


def fetch_links(client: ETDClient, start: datetime, end: datetime, log_types: tuple[str, ...] | list[str],
                truncated: list[tuple[datetime, datetime]] | None = None) -> dict[str, list[str]]:
    """Download links per log type; windows that hit the 200-link cap are re-requested per hour.
    Hours that still hit the cap may be missing files - they are added to ``truncated``."""
    data = client.log_download_links(start, end, list(log_types))
    out = {t: _unique(list(data.get(t) or [])) for t in log_types}
    full = [t for t, urls in out.items() if len(urls) >= MAX_LINKS]
    if full and end - start > timedelta(hours=1):
        for t in full:
            out[t] = []
        hour = start
        while hour < end:
            sub = client.log_download_links(hour, hour + timedelta(hours=1), full)
            for t in full:
                hour_links = sub.get(t) or []
                out[t].extend(hour_links)
                if len(hour_links) >= MAX_LINKS and truncated is not None:
                    truncated.append((hour, hour + timedelta(hours=1)))
            hour += timedelta(hours=1)
        for t in full:
            out[t] = _unique(out[t])
            if len(out[t]) >= MAX_LINKS * (end - start).total_seconds() / 3600:
                log.warning("Log Export %s links for %s may be truncated at %d per hour", t, start, MAX_LINKS)
    elif full:
        if truncated is not None:
            truncated.append((start, end))
        log.warning("Log Export returned %d %s links for one hour; the API truncates at %d", MAX_LINKS, full, MAX_LINKS)
    return out


def collect_logs(session: Session, tenant: Tenant, client: ETDClient, *, budget: int, now: datetime | None = None,
                 log_types: tuple[str, ...] = LOG_TYPES) -> dict[str, Any]:
    now = now or utcnow()
    current = floor_hour(now)
    horizon = current - timedelta(days=RETENTION_DAYS)
    if tenant.logs_cursor is None:
        start = horizon
        if tenant.logs_first_hour is None:
            tenant.logs_first_hour = horizon
    else:
        cursor = tenant.logs_cursor
        if cursor < horizon:
            gaps = list(tenant.logs_gaps or [])
            gaps.append([cursor.isoformat(), horizon.isoformat()])
            tenant.logs_gaps = gaps
            log.warning("Tenant %s: log collection gap %s - %s (older than ETD retention)", tenant.name, cursor, horizon)
            cursor = horizon
        start = max(horizon, cursor - timedelta(hours=LOOKBACK_HOURS))

    seen = set(session.execute(
        select(LogFile.path_hash).where(LogFile.tenant_id == tenant.id, LogFile.processed_at >= now - timedelta(days=RETENTION_DAYS + 3))
    ).scalars())
    used_at_start = client.request_count
    files = events = windows = partial_files = 0
    truncated: list[tuple[datetime, datetime]] = []
    status = "ok"
    win = start
    while win < current:
        if budget - (client.request_count - used_at_start) < MIN_BUDGET:
            status = "paused"
            break
        end = min(win + timedelta(hours=WINDOW_HOURS), current)
        try:
            links = fetch_links(client, win, end, log_types, truncated)
        except ETDError as exc:
            if exc.status == 400 and "past" in (exc.body or "").lower():
                log.info("Tenant %s: window %s is outside ETD retention, skipping", tenant.name, win)
                win = end
                continue
            raise
        batch = WindowBatch()
        for log_type, urls in links.items():
            for url in urls:
                h = path_hash(url)
                if h in seen:
                    continue
                objs, unreadable = parse_log(client.download(url))
                attempts = 1
                while unreadable and attempts < DOWNLOAD_ATTEMPTS:  # a truncated download is the usual cause
                    attempts += 1
                    objs, unreadable = parse_log(client.download(url))
                for obj in objs:
                    batch.add(obj, log_type)
                n = len(objs)
                if unreadable:
                    partial_files += 1
                    log.warning("Tenant %s: %d unreadable line(s) in %s after %d download(s) - stored as partial",
                                tenant.name, unreadable, canonical_path(url), attempts)
                batch.files.append((log_type, canonical_path(url), h, n, unreadable))
                seen.add(h)
                files += 1
                events += n
        store_batch(session, tenant.id, batch)
        if truncated:  # hours where ETD's link limit may have hidden files: coverage must not count them as complete
            tenant.logs_gaps = list(tenant.logs_gaps or []) + [[s.isoformat(), e.isoformat(), "link limit reached"] for s, e in truncated]
            truncated.clear()
        if tenant.logs_cursor is None or end > tenant.logs_cursor:
            tenant.logs_cursor = end
        session.commit()
        windows += 1
        win = end

    note = f"{files} new file(s), {events} event(s) in {windows} window(s)"
    if partial_files:
        note += f"; {partial_files} file(s) had unreadable lines and are marked partial"
    if status == "paused":
        note = f"Daily API budget reached - continues next hour ({note})."
    elif session.execute(select(LogFile.id).where(LogFile.tenant_id == tenant.id, LogFile.log_type == "message").limit(1)).first() is None:
        first = tenant.logs_first_hour or current
        if current - first >= timedelta(hours=2):
            status = "no_data"
            note = ("No message log files yet. Enable the logs in ETD under Administration > Business > Export Log "
                    "Preferences; export starts 15-20 minutes after enabling and earlier history is not available.")
    log.info("Tenant %s: Log Export %s - %s", tenant.name, status, note)
    return {"status": status, "note": note, "files": files, "events": events, "windows": windows}
