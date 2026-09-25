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
"""A simulated Cisco Secure Email Threat Defense API for demo mode.

The real collectors talk to it through the transport hook in ``app.etd.factory``, so demo data
flows through exactly the code paths real data does. Everything is derived from the tenant and the
day, so repeated and overlapping requests agree; scenario events stay in the most recent weeks, so
a demo looks current whenever it runs.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

import httpx

from app.demo.scenario import ANALYSTS, BY_CLIENT_ID, THREATS, DemoTenant, Threat, generic_tenant
from app.models import Tenant

LOG_HOST = "logs.demo.invalid"
_HOUR_WEIGHTS = (1, 1, 1, 1, 1, 2, 4, 8, 10, 10, 9, 8, 7, 8, 9, 8, 7, 5, 4, 3, 2, 2, 1, 1)
_REGISTRY: dict[str, DemoTenant] = {}
_ANALYST_IDS = tuple(ANALYSTS)


def _rng(*parts: object) -> random.Random:
    digest = hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse(value: str) -> datetime:
    return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)


def _today() -> date:
    return datetime.now(UTC).date()


def _recent(day: date, days: int) -> bool:
    return 0 <= (_today() - day).days < days


def _when(rng: random.Random, day: date) -> datetime:
    hour = rng.choices(range(24), weights=_HOUR_WEIGHTS)[0]
    return datetime(day.year, day.month, day.day, hour, rng.randint(0, 59), rng.randint(0, 59), tzinfo=UTC)


def _mailbox(spec: DemoTenant, rng: random.Random, vip: bool = False) -> str:
    local = rng.choice(spec.vips) if vip or rng.random() < 0.2 else rng.choice(spec.employees)
    return f"{local}@{spec.domain}"


@lru_cache(maxsize=4096)
def day_messages(key: str, day: date) -> tuple[dict[str, Any], ...]:
    """The convicted messages of one tenant and day."""
    spec = _REGISTRY[key]
    rng = _rng(key, day, "messages")
    weekday = day.weekday() < 5
    volume = spec.size * (1.0 if weekday else 0.28)
    expected = volume * spec.threat_rate
    messages: list[dict[str, Any]] = []

    def add(threat: Threat, ts: datetime, *, sender: str | None = None, recipients: list[str] | None = None, direction: str = "incoming",
            reply_to: str | None = None, subject: str | None = None, url: str | None = None, n: int | None = None, ref: str | None = None) -> None:
        n = rng.randint(0, 9) if n is None else n
        ref = str(rng.randint(10000, 99999)) if ref is None else ref
        rcpts = recipients or [_mailbox(spec, rng, vip=threat.vip_bias and rng.random() < 0.7)]
        retro = threat.verdict in ("phishing", "malicious") and rng.random() < 0.12
        verdict_ts = ts + (timedelta(hours=rng.uniform(1, 30)) if retro else timedelta(seconds=rng.randint(1, 50)))
        link = url or threat.url
        msg: dict[str, Any] = {
            "id": f"demo-{key}-{day:%Y%m%d}-{len(messages):04d}",
            "timestamp": _iso(ts),
            "direction": direction,
            "fromAddress": sender or threat.sender.format(n=n, ref=ref),
            "toAddresses": rcpts,
            "mailboxes": rcpts if direction != "outgoing" else [sender or ""],
            "subject": (subject or threat.subject).format(n=n, ref=ref, domain=spec.domain),
            "urls": [link.format(n=n, ref=ref)] if link else [],
            "attachments": [{"fileName": threat.attachment[0].format(n=n, ref=ref), "contentType": threat.attachment[1]}] if threat.attachment else [],
            "verdict": {"originalVerdict": threat.verdict, "category": threat.verdict, "isRetroVerdict": retro, "timestamp": _iso(verdict_ts),
                        "businessRisk": threat.risk,
                        "techniques": [{"type": t, "severity": "high" if i == 0 else "medium"} for i, t in enumerate(threat.techniques)]},
            "secureEmailGateway": {"gatewayType": "ciscoDefault", "headerName": "X-IronPort-RemoteIP"},
        }
        if reply_to:
            msg["replyTo"] = reply_to
        if rng.random() < 0.015:
            msg["rule"] = {"type": "allow-list"}
        late = retro and spec.slow_remediation
        if not (late and rng.random() < 0.3):  # a slow SOC leaves some retro verdicts in the mailbox
            delay = timedelta(hours=rng.uniform(2, 60)) if late else timedelta(minutes=rng.uniform(1, 20)) if retro else timedelta(seconds=rng.randint(2, 90))
            msg["action"] = {"type": "move", "folder": "quarantine" if threat.verdict == "malicious" else "junkemail",
                             "timestamp": _iso(verdict_ts + delay), "isAutoRemediated": not late and rng.random() < 0.93}
        messages.append(msg)

    for _ in range(max(0, round(rng.gauss(expected, expected * 0.3)))):
        add(rng.choices(THREATS, weights=[t.weight for t in THREATS])[0], _when(rng, day))

    week = _rng(key, day.isocalendar()[1], "campaign")
    campaign, campaign_day = week.choice(THREATS[:4]), week.randint(0, 4)
    if day.weekday() == campaign_day:  # one campaign a week: same sender, subject and lure
        n, ref, start = week.randint(0, 9), str(week.randint(10000, 99999)), _when(week, day)
        for i in range(week.randint(8, 20)):
            add(campaign, start + timedelta(minutes=3 * i), n=n, ref=ref,
                recipients=[_mailbox(spec, rng, vip=campaign.vip_bias) for _ in range(rng.randint(1, 3))])

    if spec.compromised_vendor and weekday and _recent(day, 21):  # a supplier's real accounts ask for new bank details
        vendor = spec.compromised_vendor
        bec = Threat("vendor-bec", "bec", "fraud", ("Frequent Sender", "Urgency", "Sender Name Mismatch"), f"accounts@{vendor}",
                     "Updated bank details for invoice {ref}", attachment=("Invoice_{ref}.pdf", "application/pdf"))
        for _ in range(rng.randint(1, 2)):
            add(bec, _when(rng, day), recipients=[f"ap@{spec.domain}", f"cfo@{spec.domain}"],
                reply_to=f"payments@{vendor.split('.')[0]}-finance.example")

    if spec.lookalike and weekday and rng.random() < 0.7:
        spoof = Threat("lookalike", "phishing", "credential harvesting", ("Domain Brand Impersonation", "Young Domain", "Malicious URL"),
                       f"it-support@{spec.lookalike}", "Password reset required for {domain}", url=f"https://{spec.lookalike}/sso/reset")
        add(spoof, _when(rng, day))

    if spec.internal_compromise and _recent(day, 30) and _rng(key, day, "internal").random() < 0.3:  # a hijacked mailbox sends phishing out
        sender = f"{spec.internal_compromise}@{spec.domain}"
        lure = Threat("internal", "phishing", "credential harvesting", ("Malicious URL", "Internal Email", "Link Visit Request"),
                      sender, "Shared document: contract review", url="https://sharepoint-files{n}.example/view")
        start = _when(rng, day)
        for i in range(rng.randint(6, 15)):
            add(lure, start + timedelta(minutes=2 * i), sender=sender, direction="outgoing",
                recipients=[f"contact{rng.randint(1, 99)}@customer{rng.randint(1, 30)}.example"])
    return tuple(sorted(messages, key=lambda m: m["timestamp"]))


def day_stats(key: str, day: date) -> dict[str, Any]:
    """Daily volumes; the threat counts come from the same messages the search returns."""
    spec = _REGISTRY[key]
    rng = _rng(key, day, "stats")
    total = max(50, round(rng.gauss(spec.size * (1.0 if day.weekday() < 5 else 0.28), spec.size * 0.05)))
    incoming, outgoing = round(total * 0.72), round(total * 0.18)
    messages = day_messages(key, day)
    counts = Counter(m["verdict"]["category"] for m in messages)
    return {
        "total": total,
        "directions": {"incoming": incoming, "outgoing": outgoing, "internal": total - incoming - outgoing},
        "verdicts": {"malicious": counts["malicious"], "phishing": counts["phishing"], "bec": counts["bec"], "scam": counts["scam"],
                     "spam": round(incoming * rng.uniform(0.04, 0.08)), "graymail": round(incoming * rng.uniform(0.07, 0.12))},
        "retro": sum(1 for m in messages if m["verdict"]["isRetroVerdict"]),
    }


def _days(start: datetime, end: datetime, limit: int = 100) -> list[date]:
    first, last = start.date(), min(end, datetime.now(UTC)).date()
    return [first + timedelta(days=i) for i in range(max(0, min(limit, (last - first).days + 1)))]


def log_lines(spec: DemoTenant, day: date, hour: int, log_type: str) -> list[dict[str, Any]]:
    """Log Export events for one hour: sign-ins, verdict changes and policy edits in the audit log;
    deliveries from suppliers and look-alikes, and analyst actions, in the message log."""
    if datetime(day.year, day.month, day.day, hour, tzinfo=UTC) >= datetime.now(UTC):
        return []
    rng = _rng(spec.key, day, hour, log_type)
    weekday, stamp = day.weekday() < 5, f"{day:%Y-%m-%d}"

    def audit(category: str, action: str, user: str, metadata: dict | None, status: str = "success", ip: str = "198.51.100.10") -> dict:
        return {"category": category, "timestamp": f"{stamp} {hour:02d}:{rng.randint(0, 59):02d}:00", "action": action, "status": status,
                "comments": None, "user": {"ip": ip, "userAgent": "Mozilla/5.0", "id": user}, "metadata": metadata}

    if log_type == "audit":
        events = []
        if weekday and hour == 8:
            events += [audit("user", "login", analyst, None) for analyst in _ANALYST_IDS]
        if weekday and hour == 10:
            events += [audit("email", "reclassify", _ANALYST_IDS[0], {"verdict": "neutral", "description": "Changing verdict to neutral",
                                                                   "emailId": f"demo-{spec.key}-{day:%Y%m%d}-r{i}"}) for i in range(rng.randint(0, 3))]
        if day.weekday() == 0 and hour == 14:
            events.append(audit("policy", "update_policy", _ANALYST_IDS[1], {"policyName": "Default", "description": "Retrospective verdicts: move to quarantine"}))
        if day.day == 1 and hour == 9:
            events.append(audit("tenant", "create_public_api_client", _ANALYST_IDS[1], {"clientId": "etd-report-scheduler"}))
        if hour == 23 and rng.random() < 0.15:
            events.append(audit("user", "login", "unknown", None, status="failure", ip=f"203.0.113.{rng.randint(2, 250)}"))
        return events
    if log_type != "message":
        return []

    def created(sender: str, mailbox: str, *, direction: str = "incoming", reply_to: str | None = None) -> dict:
        return {"message": {"eventType": "create", "id": f"m-{spec.key}-{stamp}-{hour:02d}-{rng.randint(0, 10**9)}", "fromAddresses": sender,
                            "replyTo": reply_to or sender, "returnPath": f"bounce@mail.{sender.split('@')[-1]}", "direction": direction,
                            "timestamp": f"{stamp}T{hour:02d}:{rng.randint(0, 59):02d}:00Z", "mailboxes": [mailbox] if mailbox else []},
                "logType": "message", "logDate": stamp, "logHour": f"{hour:02d}"}

    events = []
    if weekday and 7 <= hour <= 17:
        for vendor in spec.vendors:  # ordinary supplier mail builds the counterparty history
            events += [created(f"{rng.choice(('invoices', 'orders', 'support'))}@{vendor}", f"{rng.choice(('ap', 'purchasing', spec.employees[0]))}@{spec.domain}")
                       for _ in range(rng.randint(0, 2))]
        events.append(created(f"{rng.choice(spec.employees)}@{spec.domain}", "", direction="outgoing"))
    if spec.lookalike and weekday and hour == 11 and _recent(day, 21):  # a look-alike that got through
        events.append(created(f"it-support@{spec.lookalike}", f"{rng.choice(spec.employees)}@{spec.domain}"))
    if weekday and hour == 12:
        events.append({"message": {"eventType": "update", "id": f"u-{spec.key}-{stamp}", "internetMessageId": f"<u-{spec.key}-{stamp}@demo>",
                                   "verdict": {"verdict": "neutral", "reclassifiedBy": "user", "timestamp": f"{stamp}T12:05:00Z", "user": _ANALYST_IDS[0]}},
                       "logType": "message"})
        events.append({"message": {"eventType": "update", "id": f"r-{spec.key}-{stamp}", "internetMessageId": f"<r-{spec.key}-{stamp}@demo>",
                                   "action": {"action": "move", "folder": "trash", "remediatedBy": "manual", "timestamp": f"{stamp}T12:10:00Z",
                                              "user": _ANALYST_IDS[0]}}, "logType": "message"})
    return events


class DemoETD:
    """Hands each tenant a transport that answers like the ETD API, from the demo scenario."""

    def spec_for(self, tenant: Tenant) -> DemoTenant:
        spec = BY_CLIENT_ID.get(tenant.client_id) or generic_tenant(tenant.client_id, tenant.name)
        _REGISTRY[spec.key] = spec
        return spec

    def transport_for(self, tenant: Tenant) -> httpx.MockTransport:
        spec = self.spec_for(tenant)
        return httpx.MockTransport(lambda request: self.handle(spec, request))

    def handle(self, spec: DemoTenant, request: httpx.Request) -> httpx.Response:
        if request.url.host == LOG_HOST:
            return self._download(spec, request)
        body = json.loads(request.content or b"{}") if request.content else {}
        path = request.url.path
        if path == "/v1/oauth/token":
            return httpx.Response(200, json={"accessToken": f"demo-token-{spec.key}"})
        if path == "/v1/messages/report":
            return self._report(spec, body)
        if path == "/v1/messages/report/top":
            return self._top(spec, body)
        if path == "/v1/messages/search":
            return self._search(spec, body)
        if path == "/v1/logs/downloadLinks":
            return self._links(spec, body)
        return httpx.Response(404, json={"message": "Not Found"})

    def _report(self, spec: DemoTenant, body: dict) -> httpx.Response:
        agg = body.get("aggregateBy")
        buckets = []
        for day in _days(_parse(body["timestamp"][0]), _parse(body["timestamp"][1])):
            stats = day_stats(spec.key, day)
            ts = f"{day:%Y-%m-%d}T00:00:00.000Z"
            if agg in ("directions", "direction"):
                buckets.append({"startTimestamp": ts, "messageCount": stats["total"], "messages": stats["directions"]})
            elif agg == "verdicts":
                buckets.append({"startTimestamp": ts, "messageCount": sum(stats["verdicts"].values()), "messages": stats["verdicts"]})
            else:
                buckets.append({"startTimestamp": ts, "messageCount": stats["retro"]})
        return httpx.Response(200, json={"data": {"aggregationInterval": body.get("aggregationInterval"),
                                                  "totalMessages": sum(b["messageCount"] for b in buckets), "aggregations": buckets}})

    def _top(self, spec: DemoTenant, body: dict) -> httpx.Response:
        start, end = _parse(body["timestamp"][0]), _parse(body["timestamp"][1])
        messages = [m for day in _days(start, end) for m in day_messages(spec.key, day) if m["direction"] == "incoming"]
        if body.get("reportType") == "targets":
            per: dict[str, Counter] = {}
            for m in messages:
                for rcpt in m["mailboxes"]:
                    per.setdefault(rcpt, Counter())[m["verdict"]["category"]] += 1
            ranked = sorted(per.items(), key=lambda kv: -sum(kv[1].values()))[:10]
            data = {"topTargets": [{"emailAddress": a, **{v: c[v] for v in ("malicious", "phishing", "bec", "scam")}} for a, c in ranked]}
        else:
            senders = Counter(m["fromAddress"] for m in messages)
            data = {"topExternalThreatSenders": [{"emailAddress": a, "total": n} for a, n in senders.most_common(10)]}
        return httpx.Response(200, json={"data": data})

    def _search(self, spec: DemoTenant, body: dict) -> httpx.Response:
        start, end = _parse(body["timestamp"][0]), _parse(body["timestamp"][1])
        wanted = set(body.get("verdicts") or ["malicious", "phishing", "bec", "scam"])
        matches = [m for day in _days(start, end) for m in day_messages(spec.key, day)
                   if m["verdict"]["category"] in wanted and start <= _parse(m["timestamp"]) <= end]
        size = int(body.get("pageSize") or 100)
        offset = int(str(body["pageToken"]).split(":")[1]) if body.get("pageToken") else 0
        payload: dict[str, Any] = {"totalSize": len(matches), "data": {"messages": matches[offset:offset + size]}}
        if offset + size < len(matches):
            payload["nextPageToken"] = f"p:{offset + size}"
        return httpx.Response(200, json=payload)

    def _links(self, spec: DemoTenant, body: dict) -> httpx.Response:
        if spec.log_export_broken:
            return httpx.Response(503, json={"message": "Service Unavailable"})
        start = datetime.strptime(body["timeRange"][0], "%Y-%m-%dT%H").replace(tzinfo=UTC)
        end = datetime.strptime(body["timeRange"][1], "%Y-%m-%dT%H").replace(tzinfo=UTC)
        if end - start > timedelta(hours=3):
            return httpx.Response(400, json={"message": "Invalid daterange"})
        data: dict[str, list[str]] = {}
        for log_type in body.get("logTypes") or []:
            urls, hour = [], start
            while hour <= end:
                urls.append(f"https://{LOG_HOST}/tenant_id%3D{spec.key}/log_date%3D{hour:%Y-%m-%d}/hour%3D{hour:%H}"
                            f"/log_type%3D{log_type}/part-0000.jsonl?X-Amz-Signature=demo")
                hour += timedelta(hours=1)
            data[log_type] = urls
        return httpx.Response(200, json={"data": data})

    def _download(self, spec: DemoTenant, request: httpx.Request) -> httpx.Response:
        m = re.search(r"log_date=(\d{4}-\d{2}-\d{2})/hour=(\d{2})/log_type=(\w+)/", unquote(str(request.url)))
        if not m:
            return httpx.Response(404)
        day = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        lines = log_lines(spec, day, int(m.group(2)), m.group(3))
        return httpx.Response(200, content="\n".join(json.dumps(line) for line in lines).encode())


simulator = DemoETD()
