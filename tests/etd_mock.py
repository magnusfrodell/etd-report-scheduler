"""In-memory fake of the ETD API, served through httpx.MockTransport."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import httpx


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class MockETD:
    def __init__(self, *, directions_key: str = "directions", reject_first_bearer: bool = False, n_messages: int = 205) -> None:
        self.directions_key = directions_key
        self.reject_first_bearer = reject_first_bearer
        self.n_messages = n_messages
        self.calls: list[tuple[str, dict]] = []
        self.downloads: list[str] = []
        self.link_requests = 0
        self.token_calls = 0
        self._rejected_once = False

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "logs.example.invalid":  # pre-signed S3 download, not the ETD API
            return self._log_file(request)
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.calls.append((path, body))
        if not request.headers.get("x-api-key"):
            return httpx.Response(403, json={"message": "Forbidden"})
        if path == "/v1/oauth/token":
            self.token_calls += 1
            return httpx.Response(200, json={"accessToken": f"tok{self.token_calls}"})
        auth = request.headers.get("Authorization", "")
        if self.reject_first_bearer and not self._rejected_once:
            self._rejected_once = True
            return httpx.Response(401, json={"message": "Token expired, generate new token to proceed"})
        if not auth.startswith("Bearer tok"):
            return httpx.Response(401, json={"message": "Unauthorized"})
        if path == "/v1/messages/report":
            return self._report(body)
        if path == "/v1/messages/report/top":
            return self._top(body)
        if path == "/v1/messages/search":
            return self._search(body)
        if path == "/v1/logs/downloadLinks":
            return self._links(body)
        return httpx.Response(404, json={"message": "Not Found"})

    def _report(self, body: dict) -> httpx.Response:
        agg = body["aggregateBy"]
        if agg in ("directions", "direction") and agg != self.directions_key:
            return httpx.Response(400, json={"message": "Unable to deserialize request body"})
        start, end = _parse(body["timestamp"][0]), _parse(body["timestamp"][1])
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        buckets = []
        while day <= end:
            ts = day.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            if agg in ("directions", "direction"):
                buckets.append({"startTimestamp": ts, "messageCount": 150, "messages": {"incoming": 100, "outgoing": 20, "internal": 30}})
            elif agg == "verdicts":
                buckets.append({"startTimestamp": ts, "messageCount": 22, "messages": {"malicious": 3, "spam": 10, "phishing": 2, "graymail": 5, "bec": 1, "scam": 1}})
            else:
                buckets.append({"startTimestamp": ts, "messageCount": 2})
            day += timedelta(days=1)
        return httpx.Response(200, json={"data": {"aggregationInterval": body["aggregationInterval"], "totalMessages": sum(b["messageCount"] for b in buckets), "aggregations": buckets}})

    @staticmethod
    def _top(body: dict) -> httpx.Response:
        if body["reportType"] == "targets":
            data = {"topTargets": [
                {"emailAddress": "ceo@example.com", "malicious": 5, "phishing": 4, "bec": 3, "scam": 1},
                {"emailAddress": "cfo@example.com", "malicious": 2, "phishing": 1, "bec": 0, "scam": 0},
            ]}
        else:
            data = {"topExternalThreatSenders": [{"emailAddress": "bad@evil.example", "total": 30}, {"emailAddress": "worse@evil.example", "total": 12}]}
        return httpx.Response(200, json={"data": data})

    def _search(self, body: dict) -> httpx.Response:
        start, end = _parse(body["timestamp"][0]), _parse(body["timestamp"][1])
        page_size = int(body.get("pageSize") or 100)
        offset = int(body["pageToken"].split(":")[1]) if body.get("pageToken") else 0
        verdicts = body.get("verdicts") or ["malicious"]
        dirs = ["incoming", "outgoing", "internal"]
        msgs = []
        span = (end - start).total_seconds()
        for i in range(offset, min(offset + page_size, self.n_messages)):
            ts = start + timedelta(seconds=span * (i + 0.5) / self.n_messages)
            msgs.append({
                "id": f"msg-{i}",
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.123456789Z"),
                "direction": dirs[i % 3],
                "fromAddress": f"user{i % 7}@example.com" if i % 3 else f"sender{i % 5}@evil.example",
                "toAddresses": [f"rcpt{i % 11}@example.com"],
                "mailboxes": [f"rcpt{i % 11}@example.com"],
                "subject": f"Invoice {i}",
                "urls": [f"http://bad{i}.example/"],
                "verdict": {"originalVerdict": verdicts[i % len(verdicts)], "category": verdicts[i % len(verdicts)], "isRetroVerdict": i % 10 == 0,
                            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "businessRisk": "credential harvesting",
                            "techniques": [{"type": "Malicious URL", "severity": "high"}]},
                "action": {"type": "move", "folder": "junkemail", "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "isAutoRemediated": True},
                "secureEmailGateway": {"gatewayType": "ciscoDefault", "headerName": "X-IronPort-RemoteIP"},
            })
        nxt = offset + page_size
        payload = {"totalSize": self.n_messages, "data": {"messages": msgs}}
        if nxt < self.n_messages:
            payload["nextPageToken"] = f"p:{nxt}"
        return httpx.Response(200, json=payload)

    # ------------------------------------------------------------------ Log Export
    def _links(self, body: dict) -> httpx.Response:
        start = datetime.strptime(body["timeRange"][0], "%Y-%m-%dT%H").replace(tzinfo=UTC)
        end = datetime.strptime(body["timeRange"][1], "%Y-%m-%dT%H").replace(tzinfo=UTC)
        if end - start > timedelta(hours=3):
            return httpx.Response(400, json={"message": "Invalid daterange"})
        self.link_requests += 1
        data: dict[str, list[str]] = {}
        for log_type in body["logTypes"]:
            urls, hour = [], start
            while hour <= end:  # end hour inclusive, like the samples in the API docs
                urls.append(
                    f"https://logs.example.invalid/tenant_id%3Dmock/log_date%3D{hour:%Y-%m-%d}/hour%3D{hour:%H}"
                    f"/log_type%3D{log_type}/part-0000.jsonl?X-Amz-Expires=3600&X-Amz-Signature=sig{self.link_requests}"
                )
                hour += timedelta(hours=1)
            data[log_type] = urls
        return httpx.Response(200, json={"data": data})

    def _log_file(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") or request.headers.get("x-api-key"):
            return httpx.Response(400, text="<Error><Code>InvalidArgument</Code><Message>Only one auth mechanism allowed</Message></Error>")
        m = re.search(r"log_date=(\d{4}-\d{2}-\d{2})/hour=(\d{2})/log_type=(\w+)/", unquote(str(request.url)))
        if not m:
            return httpx.Response(404)
        self.downloads.append(unquote(request.url.path))
        lines = self.log_events(m.group(1), int(m.group(2)), m.group(3))
        return httpx.Response(200, content="\n".join(json.dumps(x) for x in lines).encode())

    @staticmethod
    def log_events(day: str, hour: int, log_type: str) -> list[dict]:
        ts = f"{day}T{hour:02d}:10:00Z"
        if log_type == "audit":
            if hour != 9:
                return []
            return [
                {"category": "email", "timestamp": f"{day} 09:15:00", "action": "reclassify", "status": "success", "comments": "",
                 "user": {"ip": "10.0.0.5", "userAgent": "Mozilla/5.0", "id": "user-analyst-1"},
                 "metadata": {"verdict": "neutral", "description": "Changing verdict to neutral", "emailId": f"e-{day}"}},
                {"category": "tenant", "timestamp": f"{day} 09:20:00", "action": "create_public_api_client", "status": "success", "comments": None,
                 "user": {"ip": "10.0.0.9", "userAgent": "python-requests/2.32.0", "id": "user-admin-1"}, "metadata": {"clientId": f"c-{day}"}},
                {"category": "user", "timestamp": f"{day} 09:25:00", "action": "login", "status": "failure", "comments": None,
                 "user": {"ip": "203.0.113.9", "userAgent": "Mozilla/5.0", "id": "user-unknown"}, "metadata": None},
            ]
        if log_type != "message":
            return []
        key = f"{day}-{hour:02d}"
        events = [
            {"message": {"eventType": "create", "id": f"n1-{key}", "fromAddresses": "billing@supplier.example", "replyTo": "billing@supplier.example",
                         "returnPath": "bounce@mail.supplier.example", "direction": "incoming", "timestamp": ts, "mailboxes": ["ap@corp.example"]},
             "logType": "message", "logDate": day, "logHour": f"{hour:02d}"},
            {"message": {"eventType": "create", "id": f"n2-{key}", "fromAddresses": "invoice@supp1ier.example", "replyTo": "pay@elsewhere.example",
                         "returnPath": "x@bulk.example", "direction": "incoming", "timestamp": ts, "mailboxes": ["ap@corp.example"]},
             "logType": "message", "logDate": day, "logHour": f"{hour:02d}"},
            {"message": {"eventType": "create", "id": f"c1-{key}", "fromAddresses": "ceo@corp.example", "direction": "incoming", "timestamp": ts,
                         "mailboxes": ["cfo@corp.example"], "verdict": {"verdict": "phishing", "category": "phishing"},
                         "action": {"action": "move", "remediatedBy": "automatic", "folder": "junkemail"}},
             "logType": "message", "logDate": day, "logHour": f"{hour:02d}"},
            {"message": {"eventType": "create", "id": f"o1-{key}", "fromAddresses": "someone@corp.example", "direction": "outgoing", "timestamp": ts, "mailboxes": []},
             "logType": "message", "logDate": day, "logHour": f"{hour:02d}"},
        ]
        if hour == 12:
            events += [
                {"message": {"eventType": "update", "id": f"c1-{key}", "internetMessageId": f"<c1-{key}@x>",
                             "verdict": {"verdict": "neutral", "reclassifiedBy": "user", "timestamp": ts, "user": "user-analyst-1"}}, "logType": "message"},
                {"message": {"eventType": "update", "id": f"r1-{key}", "internetMessageId": f"<r1-{key}@x>",
                             "action": {"action": "move", "folder": "trash", "remediatedBy": "manual", "timestamp": ts, "user": "user-analyst-1"}}, "logType": "message"},
            ]
        return events
