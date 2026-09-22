"""In-memory fake of the ETD API, served through httpx.MockTransport."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import httpx


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class MockETD:
    def __init__(self, *, directions_key: str = "directions", reject_first_bearer: bool = False, n_messages: int = 205) -> None:
        self.directions_key = directions_key
        self.reject_first_bearer = reject_first_bearer
        self.n_messages = n_messages
        self.calls: list[tuple[str, dict]] = []
        self.token_calls = 0
        self._rejected_once = False

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def handler(self, request: httpx.Request) -> httpx.Response:
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
            return httpx.Response(200, json={"data": {t: [f"https://example.invalid/{t}.jsonl"] for t in body["logTypes"]}})
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
