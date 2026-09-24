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
"""Thin, synchronous client for the Secure Email Threat Defense public API.

Covers the parts needed for reporting:

* ``POST /v1/oauth/token``            - JWT (valid 60 minutes), cached and refreshed on 401
* ``POST /v1/messages/report``        - time series by direction / verdicts / retroVerdicts
* ``POST /v1/messages/report/top``    - top-10 targets and external threat senders
* ``POST /v1/messages/search``        - message search, paginated, 32-day windows
* ``POST /v1/logs/downloadLinks``     - log export links (message / audit / connection)

Documented limits are enforced client-side so callers never have to think
about them: search windows are chunked to 31 days, the 90-day horizon is
clamped, 429s are retried with back-off.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.etd.regions import base_url_for

log = logging.getLogger(__name__)

SEARCH_MAX_WINDOW_DAYS = 31  # documented maximum is 32 days; stay one day inside it
HISTORY_HORIZON_DAYS = 90  # reporting and search only reach 90 days back
TOKEN_TTL_SECONDS = 60 * 60
TOKEN_REFRESH_MARGIN = 120
DEFAULT_PAGE_SIZE = 100

VALID_VERDICTS = ("spam", "malicious", "phishing", "graymail", "neutral", "bec", "scam")
VALID_DIRECTIONS = ("incoming", "outgoing", "internal", "mixed")


RATE_LIMIT_PER_SECOND = 2.0  # documented sustained limit per tenant (burst 4)


class RateLimiter:
    """Minimal-interval limiter shared by every client of the same tenant, so stats,
    conviction and backfill jobs together never exceed the documented 2 requests/s."""

    def __init__(self, per_second: float, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._clock, self._sleep = clock, sleep
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block until a request may start; returns the seconds slept."""
        if not self.interval:
            return 0.0
        with self._lock:
            now = self._clock()
            start = max(now, self._next_allowed)
            self._next_allowed = start + self.interval
        delay = start - now
        if delay > 0:
            self._sleep(delay)
        return delay


_limiters: dict[str, RateLimiter] = {}
_limiters_lock = threading.Lock()


def limiter_for(key: str, per_second: float = RATE_LIMIT_PER_SECOND) -> RateLimiter:
    with _limiters_lock:
        limiter = _limiters.get(key)
        if limiter is None:
            limiter = _limiters[key] = RateLimiter(per_second)
        return limiter


class ETDError(Exception):
    """Any non-successful response from the ETD API."""

    def __init__(self, message: str, status: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class ETDAuthError(ETDError):
    pass


class ETDRateLimited(ETDError):
    pass


def iso_utc(value: datetime) -> str:
    """Format a datetime the way the API wants it: ``YYYY-MM-DDTHH:MM:SSZ``."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Trim sub-microsecond precision (the API emits up to 9 fractional digits).
    if "." in text:
        head, _, tail = text.partition(".")
        frac = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[i:]
                break
        text = f"{head}.{frac[:6]}{rest}" if frac else f"{head}{rest}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


class ETDClient:
    def __init__(
        self,
        region: str,
        client_id: str,
        client_secret: str,
        api_key: str,
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        base_url: str | None = None,
        max_retries: int = 3,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.region = region
        self.base_url = base_url or base_url_for(region)
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_key = api_key
        self.max_retries = max_retries
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._aggregate_by_alias: dict[str, str] = {}
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)
        # Log Export files are pre-signed S3 URLs: plain GETs, never with API credentials.
        self._download_http = httpx.Client(timeout=max(timeout, 60.0), transport=transport, follow_redirects=True)
        self._limiter = rate_limiter or limiter_for(f"{self.base_url}|{client_id}")
        self.request_count = 0

    # ------------------------------------------------------------------ auth
    def close(self) -> None:
        self._http.close()
        self._download_http.close()

    def __enter__(self) -> ETDClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_token(self, force: bool = False) -> str:
        if not force and self._token and time.monotonic() < self._token_expires_at - TOKEN_REFRESH_MARGIN:
            return self._token
        log.debug("Requesting new ETD token (region=%s)", self.region)
        self._limiter.wait()
        resp = self._http.post(
            "/v1/oauth/token",
            auth=(self.client_id, self.client_secret),
            headers={"x-api-key": self.api_key, "Accept": "application/json"},
        )
        self.request_count += 1
        if resp.status_code in (400, 401, 403):
            raise ETDAuthError(
                f"Authentication failed ({resp.status_code}). Check client ID, secret and API key.",
                status=resp.status_code,
                body=resp.text[:500],
            )
        if resp.status_code != 200:
            raise ETDError(f"Token request failed ({resp.status_code})", status=resp.status_code, body=resp.text[:500])
        payload = self._json(resp)
        token = (
            payload.get("accessToken")
            or payload.get("access_token")
            or payload.get("token")
            or (payload.get("data") or {}).get("accessToken")
        )
        if not token:
            raise ETDAuthError("Token response did not contain an access token", status=200, body=resp.text[:500])
        self._token = token
        self._token_expires_at = time.monotonic() + TOKEN_TTL_SECONDS
        return token

    def test_connection(self) -> bool:
        self.get_token(force=True)
        return True

    # -------------------------------------------------------------- transport
    @staticmethod
    def _json(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError as exc:
            raise ETDError("Response was not JSON", status=resp.status_code, body=resp.text[:500]) from exc
        if not isinstance(data, dict):
            raise ETDError("Unexpected JSON payload", status=resp.status_code, body=resp.text[:500])
        return data

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        refreshed = False
        while True:
            attempt += 1
            headers = {
                "Authorization": f"Bearer {self.get_token()}",
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            self._limiter.wait()
            resp = self._http.post(path, json=body, headers=headers)
            self.request_count += 1
            if resp.status_code == 200:
                return self._json(resp)
            if resp.status_code == 401 and not refreshed:
                log.info("ETD token rejected, refreshing once")
                refreshed = True
                self.get_token(force=True)
                continue
            if resp.status_code == 429:
                if attempt > self.max_retries:
                    raise ETDRateLimited(
                        "ETD rate limit exceeded (2 req/s, 10 000 req/day per tenant)",
                        status=429,
                        body=resp.text[:500],
                    )
                wait = float(resp.headers.get("Retry-After") or 2 ** attempt)
                log.warning("ETD 429 on %s, waiting %.0fs (attempt %d)", path, wait, attempt)
                time.sleep(min(wait, 60))
                continue
            if resp.status_code in (502, 503) and attempt <= self.max_retries:
                wait = 2**attempt
                log.warning("ETD %s on %s, retrying in %ds", resp.status_code, path, wait)
                time.sleep(wait)
                continue
            if resp.status_code == 403:
                raise ETDAuthError("Forbidden - the x-api-key header is missing or invalid", status=403, body=resp.text[:500])
            raise ETDError(f"ETD API error {resp.status_code} on {path}", status=resp.status_code, body=resp.text[:500])

    # -------------------------------------------------------------- reporting
    def report(self, aggregate_by: str, start: datetime, end: datetime, interval: str = "1d") -> dict[str, Any]:
        """``/v1/messages/report`` - aggregate_by is ``directions``, ``verdicts`` or ``retroVerdicts``.

        The DevNet documentation uses both ``directions`` and ``direction``; the
        client tries the documented sample first and falls back once on a 400.
        """
        start, end = self._clamp(start, end)
        candidates = [self._aggregate_by_alias.get(aggregate_by, aggregate_by)]
        if aggregate_by == "directions":
            candidates.append("direction")
        elif aggregate_by == "direction":
            candidates.append("directions")
        last_error: ETDError | None = None
        for candidate in candidates:
            body = {"aggregationInterval": interval, "timestamp": [iso_utc(start), iso_utc(end)], "aggregateBy": candidate}
            try:
                data = self._post("/v1/messages/report", body)
            except ETDError as exc:
                if exc.status == 400 and len(candidates) > 1:
                    last_error = exc
                    continue
                raise
            self._aggregate_by_alias[aggregate_by] = candidate
            return data.get("data") or {}
        assert last_error is not None
        raise last_error

    def report_top(self, report_type: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        """``/v1/messages/report/top`` - report_type is ``targets`` or ``threatSenders``."""
        start, end = self._clamp(start, end)
        body = {"timestamp": [iso_utc(start), iso_utc(end)], "reportType": report_type}
        data = self._post("/v1/messages/report/top", body).get("data") or {}
        if report_type == "targets":
            return list(data.get("topTargets") or [])
        return list(data.get("topExternalThreatSenders") or data.get("topThreatSenders") or [])

    # ----------------------------------------------------------------- search
    def search_page(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("/v1/messages/search", body)

    def iter_pages(
        self,
        start: datetime,
        end: datetime,
        *,
        verdicts: list[str] | None = None,
        directions: list[str] | None = None,
        subject: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages_per_window: int = 10_000,
    ) -> Iterator[list[dict[str, Any]]]:
        """Yield one list of messages per API page; windows longer than 31 days are chunked.

        Callers that need to stop early (quota budgets) simply stop iterating - no request
        is made until the next page is asked for.
        """
        start, end = self._clamp(start, end)
        for win_start, win_end in self.windows(start, end):
            body: dict[str, Any] = {"timestamp": [iso_utc(win_start), iso_utc(win_end)], "pageSize": page_size}
            if verdicts:
                body["verdicts"] = [v for v in verdicts if v in VALID_VERDICTS]
            if directions:
                body["directions"] = [d for d in directions if d in VALID_DIRECTIONS]
            if subject:
                body["subject"] = subject
            page_token: str | None = None
            pages = 0
            while True:
                if page_token:
                    body["pageToken"] = page_token
                else:
                    body.pop("pageToken", None)
                payload = self.search_page(body)
                messages = (payload.get("data") or {}).get("messages") or []
                yield list(messages)
                page_token = payload.get("nextPageToken")
                pages += 1
                if not page_token or not messages or pages >= max_pages_per_window:
                    break

    def iter_messages(self, start: datetime, end: datetime, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Flat iterator over :meth:`iter_pages`."""
        for page in self.iter_pages(start, end, **kwargs):
            yield from page

    # ------------------------------------------------------------- log export
    def log_download_links(self, start: datetime, end: datetime, log_types: list[str]) -> dict[str, list[str]]:
        """``/v1/logs/downloadLinks`` - hour granularity, max 3 hours per call, 30-day retention."""
        if end - start > timedelta(hours=3):
            raise ValueError("Log export requests may span at most 3 hours")
        fmt = "%Y-%m-%dT%H"
        body = {"timeRange": [start.astimezone(UTC).strftime(fmt), end.astimezone(UTC).strftime(fmt)], "logTypes": log_types}
        data = self._post("/v1/logs/downloadLinks", body).get("data") or {}
        return {k: list(v or []) for k, v in data.items()}

    def download(self, url: str) -> bytes:
        """Fetch one Log Export file. The URL carries its own signature; sending the bearer
        token or API key as well would leak them to S3 and make S3 reject the request."""
        resp = self._download_http.get(url)
        if resp.status_code != 200:
            raise ETDError(f"Log file download failed ({resp.status_code})", status=resp.status_code, body=resp.text[:300])
        return resp.content

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def windows(start: datetime, end: datetime, days: int = SEARCH_MAX_WINDOW_DAYS) -> list[tuple[datetime, datetime]]:
        out: list[tuple[datetime, datetime]] = []
        cursor = start
        step = timedelta(days=days)
        while cursor < end:
            nxt = min(cursor + step, end)
            out.append((cursor, nxt))
            cursor = nxt
        return out

    @staticmethod
    def _clamp(start: datetime, end: datetime) -> tuple[datetime, datetime]:
        now = datetime.now(UTC)
        horizon = now - timedelta(days=HISTORY_HORIZON_DAYS - 1)
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if start < horizon:
            log.info("Clamping start %s to the 90-day horizon %s", start, horizon)
            start = horizon
        if end > now:
            end = now
        if end <= start:
            raise ValueError("end must be later than start (after clamping to the 90-day horizon)")
        return start, end
