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
"""Browser-facing hardening: cross-origin protection, security headers, safe redirect targets
and sign-in throttling."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "frame-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'none'; object-src 'none'"
)
# Archived reports contain text chosen by attackers (subjects, sender names). It is escaped when the
# report is rendered; the sandbox is a second layer so nothing in a report can ever run as this app.
REPORT_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; frame-ancestors 'self'"
# FastAPI's Swagger UI loads its bundle from jsDelivr and starts it with an inline script.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'self'"
)


def is_report_file(path: str) -> bool:
    parts = path.strip("/").split("/")
    return len(parts) == 3 and parts[0] == "reports" and parts[1].isdigit() and parts[2] in ("html", "pdf")


def origin_allowed(headers: Headers, trusted: frozenset[str] = frozenset()) -> bool:
    """Decide whether a state-changing request may proceed (the model of Go's CrossOriginProtection).

    Browsers send ``Sec-Fetch-Site``: only ``same-origin`` (or user-initiated ``none``) passes, so a web
    UI on the same host but another port - same *site*, different *origin*, where SameSite cookies are
    still attached - is refused. Browsers without Fetch Metadata fall back to comparing ``Origin`` with
    ``Host``. Requests with neither header are not browser form posts (scripts, curl) and pass.
    """
    origin = headers.get("origin")
    if origin and origin.rstrip("/").lower() in trusted:
        return True
    site = headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    if origin is None:
        return True
    if origin == "null":
        return False
    return urlsplit(origin).netloc.lower() == headers.get("host", "").lower()


class SecurityMiddleware:
    """Refuses cross-origin state changes and adds security headers to every response."""

    def __init__(self, app: ASGIApp, trusted_origins: str = "") -> None:
        self.app = app
        self.trusted = frozenset(o.strip().rstrip("/").lower() for o in trusted_origins.split(",") if o.strip())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope["method"] not in SAFE_METHODS and not origin_allowed(Headers(scope=scope), self.trusted):
            await PlainTextResponse("Cross-origin request blocked.", status_code=403)(scope, receive, send)
            return
        path: str = scope["path"]

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("Referrer-Policy", "same-origin")
                headers.setdefault("X-Frame-Options", "SAMEORIGIN")
                if not path.startswith("/static/"):
                    headers.setdefault("Cache-Control", "no-store")
                    csp = DOCS_CSP if path.startswith("/api/docs") else REPORT_CSP if is_report_file(path) else APP_CSP
                    headers.setdefault("Content-Security-Policy", csp)
            await send(message)

        await self.app(scope, receive, send_with_headers)


def safe_next(value: str | None, default: str = "/", prefixes: tuple[str, ...] = ("/",)) -> str:
    """A local path to redirect to after a form, or ``default``.

    Rejects ``//host``, ``/\\host`` and control characters (browsers treat both slashes alike and
    drop tabs and newlines, so ``/\\t/host`` would leave the site too) as well as absolute URLs."""
    v = (value or "").strip()
    if not v.startswith("/") or v.startswith("//") or "\\" in v or any(ord(c) < 32 or ord(c) == 127 for c in v):
        return default
    parts = urlsplit(v)
    if parts.scheme or parts.netloc:
        return default
    return v if v.startswith(prefixes) else default


class LoginLimiter:
    """Failed sign-ins per account and client, and per client, within a sliding window.

    Keyed by account *and* client address, so nobody can lock a known user out from elsewhere.
    Kept in memory: the tool runs as a single process."""

    def __init__(self, *, window_seconds: int = 900, per_account: int = 5, per_client: int = 20, clock: Callable[[], float] = time.monotonic) -> None:
        self.window, self.per_account, self.per_client, self._clock = window_seconds, per_account, per_client, clock
        self._failures: dict[tuple[str, ...], list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: tuple[str, ...], now: float) -> list[float]:
        stamps = [t for t in self._failures.get(key, []) if now - t < self.window]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def retry_after(self, username: str, client: str) -> int:
        """Seconds until the next attempt is allowed, 0 if it is allowed now."""
        now = self._clock()
        with self._lock:
            for key, limit in (((client, username.strip().lower()), self.per_account), ((client,), self.per_client)):
                stamps = self._recent(key, now)
                if len(stamps) >= limit:
                    return max(1, int(stamps[-limit] + self.window - now) + 1)
        return 0

    def failed(self, username: str, client: str) -> None:
        now = self._clock()
        with self._lock:
            if len(self._failures) > 10_000:
                for key in list(self._failures):
                    self._recent(key, now)
            for key in ((client, username.strip().lower()), (client,)):
                self._failures.setdefault(key, []).append(now)

    def succeeded(self, username: str, client: str) -> None:
        with self._lock:
            self._failures.pop((client, username.strip().lower()), None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


login_limiter = LoginLimiter()
