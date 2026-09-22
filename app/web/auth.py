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
"""Minimal session handling: one admin user, signed cookie, constant-time password check."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import AppConfig, get_config

SESSION_COOKIE = "etd_session"
TENANT_COOKIE = "etd_tenant"


def serializer(cfg: AppConfig | None = None) -> URLSafeTimedSerializer:
    cfg = cfg or get_config()
    return URLSafeTimedSerializer(cfg.secret_key, salt="etd-session")


def check_password(username: str, password: str, cfg: AppConfig | None = None) -> bool:
    cfg = cfg or get_config()
    return hmac.compare_digest(username, cfg.admin_username) and hmac.compare_digest(password, cfg.admin_password)


def session_token(username: str) -> str:
    return serializer().dumps({"user": username})


def read_session(request: Request) -> dict[str, Any] | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        return serializer().loads(raw, max_age=get_config().session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


def require_auth(request: Request) -> dict[str, Any]:
    session = read_session(request)
    if session is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": f"/login?next={request.url.path}"})
    return session


def current_tenant_selection(request: Request) -> str:
    """'all' or a tenant id as string; drives the tenant switcher in the header."""
    value = request.cookies.get(TENANT_COOKIE, "all")
    return value if value == "all" or value.isdigit() else "all"
