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
"""API keys: ``Authorization: Bearer etd_<key id>_<secret>`` for scripts and integrations.

A key acts as its user and can only narrow what the user may do: "read" allows GET requests, "run"
also starts reports and collection. It works with /api only, never with the web UI. The key id is
public - it appears in lists and in the activity log - and only a SHA-256 of the whole key is stored,
so a copy of the database cannot be used to call the API."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db import session_scope
from app.models import ApiKey, User, utcnow

SCOPES = {"read": "Read", "run": "Read and run reports and collection"}
EXPIRY_DAYS = {"30": 30, "90": 90, "365": 365, "never": None}
TOUCH_EVERY = timedelta(seconds=60)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create(db: Session, user: User, name: str, scope: str, expires: str, created_by: str) -> tuple[ApiKey, str]:
    """A new key for ``user``: the row and the key itself, which is shown once and never stored."""
    key_id = secrets.token_hex(5)
    raw = f"etd_{key_id}_{secrets.token_urlsafe(32)}"
    days = EXPIRY_DAYS.get(expires, 90)
    row = ApiKey(user_id=user.id, name=" ".join(name.split())[:120] or "API key", key_id=key_id, secret_hash=_hash(raw),
                 scope=scope if scope in SCOPES else "read", created_by=created_by[:120],
                 expires_at=utcnow() + timedelta(days=days) if days else None)
    db.add(row)
    return row, raw


def key_id_of(raw: str) -> str | None:
    parts = raw.split("_", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "etd" and parts[1].isalnum() and len(parts[1]) <= 16 else None


def label(key: ApiKey) -> str:
    return f"{key.name} (etd_{key.key_id})"


def check(db: Session, raw: str) -> tuple[ApiKey | None, str]:
    """The key if it is valid, else None and why."""
    key_id = key_id_of(raw)
    row = db.execute(select(ApiKey).where(ApiKey.key_id == key_id)).scalar_one_or_none() if key_id else None
    if row is None or not hmac.compare_digest(row.secret_hash, _hash(raw)):
        return None, "unknown API key"
    if row.revoked_at is not None:
        return None, "the API key was revoked"
    if row.expires_at is not None and row.expires_at <= utcnow():
        return None, "the API key has expired"
    return row, ""


def touch(key: ApiKey, request: Request) -> None:
    """Record use, at most once a minute, in a short transaction of its own."""
    now = utcnow()
    if key.last_used_at is not None and now - key.last_used_at < TOUCH_EVERY:
        return
    with session_scope() as db:
        db.execute(update(ApiKey).where(ApiKey.id == key.id).values(last_used_at=now, last_used_ip=request.client.host if request.client else None))


def revoke(db: Session, key: ApiKey, by: str) -> None:
    if key.revoked_at is None:
        key.revoked_at, key.revoked_by = utcnow(), by[:120]


def status(key: ApiKey) -> str:
    if key.revoked_at is not None:
        return "revoked"
    if key.expires_at is not None and key.expires_at <= utcnow():
        return "expired"
    return "active"
