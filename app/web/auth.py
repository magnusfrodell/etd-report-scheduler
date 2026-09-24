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
"""Authentication: scrypt password hashes, signed session cookies, bootstrap admin.

Sessions carry the user id and the tail of the password hash, so changing a
password (or resetting it with ``python -m app.manage``) invalidates every
existing session of that user.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from typing import Any

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import AppConfig, get_config
from app.models import User, utcnow

log = logging.getLogger(__name__)

SESSION_COOKIE = "etd_session"
TENANT_COOKIE = "etd_tenant"
MIN_PASSWORD_LENGTH = 8

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        return False
    try:
        _, salt_b64, digest_b64 = stored.split("$", 2)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return hmac.compare_digest(digest, expected)


def validate_new_password(password: str) -> str | None:
    """Return an error message or None when acceptable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None


# ------------------------------------------------------------------- sessions
def serializer(cfg: AppConfig | None = None) -> URLSafeTimedSerializer:
    cfg = cfg or get_config()
    return URLSafeTimedSerializer(cfg.secret_key, salt="etd-session-v2")


def session_token(user: User) -> str:
    return serializer().dumps({"uid": user.id, "ph": user.password_hash[-16:]})


def read_session(request: Request) -> dict[str, Any] | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = serializer().loads(raw, max_age=get_config().session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    return data if isinstance(data, dict) and "uid" in data else None


def user_from_session(db: Session, request: Request) -> User | None:
    data = read_session(request)
    if data is None:
        return None
    user = db.get(User, int(data["uid"]))
    if user is None or not user.enabled or user.password_hash[-16:] != data.get("ph"):
        return None
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.execute(select(User).where(func.lower(User.username) == username.strip().lower())).scalar_one_or_none()
    if user is None or not user.enabled or not verify_password(password, user.password_hash):
        if user is None:  # hash anyway so timing does not reveal which usernames exist
            verify_password(password, hash_password("x"))
        return None
    user.last_login_at = utcnow()
    return user


def current_tenant_selection(request: Request) -> str:
    """'all' or a tenant id as string; drives the tenant switcher in the header."""
    value = request.cookies.get(TENANT_COOKIE, "all")
    return value if value == "all" or value.isdigit() else "all"


# ------------------------------------------------------------------ bootstrap
def bootstrap_admin(db: Session, cfg: AppConfig | None = None) -> User | None:
    """Create the first admin from ADMIN_USERNAME/ADMIN_PASSWORD when no users exist."""
    cfg = cfg or get_config()
    if db.execute(select(func.count()).select_from(User)).scalar_one():
        return None
    user = User(username=cfg.admin_username, display_name="Administrator", password_hash=hash_password(cfg.admin_password), role="admin", enabled=True)
    db.add(user)
    db.flush()
    log.warning("Created initial admin user %r from environment - manage users in the UI from now on", cfg.admin_username)
    return user
