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
import secrets
from datetime import timedelta

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import AppConfig, get_config
from app.db import session_scope
from app.models import Setting, User, UserSession, utcnow

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
# The cookie carries a random token in a signed envelope; the session itself lives in the database, so
# signing out, an administrator's revoke, a password change or inactivity ends it for whoever holds the
# cookie - not just in the browser that pressed the button.
TOUCH_EVERY = timedelta(seconds=60)  # how often last_seen_at is written


def serializer(cfg: AppConfig | None = None) -> URLSafeTimedSerializer:
    cfg = cfg or get_config()
    return URLSafeTimedSerializer(cfg.secret_key, salt="etd-session-v3")  # v2 cookies (before 0.12.0) sign in again


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, request: Request, method: str = "password") -> str:
    """Start a session for ``user`` and return the cookie value."""
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(UserSession(user_id=user.id, token_hash=_token_hash(token), created_at=now, last_seen_at=now,
                       expires_at=now + timedelta(seconds=get_config().session_max_age_seconds),
                       ip=request.client.host if request.client else None,
                       user_agent=(request.headers.get("user-agent") or "")[:200] or None, auth_method=method))
    return serializer().dumps({"sid": token})


def read_session(request: Request) -> str | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = serializer().loads(raw, max_age=get_config().session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("sid") if isinstance(data, dict) and isinstance(data.get("sid"), str) else None


def _idle_limit(db: Session) -> timedelta | None:
    row = db.get(Setting, "session_idle_minutes")
    try:
        minutes = int(row.value) if row is not None and row.value is not None else 120
    except (TypeError, ValueError):
        minutes = 120
    return timedelta(minutes=minutes) if minutes > 0 else None


def current_session(db: Session, request: Request) -> UserSession | None:
    token = read_session(request)
    if token is None:
        return None
    session = db.execute(select(UserSession).where(UserSession.token_hash == _token_hash(token))).scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return None
    now = utcnow()
    idle = _idle_limit(db)
    if session.expires_at <= now:
        return None
    if idle is not None and session.last_seen_at + idle <= now:
        _end([session.id], "inactivity")
        return None
    if now - session.last_seen_at >= TOUCH_EVERY:
        with session_scope() as touch:  # WAL: a short write of its own, independent of the request's transaction
            touch.execute(update(UserSession).where(UserSession.id == session.id).values(last_seen_at=now))
    return session


def user_from_session(db: Session, request: Request) -> User | None:
    session = current_session(db, request)
    if session is None:
        return None
    user = db.get(User, session.user_id)
    if user is None or not user.enabled:
        return None
    request.state.session_id = session.id
    return user


def _end(session_ids: list[int], reason: str) -> None:
    if not session_ids:
        return
    with session_scope() as db:
        db.execute(update(UserSession).where(UserSession.id.in_(session_ids), UserSession.revoked_at.is_(None))
                   .values(revoked_at=utcnow(), revoked_reason=reason[:60]))


def active_sessions(db: Session, user_id: int | None = None) -> list[UserSession]:
    """Sessions that can still be used, most recently active first; all users when ``user_id`` is None."""
    now = utcnow()
    query = select(UserSession).where(UserSession.revoked_at.is_(None), UserSession.expires_at > now)
    if user_id is not None:
        query = query.where(UserSession.user_id == user_id)
    idle = _idle_limit(db)
    rows = list(db.execute(query.order_by(UserSession.last_seen_at.desc())).scalars())
    return [r for r in rows if idle is None or r.last_seen_at + idle > now]


def end_sessions(db: Session, user_id: int, reason: str, keep: int | None = None) -> int:
    """End every session of a user (except ``keep``). Returns how many were ended."""
    ids = [s.id for s in active_sessions(db, user_id) if s.id != keep]
    db.execute(update(UserSession).where(UserSession.id.in_(ids)).values(revoked_at=utcnow(), revoked_reason=reason[:60]))
    return len(ids)


def end_session(db: Session, session_id: int, reason: str) -> UserSession | None:
    session = db.get(UserSession, session_id)
    if session is not None and session.revoked_at is None:
        session.revoked_at, session.revoked_reason = utcnow(), reason[:60]
    return session


def device_label(user_agent: str | None) -> str:
    """'Edge on Windows' from a User-Agent header - enough to recognise one's own browser."""
    ua = user_agent or ""
    browser = next((name for key, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                                           ("Safari/", "Safari"), ("curl/", "curl"), ("python-httpx", "script"), ("testclient", "test client"))
                    if key.lower() in ua.lower()), "")
    system = next((name for key, name in (("Windows", "Windows"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Android", "Android"),
                                          ("Mac OS X", "macOS"), ("Macintosh", "macOS"), ("Linux", "Linux")) if key in ua), "")
    if browser and system:
        return f"{browser} on {system}"
    return browser or system or (ua[:40] if ua else "unknown device")


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
