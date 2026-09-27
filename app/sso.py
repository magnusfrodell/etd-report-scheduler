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
"""Single sign-on with OpenID Connect - built against Duo Single Sign-On, and standard enough for Entra ID,
Okta and other providers.

Authorization Code flow with PKCE (S256), state and nonce. The ID token is checked against the keys the
provider publishes (JWKS): signature, issuer, audience, expiry and nonce. Only the user's browser talks to
this container during sign-in; the token exchange is outbound."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_config
from app.models import User, utcnow
from app.settings_store import RuntimeSettings

log = logging.getLogger(__name__)

CALLBACK_PATH = "/auth/sso/callback"
STATE_COOKIE = "etd_sso"
STATE_MAX_AGE = 600  # seconds to finish signing in at the provider
UNUSABLE_PASSWORD = "!sso"  # accounts created by single sign-on have no password
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384")
CACHE_SECONDS = 3600


def _default_transport() -> httpx.BaseTransport | None:
    return None


# Tests replace this to stand in for the identity provider.
transport_factory = _default_transport


class SsoError(Exception):
    """Signing in failed; the message says what to do about it."""

    def __init__(self, message: str, denied: bool = False) -> None:
        super().__init__(message)
        self.denied = denied  # the person is not allowed, as opposed to something being broken


@dataclass(frozen=True)
class Provider:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    algorithms: tuple[str, ...]


_providers: dict[str, tuple[float, Provider]] = {}
_keys: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _client() -> httpx.Client:
    return httpx.Client(timeout=15.0, transport=transport_factory(), follow_redirects=False)


def callback_url(settings: RuntimeSettings) -> str:
    return settings.base_url.rstrip("/") + CALLBACK_PATH if settings.base_url else ""


def discover(issuer: str, fresh: bool = False) -> Provider:
    issuer = issuer.strip().rstrip("/")
    if not issuer.startswith("https://"):
        raise SsoError("The issuer must be an https URL - copy it from the provider (Duo: the application's Metadata tab).")
    cached = _providers.get(issuer)
    if cached and not fresh and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with _client() as client:
            response = client.get(url)
        response.raise_for_status()
        doc = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError(f"Could not read the provider's configuration at {url}: {exc}") from exc
    if str(doc.get("issuer", "")).rstrip("/") != issuer:
        raise SsoError(f"The provider calls itself '{doc.get('issuer')}', not '{issuer}' - copy the issuer exactly as the provider shows it.")
    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(k)]
    if missing:
        raise SsoError(f"The provider's configuration lacks {', '.join(missing)}.")
    algorithms = tuple(a for a in doc.get("id_token_signing_alg_values_supported") or ["RS256"] if a in ALLOWED_ALGORITHMS) or ("RS256",)
    provider = Provider(issuer, doc["authorization_endpoint"], doc["token_endpoint"], doc["jwks_uri"], doc.get("userinfo_endpoint"), algorithms)
    _providers[issuer] = (time.monotonic(), provider)
    return provider


def _jwks(provider: Provider, fresh: bool = False) -> list[dict[str, Any]]:
    cached = _keys.get(provider.jwks_uri)
    if cached and not fresh and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    try:
        with _client() as client:
            response = client.get(provider.jwks_uri)
        response.raise_for_status()
        keys = list(response.json().get("keys") or [])
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError(f"Could not read the provider's signing keys: {exc}") from exc
    _keys[provider.jwks_uri] = (time.monotonic(), keys)
    return keys


def check(settings: RuntimeSettings) -> str:
    """Read the provider's configuration and keys now - for the Check button."""
    provider = discover(settings.sso_issuer, fresh=True)
    keys = _jwks(provider, fresh=True)
    return f"Found {provider.issuer}: sign-in at {provider.authorization_endpoint}, {len(keys)} signing key(s)."


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_config().secret_key, salt="etd-sso-state-v1")


def start(settings: RuntimeSettings, next_url: str) -> tuple[str, str]:
    """The provider's sign-in URL, and the value of the short-lived cookie that the callback checks."""
    provider = discover(settings.sso_issuer)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": settings.sso_client_id, "response_type": "code", "redirect_uri": callback_url(settings),
              "scope": " ".join(settings.sso_scopes.split()) or "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    separator = "&" if "?" in provider.authorization_endpoint else "?"
    cookie = _serializer().dumps({"state": state, "nonce": nonce, "verifier": verifier, "next": next_url})
    return f"{provider.authorization_endpoint}{separator}{urlencode(params)}", cookie


def read_state(cookie: str | None) -> dict[str, Any]:
    if not cookie:
        raise SsoError("The sign-in was not started in this browser, or it took longer than 10 minutes - start it again.")
    try:
        return _serializer().loads(cookie, max_age=STATE_MAX_AGE)
    except SignatureExpired as exc:
        raise SsoError("The sign-in took longer than 10 minutes - start it again.") from exc
    except BadSignature as exc:
        raise SsoError("The sign-in could not be matched to this browser - start it again.") from exc


def exchange(settings: RuntimeSettings, code: str, verifier: str) -> dict[str, Any]:
    provider = discover(settings.sso_issuer)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": callback_url(settings), "code_verifier": verifier,
            "client_id": settings.sso_client_id, "client_secret": settings.sso_client_secret}
    try:
        with _client() as client:
            response = client.post(provider.token_endpoint, data=data, headers={"Accept": "application/json"})
        tokens = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SsoError(f"The provider could not be reached to finish the sign-in: {exc}") from exc
    if response.status_code != 200:
        reason = tokens.get("error_description") or tokens.get("error") or response.text[:200]
        raise SsoError(f"The provider refused to finish the sign-in ({response.status_code}): {reason}")
    if not tokens.get("id_token"):
        raise SsoError("The provider sent no ID token - 'openid' must be among the scopes.")
    return tokens


def _signing_key(provider: Provider, kid: str | None) -> Any:
    for fresh in (False, True):  # a key the provider rotated in since the last look
        for jwk in _jwks(provider, fresh):
            if kid is None or jwk.get("kid") == kid:
                try:
                    return jwt.PyJWK(jwk).key
                except jwt.PyJWKError:
                    continue
    raise SsoError("The ID token is signed with a key the provider does not publish.")


def verify_id_token(settings: RuntimeSettings, id_token: str, nonce: str) -> dict[str, Any]:
    provider = discover(settings.sso_issuer)
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise SsoError(f"The ID token cannot be read: {exc}") from exc
    algorithm = header.get("alg")
    if algorithm not in provider.algorithms:
        raise SsoError(f"The ID token is signed with {algorithm}, which the provider does not announce.")
    key = _signing_key(provider, header.get("kid"))
    try:
        claims = jwt.decode(id_token, key=key, algorithms=[algorithm], audience=settings.sso_client_id, issuer=provider.issuer,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=60)
    except jwt.ExpiredSignatureError as exc:
        raise SsoError("The ID token has expired - check the clock of this server.") from exc
    except jwt.InvalidAudienceError as exc:
        raise SsoError("The ID token is for another application - check the client ID.") from exc
    except jwt.InvalidIssuerError as exc:
        raise SsoError("The ID token comes from another issuer - check the issuer URL.") from exc
    except jwt.InvalidTokenError as exc:
        raise SsoError(f"The ID token is not valid: {exc}") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SsoError("The ID token does not belong to this sign-in (nonce) - start it again.")
    return claims


def userinfo(settings: RuntimeSettings, access_token: str | None, subject: str) -> dict[str, Any]:
    """Claims from the UserInfo endpoint, when the provider has one - only if they are about the same person."""
    provider = discover(settings.sso_issuer)
    if not provider.userinfo_endpoint or not access_token:
        return {}
    try:
        with _client() as client:
            response = client.get(provider.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
        info = response.json() if response.status_code == 200 else {}
    except (httpx.HTTPError, ValueError):
        log.warning("Single sign-on: the UserInfo endpoint could not be read; using the ID token alone")
        return {}
    return info if isinstance(info, dict) and info.get("sub") == subject else {}


def groups_of(claims: dict[str, Any], claim: str) -> list[str]:
    value = claims.get(claim or "groups")
    if isinstance(value, str):
        return [g.strip() for g in value.replace(";", ",").split(",") if g.strip()]
    if isinstance(value, list):
        return [str(g).strip() for g in value if str(g).strip()]
    return []


def role_from_groups(settings: RuntimeSettings, groups: list[str]) -> str | None:
    """The global role the groups give, or None when no group mapping is set up (roles are then kept)."""
    admins = {g.strip().lower() for g in settings.sso_admin_groups.split(",") if g.strip()}
    tenant_admins = {g.strip().lower() for g in settings.sso_tenant_admin_groups.split(",") if g.strip()}
    if not admins and not tenant_admins:
        return None
    member = {g.lower() for g in groups}
    if member & admins:
        return "admin"
    if member & tenant_admins:
        return "tenant_admin"
    return "user"


def _free_username(db: Session, wanted: str) -> str:
    base = "".join(ch for ch in wanted.strip() if not ch.isspace())[:72] or "sso-user"
    name, n = base, 2
    while db.execute(select(User.id).where(func.lower(User.username) == name.lower())).first():
        name, n = f"{base}-{n}", n + 1
    return name


def account_for(db: Session, settings: RuntimeSettings, claims: dict[str, Any]) -> tuple[User, list[str]]:
    """The user this sign-in is for - found by the provider's id, linked by e-mail, or created. Returns the
    user and what was done (for the activity log)."""
    sso_id = f"{claims['iss']} {claims['sub']}"[:400]
    email = str(claims.get("email") or "").strip()
    done: list[str] = []
    user = db.execute(select(User).where(User.sso_id == sso_id)).scalar_one_or_none()
    if user is None and email:
        user = db.execute(select(User).where(func.lower(User.email) == email.lower(), User.sso_id.is_(None))).scalars().first()
        if user is not None:
            user.sso_id = sso_id
            done.append("linked to the existing account by e-mail")
    if user is None:
        if not settings.sso_create_users:
            raise SsoError(f"There is no account for {email or 'you'} in ETD Report Scheduler - ask an administrator to create one.", denied=True)
        user = User(username=_free_username(db, email or str(claims.get("preferred_username") or "") or f"sso-{str(claims['sub'])[:12]}"),
                    display_name=str(claims.get("name") or "")[:120], email=email or None, password_hash=UNUSABLE_PASSWORD,
                    role="user", enabled=True, sso_id=sso_id)
        db.add(user)
        db.flush()
        done.append("account created")
    if not user.enabled:
        raise SsoError("Your account in ETD Report Scheduler is disabled - ask an administrator.", denied=True)
    role = role_from_groups(settings, groups_of(claims, settings.sso_groups_claim))
    if role and role != user.role:
        last_admin = user.role == "admin" and db.execute(
            select(func.count()).select_from(User).where(User.role == "admin", User.enabled.is_(True), User.id != user.id)).scalar_one() == 0
        if last_admin:
            log.warning("Single sign-on: %s keeps the admin role - the groups would remove the last enabled administrator", user.username)
        else:
            done.append(f"role {user.role} → {role} from groups")
            user.role = role
    if claims.get("name"):
        user.display_name = str(claims["name"])[:120]
    if email:
        user.email = email
    user.last_login_at = utcnow()
    return user, done
