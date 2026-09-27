"""0.14.0: single sign-on with OpenID Connect, against a stand-in for Duo Single Sign-On."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import sso
from app.db import session_scope
from app.main import app
from app.models import ActivityEvent, User, UserSession
from app.settings_store import load_settings, save_settings
from tests.test_rbac import _user

ISSUER = "https://sso-test1234.sso.duosecurity.com/oidc/DITESTCLIENT0000001"
CLIENT_ID, CLIENT_SECRET = "DITESTCLIENT0000001", "duo-client-secret"
CALLBACK = "https://etd.example/auth/sso/callback"


def _rsa() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeDuo:
    """Discovery, JWKS, token (with PKCE) and UserInfo, answered the way Duo's documentation shows them."""

    def __init__(self) -> None:
        self.key, self.kid = _rsa(), "duo-key-1"
        self.signing_key, self.signing_kid = self.key, self.kid
        self.challenge = self.nonce = None
        self.claims: dict[str, Any] = {}
        self.overrides: dict[str, Any] = {}
        self.userinfo: dict[str, Any] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks", "userinfo_endpoint": f"{ISSUER}/userinfo", "response_types_supported": ["code"],
                "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]})
        if path.endswith("/jwks"):
            public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            return httpx.Response(200, json={"keys": [{**public, "kid": self.kid, "alg": "RS256", "use": "sig"}]})
        if path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            verifier_ok = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode() == self.challenge
            if form.get("client_secret") != CLIENT_SECRET or form.get("code") != "code-1" or not verifier_ok or form.get("redirect_uri") != CALLBACK:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "The code or its verifier is not valid"})
            now = int(time.time())
            body = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": self.nonce, "amr": ["pwd", "mfa"],
                    **self.claims, **self.overrides}
            id_token = jwt.encode(body, self.signing_key, algorithm="RS256", headers={"kid": self.signing_kid})
            return httpx.Response(200, json={"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600, "id_token": id_token})
        if path.endswith("/userinfo"):
            return httpx.Response(200, json={"sub": self.claims.get("sub"), **self.userinfo})
        return httpx.Response(404)


@pytest.fixture
def duo(client, monkeypatch):
    fake = FakeDuo()
    monkeypatch.setattr(sso, "transport_factory", lambda: httpx.MockTransport(fake.handler))
    sso._providers.clear()
    sso._keys.clear()
    keys = ("sso_enabled", "sso_issuer", "sso_client_id", "sso_scopes", "sso_admin_groups", "sso_tenant_admin_groups", "sso_create_users",
            "sso_password_login", "base_url")
    with session_scope() as s:
        before = load_settings(s)
        save_settings(s, {"sso_enabled": True, "sso_issuer": ISSUER, "sso_client_id": CLIENT_ID, "sso_client_secret": CLIENT_SECRET,
                          "sso_scopes": "openid email profile groups", "sso_admin_groups": "", "sso_tenant_admin_groups": "",
                          "sso_create_users": True, "sso_password_login": "all", "base_url": "https://etd.example"})
    yield fake
    with session_scope() as s:
        save_settings(s, {k: getattr(before, k) for k in keys})


def _sign_in(fake: FakeDuo, browser: TestClient | None = None, **claims: Any) -> tuple[TestClient, httpx.Response]:
    c = browser or TestClient(app)
    start = c.get("/auth/sso/start?next=/archive", follow_redirects=False)
    assert start.status_code == 303, start.text
    url = start.headers["location"]
    assert url.startswith(f"{ISSUER}/authorize?")
    query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    assert query["code_challenge_method"] == "S256" and query["redirect_uri"] == CALLBACK and query["scope"] == "openid email profile groups"
    fake.challenge, fake.nonce = query["code_challenge"], query["nonce"]
    fake.claims = {"sub": f"duo-{uuid.uuid4().hex[:10]}", **claims}
    return c, c.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)


def _signed_in(c: TestClient) -> bool:
    return c.get("/", follow_redirects=False).status_code == 200


def _last_sign_in() -> ActivityEvent:
    with session_scope() as s:
        row = s.execute(select(ActivityEvent).where(ActivityEvent.action == "auth.sign_in").order_by(ActivityEvent.id.desc())).scalars().first()
        s.expunge(row)
        return row


def _user_by_email(email: str) -> User:
    with session_scope() as s:
        row = s.execute(select(User).where(User.email == email)).scalar_one()
        s.expunge(row)
        return row


# ---------------------------------------------------------------------------------------- signing in

def test_a_first_sign_in_creates_the_account_and_a_session(duo):
    c, r = _sign_in(duo, email="anna@corp.example", name="Anna Andersson")
    assert r.status_code == 303 and r.headers["location"] == "/archive"
    assert _signed_in(c)
    user = _user_by_email("anna@corp.example")
    assert user.username == "anna@corp.example" and user.role == "user" and user.password_hash == sso.UNUSABLE_PASSWORD
    assert user.sso_id == f"{ISSUER} {duo.claims['sub']}" and user.display_name == "Anna Andersson"
    with session_scope() as s:
        assert s.execute(select(UserSession.auth_method).where(UserSession.user_id == user.id)).scalar_one() == "sso"
    event = _last_sign_in()
    assert event.actor == "anna@corp.example" and event.outcome == "ok"
    assert event.details["method"] == "sso" and event.details["account"] == "account created" and event.details["amr"] == ["pwd", "mfa"]
    assert "SSO" in c.get("/account").text


def test_the_same_person_gets_the_same_account_and_cannot_use_a_password(duo):
    c, _ = _sign_in(duo, email="per@corp.example")
    subject = duo.claims["sub"]
    again = TestClient(app)
    start = again.get("/auth/sso/start", follow_redirects=False)
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    duo.challenge, duo.nonce, duo.claims = query["code_challenge"], query["nonce"], {"sub": subject, "email": "per.new@corp.example"}
    again.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)
    with session_scope() as s:
        accounts = s.execute(select(User).where(User.sso_id == f"{ISSUER} {subject}")).scalars().all()
        assert len(accounts) == 1 and accounts[0].email == "per.new@corp.example"
    r = TestClient(app).post("/login", data={"username": "per@corp.example", "password": "!sso"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_groups_set_the_role_at_every_sign_in(duo):
    with session_scope() as s:
        save_settings(s, {"sso_admin_groups": "ETD-Admins", "sso_tenant_admin_groups": "ETD-Tenant-Admins"})
    _, _ = _sign_in(duo, email="grp@corp.example", groups=["Staff", "etd-admins"])
    subject = duo.claims["sub"]
    assert _user_by_email("grp@corp.example").role == "admin", "group names match without regard to case"
    c = TestClient(app)
    start = c.get("/auth/sso/start", follow_redirects=False)
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    duo.challenge, duo.nonce, duo.claims = query["code_challenge"], query["nonce"], {"sub": subject, "email": "grp@corp.example", "groups": ["Staff"]}
    c.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)
    assert _user_by_email("grp@corp.example").role == "user"
    assert "role admin → user from groups" in _last_sign_in().details["account"]


def test_an_existing_account_is_linked_by_email(duo):
    uid = _user("bo-local")
    with session_scope() as s:
        s.get(User, uid).email = "bo@corp.example"
    c, r = _sign_in(duo, email="BO@corp.example")
    assert _signed_in(c)
    with session_scope() as s:
        user = s.get(User, uid)
        assert user.sso_id == f"{ISSUER} {duo.claims['sub']}" and user.username == "bo-local"
    assert _last_sign_in().details["account"] == "linked to the existing account by e-mail"


def test_without_automatic_accounts_unknown_people_are_turned_away(duo):
    with session_scope() as s:
        save_settings(s, {"sso_create_users": False})
    c, r = _sign_in(duo, email="stranger@corp.example")
    assert r.status_code == 303 and "no account for stranger@corp.example" in unquote(r.headers["location"])
    assert not _signed_in(c)
    assert _last_sign_in().outcome == "denied"
    with session_scope() as s:
        assert s.execute(select(User).where(User.email == "stranger@corp.example")).first() is None


def test_a_disabled_account_stays_out(duo):
    _sign_in(duo, email="gone@corp.example")
    subject = duo.claims["sub"]
    with session_scope() as s:
        s.execute(select(User).where(User.email == "gone@corp.example")).scalar_one().enabled = False
    c = TestClient(app)
    start = c.get("/auth/sso/start", follow_redirects=False)
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    duo.challenge, duo.nonce, duo.claims = query["code_challenge"], query["nonce"], {"sub": subject, "email": "gone@corp.example"}
    r = c.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)
    assert "disabled" in unquote(r.headers["location"]) and not _signed_in(c)


# ---------------------------------------------------------------------------------------- what must be refused

@pytest.mark.parametrize("change,message", [
    ({"overrides": {"nonce": "someone-elses"}}, "does not belong to this sign-in"),
    ({"overrides": {"aud": "another-app"}}, "for another application"),
    ({"overrides": {"iss": "https://evil.example/oidc"}}, "from another issuer"),
    ({"overrides": {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}}, "has expired"),
    ({"signing_key": "other"}, "not valid"),
    ({"signing_kid": "unknown-key"}, "does not publish"),
])
def test_tokens_that_are_not_for_this_sign_in_are_refused(duo, change, message):
    if "overrides" in change:
        duo.overrides = change["overrides"]
    if change.get("signing_key") == "other":
        duo.signing_key = _rsa()
    if "signing_kid" in change:
        duo.signing_kid = change["signing_kid"]
    c, r = _sign_in(duo, email=f"t-{uuid.uuid4().hex[:6]}@corp.example")
    assert r.status_code == 303 and r.headers["location"].startswith("/login?err=") and message in unquote(r.headers["location"])
    assert not _signed_in(c)
    event = _last_sign_in()
    assert event.outcome == "failed" and message in event.details["message"]


def test_the_sign_in_must_finish_in_the_browser_that_started_it(duo):
    starter = TestClient(app)
    start = starter.get("/auth/sso/start", follow_redirects=False)
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    duo.challenge, duo.nonce, duo.claims = query["code_challenge"], query["nonce"], {"sub": "x", "email": "x@corp.example"}
    other = TestClient(app)
    r = other.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)
    assert "not started in this browser" in unquote(r.headers["location"]) and not _signed_in(other)
    r = starter.get("/auth/sso/callback?code=code-1&state=forged", follow_redirects=False)
    assert "could not be matched" in unquote(r.headers["location"]) and not _signed_in(starter)


def test_pkce_is_checked_by_the_provider(duo):
    c = TestClient(app)
    start = c.get("/auth/sso/start", follow_redirects=False)
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    duo.challenge, duo.nonce, duo.claims = "not-the-challenge-we-sent", query["nonce"], {"sub": "y", "email": "y@corp.example"}
    r = c.get(f"/auth/sso/callback?code=code-1&state={query['state']}", follow_redirects=False)
    assert "refused to finish the sign-in (400)" in unquote(r.headers["location"]) and not _signed_in(c)


def test_a_refusal_at_duo_is_shown_and_logged(duo):
    c = TestClient(app)
    c.get("/auth/sso/start", follow_redirects=False)
    r = c.get("/auth/sso/callback?error=access_denied&error_description=User+is+not+allowed", follow_redirects=False)
    assert "Duo did not sign you in: User is not allowed" in unquote(r.headers["location"])
    assert _last_sign_in().outcome == "denied"


# ---------------------------------------------------------------------------------------- passwords and the admin page

def test_passwords_can_be_kept_for_the_emergency_administrator_only(duo):
    _user("pw-person")
    with session_scope() as s:
        save_settings(s, {"sso_password_login": "break_glass"})
    page = TestClient(app).get("/login").text
    assert "Sign in with Duo" in page and "Emergency administrator sign-in" in page
    refused = TestClient(app).post("/login", data={"username": "pw-person", "password": "Passw0rd!x"}, follow_redirects=False)
    assert "Sign in with Duo" in unquote(refused.headers["location"])
    admin = TestClient(app)
    ok = admin.post("/login", data={"username": "admin", "password": "test-password"}, follow_redirects=False)
    assert ok.status_code == 303 and "err=" not in ok.headers["location"] and _signed_in(admin)


def test_the_single_sign_on_page(logged_in, duo):
    page = logged_in.get("/sso").text
    assert CALLBACK in page and "Generic OIDC Relying Party" in page
    r = logged_in.post("/sso", data={"enabled": "on", "name": "Duo", "issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "new-secret",
                                     "scopes": "email profile", "groups_claim": "groups", "create_users": "on", "password_login": "all"},
                       follow_redirects=False)
    assert "Found " + ISSUER in unquote(r.headers["location"])
    with session_scope() as s:
        settings = load_settings(s)
        assert settings.sso_client_secret == "new-secret" and settings.sso_scopes == "openid email profile"
    assert "1 signing key" in unquote(logged_in.post("/sso/check", follow_redirects=False).headers["location"])
    with session_scope() as s:
        save_settings(s, {"sso_client_secret": CLIENT_SECRET})
