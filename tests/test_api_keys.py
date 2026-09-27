"""0.13.0: API keys for scripts and integrations."""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import session_scope
from app.main import app
from app.models import ActivityEvent, ApiKey, TenantGrant, User, utcnow
from tests.conftest import make_tenant
from tests.test_rbac import _login, _user

KEY = re.compile(r"etd_[0-9a-f]{10}_[A-Za-z0-9_-]{40,}")


def _new_key(c: TestClient, name: str, scope: str = "read", expires: str = "90") -> str:
    page = c.post("/account/api-keys", data={"name": name, "scope": scope, "expires": expires}).text
    found = set(KEY.findall(page))
    assert len(found) == 1, "the new key is shown once, in the answer"
    return found.pop()


def _api(key: str) -> TestClient:
    c = TestClient(app)  # no session cookie - only the key
    c.headers["Authorization"] = f"Bearer {key}"
    return c


def _key_row(name: str) -> ApiKey:
    with session_scope() as s:
        row = s.execute(select(ApiKey).where(ApiKey.name == name)).scalar_one()
        s.expunge(row)
        return row


def _last(action: str) -> ActivityEvent:
    with session_scope() as s:
        row = s.execute(select(ActivityEvent).where(ActivityEvent.action == action).order_by(ActivityEvent.id.desc())).scalars().first()
        s.expunge(row)
        return row


def test_a_key_is_shown_once_and_only_its_hash_is_stored(logged_in):
    key = _new_key(logged_in, "Inventory script")
    row = _key_row("Inventory script")
    assert row.secret_hash == hashlib.sha256(key.encode()).hexdigest() and key.split("_")[1] == row.key_id
    page = logged_in.get("/account").text
    assert key not in page and f"etd_{row.key_id}" in page, "afterwards the key is listed by its public id only"
    created = _last("api_key.create")
    assert created.target == "Inventory script" and key not in str(created.details)


def test_a_read_key_reads_but_cannot_start_anything(logged_in, tenant_id):
    key = _new_key(logged_in, "Reader")
    api = _api(key)
    me = api.get("/api/me")
    assert me.status_code == 200 and me.json()["username"] == "admin"
    refused = api.post(f"/api/reports/health_check/run?tenant_id={tenant_id}")
    assert refused.status_code == 403 and "can only read" in refused.json()["detail"]
    event = _last("report.run")
    assert event.outcome == "denied" and event.details["api_key"].startswith("Reader (etd_")
    assert _key_row("Reader").last_used_at is not None


def test_a_run_key_starts_a_report_as_its_user(logged_in, tenant_id):
    key = _new_key(logged_in, "Runner", scope="run")
    assert _api(key).post(f"/api/reports/health_check/run?tenant_id={tenant_id}").status_code == 200
    event = _last("report.run")
    assert event.outcome == "ok" and event.actor == "admin" and event.details["api_key"].startswith("Runner (etd_")


def test_keys_never_open_the_web_interface(logged_in):
    key = _new_key(logged_in, "API only")
    r = _api(key).get("/reports", follow_redirects=False)
    assert r.status_code == 401 and "/api only" in r.json()["detail"]
    assert _last("auth.api_key").outcome == "denied"


def test_wrong_expired_and_revoked_keys_are_refused_and_logged(logged_in):
    key = _new_key(logged_in, "Short-lived")
    row = _key_row("Short-lived")
    forged = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
    assert _api(forged).get("/api/me").status_code == 401
    refusal = _last("auth.api_key")
    assert refusal.actor == f"etd_{row.key_id}" and refusal.details["message"] == "Not signed in: unknown API key."
    with session_scope() as s:
        s.get(ApiKey, row.id).expires_at = utcnow() - timedelta(minutes=1)
    assert "expired" in _api(key).get("/api/me").json()["detail"]
    with session_scope() as s:
        s.get(ApiKey, row.id).expires_at = None
    assert _api(key).get("/api/me").status_code == 200
    logged_in.post(f"/account/api-keys/{row.id}/revoke", follow_redirects=False)
    revoked = _api(key).get("/api/me")
    assert revoked.status_code == 401 and "revoked" in revoked.json()["detail"]
    assert _api("not-a-key").get("/api/me").status_code == 401


def test_a_service_account_key_has_exactly_the_service_accounts_access(logged_in):
    a = make_tenant("Key-Co-A")
    make_tenant("Key-Co-B")  # exists, but the service account has no access to it
    uid = _user("svc-xdr")
    with session_scope() as s:
        s.add(TenantGrant(user_id=uid, tenant_id=a, role="viewer"))
    page = logged_in.post("/api-keys", data={"user_id": str(uid), "name": "XDR workflow", "scope": "run", "expires": "365"}).text
    key = set(KEY.findall(page)).pop()
    api = _api(key)
    assert {t["id"] for t in api.get("/api/tenants").json()} == {a}
    assert api.post(f"/api/reports/health_check/run?tenant_id={a}").status_code == 403, "run scope, but only a viewer on the tenant"
    created = _last("api_key.create")
    assert created.actor == "admin" and created.details["for_user"] == "svc-xdr" and created.details["scope"] == "run"
    with session_scope() as s:
        s.get(User, uid).enabled = False
    assert _api(key).get("/api/me").status_code == 401, "a disabled user's keys stop working"


def test_administrators_see_and_revoke_every_key_and_others_cannot(logged_in):
    _user("key-owner")
    _user("key-neighbour")
    owner = TestClient(app)
    _login(owner, "key-owner")
    key = _new_key(owner, "Owner script")
    row = _key_row("Owner script")
    neighbour = TestClient(app)
    _login(neighbour, "key-neighbour")
    r = neighbour.post(f"/account/api-keys/{row.id}/revoke", follow_redirects=False)
    assert r.status_code == 403 or "err=" in r.headers.get("location", "")
    assert _api(key).get("/api/me").status_code == 200, "someone else's revoke did nothing"
    page = logged_in.get("/users").text
    assert "Owner script" in page and "key-owner" in page
    logged_in.post(f"/api-keys/{row.id}/revoke", follow_redirects=False)
    assert _api(key).get("/api/me").status_code == 401
    assert _key_row("Owner script").revoked_by == "admin"


def test_the_api_documentation_offers_bearer_keys():
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert {"HTTPBearer": []} in schema["paths"]["/api/me"]["get"]["security"]
