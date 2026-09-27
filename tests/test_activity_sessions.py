"""0.12.0: the activity log (who did what in this tool) and server-side sessions."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import select

from app import activity
from app.config import get_config
from app.db import session_scope
from app.main import app
from app.models import ActivityEvent, User, UserSession, utcnow
from app.services import run_report
from app.settings_store import load_settings, save_settings
from tests.test_rbac import _login, _user


def _events(action: str | None = None, **where) -> list[ActivityEvent]:
    with session_scope() as s:
        query = select(ActivityEvent).order_by(ActivityEvent.id.desc())
        if action:
            query = query.where(ActivityEvent.action == action)
        for key, value in where.items():
            query = query.where(getattr(ActivityEvent, key) == value)
        rows = list(s.execute(query).scalars())
        s.expunge_all()
        return rows


def _browser(username: str, password: str = "Passw0rd!x") -> TestClient:
    other = TestClient(app)
    _login(other, username, password)
    return other


def _signed_in(c: TestClient) -> bool:
    r = c.get("/", follow_redirects=False)
    return r.status_code == 200


def _all_routes(routes):
    for r in routes:
        if hasattr(r, "original_router"):
            yield from _all_routes(r.original_router.routes)
        else:
            yield r


# ---------------------------------------------------------------------------------------- sessions

def test_signing_out_ends_the_session_on_the_server(client):
    _user("sess-out")
    c = _browser("sess-out")
    copied = c.cookies.get("etd_session")
    assert _signed_in(c)
    c.post("/logout", follow_redirects=False)
    thief = TestClient(app)
    thief.cookies.set("etd_session", copied)
    assert not _signed_in(thief), "a copy of the cookie must stop working at sign-out"
    event = _events("auth.sign_out", actor="sess-out")[0]
    assert event.outcome == "ok" and event.target_type == "session"


def test_sessions_end_after_inactivity(client):
    _user("sess-idle")
    c = _browser("sess-idle")
    with session_scope() as s:
        save_settings(s, {"session_idle_minutes": 30})
        uid = s.execute(select(User.id).where(User.username == "sess-idle")).scalar_one()
        session = s.execute(select(UserSession).where(UserSession.user_id == uid)).scalars().first()
        session.last_seen_at = utcnow() - timedelta(minutes=31)
        sid = session.id
    try:
        assert not _signed_in(c)
        with session_scope() as s:
            assert s.get(UserSession, sid).revoked_reason == "inactivity"
    finally:
        with session_scope() as s:
            save_settings(s, {"session_idle_minutes": 120})


def test_cookies_from_before_the_upgrade_sign_in_again(client):
    with session_scope() as s:
        admin = s.execute(select(User).where(User.username == "admin")).scalar_one()
        old = URLSafeTimedSerializer(get_config().secret_key, salt="etd-session-v2").dumps({"uid": admin.id, "ph": admin.password_hash[-16:]})
    c = TestClient(app)
    c.cookies.set("etd_session", old)
    assert not _signed_in(c)


def test_an_administrator_ends_other_peoples_sessions(logged_in):
    _user("sess-victim")
    laptop, phone = _browser("sess-victim"), _browser("sess-victim")
    page = logged_in.get("/users").text
    assert "Active sessions" in page and "sess-victim" in page
    with session_scope() as s:
        uid = s.execute(select(User.id).where(User.username == "sess-victim")).scalar_one()
        first = s.execute(select(UserSession.id).where(UserSession.user_id == uid).order_by(UserSession.id)).scalars().first()
    logged_in.post(f"/sessions/{first}/end", follow_redirects=False)
    assert not _signed_in(laptop) and _signed_in(phone)
    logged_in.post(f"/users/{uid}/sessions/end", follow_redirects=False)
    assert not _signed_in(phone)
    assert _events("session.end_user", target="sess-victim")[0].details == {"sessions_ended": 1}


def test_people_see_and_end_their_own_sessions(client):
    _user("sess-self")
    here, there = _browser("sess-self"), _browser("sess-self")
    page = here.get("/account").text
    assert "Your sessions" in page and "this browser" in page
    assert "1 other session(s) ended" in here.post("/account/sessions/end-others", follow_redirects=True).text
    assert _signed_in(here) and not _signed_in(there)


def test_disabling_a_user_ends_their_sessions(logged_in):
    _user("sess-disabled")
    c = _browser("sess-disabled")
    with session_scope() as s:
        uid = s.execute(select(User.id).where(User.username == "sess-disabled")).scalar_one()
    logged_in.post(f"/users/{uid}/toggle", follow_redirects=False)
    assert not _signed_in(c)
    with session_scope() as s:
        reasons = {r.revoked_reason for r in s.execute(select(UserSession).where(UserSession.user_id == uid)).scalars()}
    assert reasons == {"account disabled"}
    assert _events("user.toggle", target="sess-disabled")[0].details["enabled"] == [True, False]


# ---------------------------------------------------------------------------------------- the activity log

def test_every_route_that_changes_something_has_an_activity_name():
    missing = []
    for route in _all_routes(app.routes):
        methods = getattr(route, "methods", None) or set()
        if methods & activity.MUTATING and route.endpoint.__name__ not in activity.ACTIONS:
            missing.append(f"{sorted(methods)} {route.path} ({route.endpoint.__name__})")
    assert not missing, "add these handlers to app.activity.ACTIONS: " + "; ".join(missing)


def test_sign_ins_are_recorded_without_passwords(client):
    _user("act-login")
    c = TestClient(app)
    c.post("/login", data={"username": "act-login", "password": "Wrong-secret-42"}, follow_redirects=False)
    _login(c, "act-login")
    failed, ok = _events("auth.sign_in", actor="act-login")[1], _events("auth.sign_in", actor="act-login")[0]
    assert failed.outcome == "failed" and failed.actor_id is None and failed.details == {"message": "Wrong username or password."}
    assert ok.outcome == "ok" and ok.actor_id is not None
    assert "Wrong-secret-42" not in json.dumps([e.details for e in _events()], default=str)


def test_changes_are_recorded_with_names_even_after_a_delete(logged_in):
    name = f"Act-Co-{uuid.uuid4().hex[:6]}"
    logged_in.post("/tenants", data={"name": name, "region": "de", "client_id": "c", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    created = _events("tenant.create", target=name)[0]
    assert created.actor == "admin" and created.outcome == "ok" and created.tenant_id is not None
    logged_in.post(f"/tenants/{created.tenant_id}/delete", follow_redirects=False)
    deleted = _events("tenant.delete", target_id=str(created.tenant_id))[0]
    assert deleted.target == name and deleted.outcome == "ok"
    logged_in.post("/tenants", data={"name": " ", "region": "de", "client_id": "c", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    refused = _events("tenant.create")[0]
    assert refused.outcome == "failed" and refused.details["message"] == "Name is required."


def test_refusals_are_recorded_as_denied(client):
    _user("act-denied")
    c = _browser("act-denied")
    c.post("/chat/channels", data={"kind": "teams", "name": "x", "webhook_url": "https://x"}, follow_redirects=False)
    event = _events("chat.channel.create", actor="act-denied")[0]
    assert event.outcome == "denied" and "administrators" in event.details["message"]


def test_settings_changes_name_the_settings_and_hide_secrets(logged_in):
    logged_in.post("/settings", data={"timezone": "Europe/Stockholm", "smtp_port": "587", "retention_days": "365", "smtp_password": "Top-secret-77",
                                      "session_idle_minutes": "90"}, follow_redirects=False)
    changed = _events("settings.update")[0].details["settings"]
    assert changed["smtp_password"] == "changed" and changed["session_idle_minutes"] == [120, 90]
    assert "Top-secret-77" not in json.dumps(changed)
    with session_scope() as s:
        save_settings(s, {"session_idle_minutes": 120})


def test_opening_a_report_is_recorded_and_view_preferences_are_not(logged_in, tenant_id):
    run_id = run_report("health_check", tenant_id=tenant_id, output_format="html")
    before = len(_events())
    logged_in.post("/select-tenant", data={"tenant": "all", "next": "/"}, follow_redirects=False)
    assert len(_events()) == before, "choosing the tenant shown in the header is not an activity"
    assert logged_in.get(f"/reports/{run_id}/html").status_code == 200
    view = _events("report.view")[0]
    assert view.target_id == str(run_id) and view.tenant_id == tenant_id and view.actor == "admin"


def test_the_activity_log_page_exports_and_api(logged_in, client):
    page = logged_in.get("/activity?action=tenant.").text
    assert "Activity log" in page and "tenant." in page and "auth.sign_in" not in page.split("<h2>Events")[1]
    rows = list(csv.DictReader(io.StringIO(logged_in.get("/activity/export?format=csv&action=auth.").text)))
    assert rows and rows[0].keys() >= {"at", "actor", "action", "outcome", "details"} and all(r["action"].startswith("auth.") for r in rows)
    first = logged_in.get("/api/activity?limit=2").json()
    second = logged_in.get(f"/api/activity?limit=2&before_id={first['next_before_id']}").json()
    assert len(first["events"]) == 2 and second["events"][0]["id"] < first["events"][-1]["id"]
    assert _events("activity.export")[0].actor == "admin"
    _user("act-viewer")
    viewer = _browser("act-viewer")
    assert viewer.get("/activity", follow_redirects=False).status_code in (303, 403)
    assert viewer.get("/api/activity").status_code == 403


def test_old_activity_and_sessions_are_purged(client):
    from app.collectors.runner import purge_old_data

    with session_scope() as s:
        s.add(ActivityEvent(at=utcnow() - timedelta(days=400), actor="old", action="tenant.update"))
        uid = s.execute(select(User.id).where(User.username == "admin")).scalar_one()
        s.add(UserSession(user_id=uid, token_hash=uuid.uuid4().hex * 2, created_at=utcnow() - timedelta(days=60),
                          last_seen_at=utcnow() - timedelta(days=60), expires_at=utcnow() - timedelta(days=59)))
        assert load_settings(s).activity_retention_days == 365
    deleted = purge_old_data()
    assert deleted["activity_events"] >= 1 and deleted["user_sessions"] >= 1
    assert not _events(actor="old")
