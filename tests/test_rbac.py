"""Users, global roles and per-tenant grants."""

from __future__ import annotations

from sqlalchemy import select

from app.db import session_scope
from app.models import ReportRun, TenantGrant, User
from app.services import run_report
from app.web.auth import hash_password
from tests.conftest import make_tenant


def _user(username: str, role: str = "user", password: str = "Passw0rd!x") -> int:
    with session_scope() as s:
        u = User(username=username, display_name=username.title(), password_hash=hash_password(password), role=role, enabled=True)
        s.add(u)
        s.flush()
        return u.id


def _grant(user_id: int, tenant_id: int, role: str) -> None:
    with session_scope() as s:
        s.add(TenantGrant(user_id=user_id, tenant_id=tenant_id, role=role))


def _login(client, username: str, password: str = "Passw0rd!x") -> None:
    client.cookies.clear()
    r = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers.get("location", ""), f"login failed for {username}"


def _select(client, tenant: int | str) -> None:
    client.post("/select-tenant", data={"tenant": str(tenant), "next": "/"}, follow_redirects=False)


def test_bootstrap_admin_exists(client):
    with session_scope() as s:
        admin = s.execute(select(User).where(User.username == "admin")).scalar_one()
        assert admin.role == "admin" and admin.enabled
    assert client.get("/api/health").status_code == 200


def test_viewer_sees_only_granted_tenant(client, mock_etd):
    a, b = make_tenant("RBAC-A"), make_tenant("RBAC-B")
    viewer = _user("viewer1")
    _grant(viewer, a, "viewer")
    run_a = run_report("health_check", tenant_id=a, deliver=False)
    run_b = run_report("health_check", tenant_id=b, deliver=False)

    _login(client, "viewer1")
    names = [t["name"] for t in client.get("/api/tenants").json()]
    assert names == ["RBAC-A"]
    page = client.get("/tenants").text
    assert "RBAC-A" in page and "RBAC-B" not in page and "Add tenant" not in page
    assert client.get(f"/reports/{run_a}/html").status_code == 200
    r = client.get(f"/reports/{run_b}/html", follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"], "other tenant's report is forbidden"
    assert client.post(f"/api/tenants/{a}/collect").status_code == 403, "viewer cannot collect"
    assert client.post(f"/api/tenants/{b}/collect").status_code == 404, "invisible tenant looks like it does not exist"
    _select(client, a)
    r = client.post("/reports/health_check/run", data={"period_kind": "daily", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "viewer cannot run reports"
    assert client.get("/users", follow_redirects=False).status_code == 303
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/scheduler").status_code == 403
    assert "Cross-tenant" not in str([x["name"] for x in client.get("/api/reports").json()])


def test_operator_can_run_and_schedule_but_not_edit(client, mock_etd):
    a, b = make_tenant("RBAC-C"), make_tenant("RBAC-D")
    op = _user("operator1")
    _grant(op, a, "operator")
    _login(client, "operator1")
    _select(client, a)
    before = _run_count()
    r = client.post("/reports/health_check/run", data={"period_kind": "daily", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "msg=" in r.headers["location"] and _run_count() == before + 1
    r = client.post("/schedules", data={"report_key": "health_check", "tenant_id": str(a), "cron": "", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    r = client.post("/schedules", data={"report_key": "health_check", "tenant_id": str(b), "cron": "", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "no grant on tenant D"
    r = client.post("/schedules", data={"report_key": "cross_tenant_rollup", "tenant_id": "", "cron": "", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "cross-tenant needs tenant_admin"
    r = client.post(f"/tenants/{a}/edit", data={"name": "Renamed", "region": "de", "client_id": "x"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "operator cannot edit"
    r = client.post(f"/tenants/{a}/delete", follow_redirects=False)
    assert "err=" in r.headers["location"], "operator cannot delete"
    assert client.post(f"/api/tenants/{a}/collect").json()["status"] == "started"
    _select(client, "all")
    r = client.post("/reports/health_check/run", data={"period_kind": "daily", "recipients": "", "output_format": "html"}, follow_redirects=False)
    from urllib.parse import unquote

    assert "msg=" in r.headers["location"] and "1 tenant(s)" in unquote(r.headers["location"]), "'all' runs only the tenants the user operates"


def test_manager_edits_and_grants_but_stays_inside_tenant(client, mock_etd):
    a, b = make_tenant("RBAC-E"), make_tenant("RBAC-F")
    mgr, other = _user("manager1"), _user("colleague1")
    _grant(mgr, a, "manager")
    _login(client, "manager1")
    r = client.post(f"/tenants/{a}/edit", data={"name": "RBAC-E2", "region": "beta", "client_id": "newcid", "client_secret": "", "api_key": ""}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert [t["name"] for t in client.get("/api/tenants").json()] == ["RBAC-E2"]
    r = client.post(f"/tenants/{a}/access", data={"user_id": str(other), "role": "viewer"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    r = client.post(f"/tenants/{b}/access", data={"user_id": str(other), "role": "viewer"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "cannot grant on a tenant they do not manage"
    _login(client, "colleague1")
    assert [t["name"] for t in client.get("/api/tenants").json()] == ["RBAC-E2"]
    _login(client, "manager1")
    r = client.post(f"/tenants/{a}/access/{other}/revoke", follow_redirects=False)
    assert "msg=" in r.headers["location"]
    _login(client, "colleague1")
    assert client.get("/api/tenants").json() == []
    _login(client, "manager1")
    r = client.post("/tenants", data={"name": "New", "region": "de", "client_id": "c", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "managers cannot create tenants"


def test_tenant_admin_manages_tenants_but_not_users_or_settings(client, mock_etd):
    make_tenant("RBAC-G")
    _user("tadmin1", role="tenant_admin")
    _login(client, "tadmin1")
    r = client.post("/tenants", data={"name": "TA-Created", "region": "de", "client_id": "c", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert "TA-Created" in [t["name"] for t in client.get("/api/tenants").json()]
    assert client.post("/api/reports/cross_tenant_rollup/run").json()["status"] == "started"
    assert client.get("/api/scheduler").status_code == 200
    r = client.get("/users", follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]
    r = client.get("/settings", follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]
    assert client.get("/api/users").status_code == 403


def test_admin_user_management_and_last_admin_protection(logged_in):
    c = logged_in
    r = c.post("/users", data={"username": "Newbie", "display_name": "New Person", "email": "n@example.com", "role": "user", "password": "Passw0rd!x"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    users = {u["username"]: u for u in c.get("/api/users").json()}
    assert users["newbie"]["role"] == "user"
    r = c.post("/users", data={"username": "short", "role": "user", "password": "123"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    admin_id = users["admin"]["id"]
    r = c.post(f"/users/{admin_id}/role", data={"role": "user"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "own" in r.headers["location"], "an admin cannot demote themself (and thus never the last admin)"
    r = c.post(f"/users/{admin_id}/delete", follow_redirects=False)
    assert "err=" in r.headers["location"]
    nid = users["newbie"]["id"]
    r = c.post(f"/users/{nid}/role", data={"role": "admin"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    r = c.post(f"/users/{admin_id}/role", data={"role": "tenant_admin"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "own" in r.headers["location"], "nobody changes their own role"
    _login(c, "newbie")
    r = c.post(f"/users/{admin_id}/role", data={"role": "tenant_admin"}, follow_redirects=False)
    assert "msg=" in r.headers["location"], "demotion allowed once another admin exists"
    r = c.post(f"/users/{admin_id}/role", data={"role": "admin"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    _login(c, "admin", "test-password")
    r = c.post(f"/users/{nid}/toggle", follow_redirects=False)
    assert "msg=" in r.headers["location"]
    c.cookies.clear()
    _login_ok = c.post("/login", data={"username": "newbie", "password": "Passw0rd!x"}, follow_redirects=False)
    assert "err=" in _login_ok.headers["location"], "disabled users cannot sign in"


def test_password_change_invalidates_old_session(client):
    _user("pwuser")
    _login(client, "pwuser")
    old_cookie = client.cookies.get("etd_session")
    r = client.post("/account/password", data={"current_password": "Passw0rd!x", "new_password": "Brand-new-1", "confirm_password": "Brand-new-1"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert client.get("/", follow_redirects=False).status_code == 200, "the new cookie works"
    client.cookies.clear()
    client.cookies.set("etd_session", old_cookie)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and "/login" in r.headers["location"], "old session is dead"
    client.cookies.clear()


def test_manage_cli_reset_password(client):
    from app import manage

    _user("cliuser")
    manage.reset_password("cliuser", "Reset-me-99")
    _login(client, "cliuser", "Reset-me-99")
    assert manage.main(["list-users"]) == 0
    assert manage.main(["reset-password", "nobody", "Whatever-1"]) == 1


def _run_count() -> int:
    with session_scope() as s:
        return len(s.execute(select(ReportRun.id)).scalars().all())
