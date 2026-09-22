def test_login_required(client):
    client.cookies.clear()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert client.get("/api/tenants").status_code == 401


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["scheduler_running"] is False


def test_bad_password(client):
    r = client.post("/login", data={"username": "admin", "password": "nope"}, follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]


def test_tenant_and_schedule_flow(logged_in, mock_etd):
    c = logged_in
    r = c.post("/tenants", data={"name": "Web Tenant", "region": "de", "client_id": "cid", "client_secret": "S3cretValueXYZ", "api_key": "ApiKeyValueXYZ"}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"] and "verified" in r.headers["location"]
    assert "90 days" in c.get("/tenants").text, "initial collection (stats, convictions, backfill) ran in the background"
    page = c.get("/tenants").text
    assert "Web Tenant" in page and "S3cretValueXYZ" not in page and "ApiKeyValueXYZ" not in page
    tid = next(t["id"] for t in c.get("/api/tenants").json() if t["name"] == "Web Tenant")

    r = c.post(f"/tenants/{tid}/test", follow_redirects=False)
    assert "succeeded" in r.headers["location"]

    r = c.post("/schedules", data={"report_key": "executive_summary", "tenant_id": str(tid), "cron": "", "recipients": "a@example.com", "output_format": "html"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    r = c.post("/schedules", data={"report_key": "executive_summary", "tenant_id": "", "cron": "", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "per-tenant report without tenant is rejected"
    r = c.post("/schedules", data={"report_key": "cross_tenant_rollup", "tenant_id": "", "cron": "bad cron", "recipients": "", "output_format": "pdf"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "invalid cron rejected"
    r = c.post("/schedules", data={"report_key": "cross_tenant_rollup", "tenant_id": "", "cron": "0 7 * * 1", "recipients": "", "output_format": "pdf"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert "All tenants" in c.get("/schedules").text

    r = c.post("/select-tenant", data={"tenant": str(tid), "next": "/"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Web Tenant" in c.get("/").text

    r = c.post("/settings", data={"timezone": "Europe/Stockholm", "smtp_port": "587", "retention_days": "365", "convictions_verdicts": ["bec", "scam"]}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    assert "Europe/Stockholm" in c.get("/settings").text
    r = c.post("/settings", data={"timezone": "Mars/Olympus", "smtp_port": "587", "retention_days": "365"}, follow_redirects=False)
    assert "err=" in r.headers["location"]

    assert {x["key"] for x in c.get("/api/reports").json()} >= {"executive_summary", "cross_tenant_rollup"}
    assert c.post(f"/api/reports/executive_summary/run?tenant_id={tid}").json()["status"] == "started"
    assert c.post("/api/reports/executive_summary/run").status_code == 400


def test_run_now_per_report(logged_in, mock_etd):
    from sqlalchemy import select

    from app.db import session_scope
    from app.models import ReportRun, Tenant

    c = logged_in
    c.post("/tenants", data={"name": "RunNow A", "region": "de", "client_id": "a", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    c.post("/tenants", data={"name": "RunNow B", "region": "beta", "client_id": "b", "client_secret": "s", "api_key": "k"}, follow_redirects=False)
    c.post("/select-tenant", data={"tenant": "all", "next": "/reports"}, follow_redirects=False)

    with session_scope() as s:
        enabled = len(s.execute(select(Tenant.id).where(Tenant.enabled.is_(True))).scalars().all())
        before = len(s.execute(select(ReportRun.id)).scalars().all())

    r = c.post("/reports/health_check/run", data={"period_kind": "daily", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    with session_scope() as s:
        runs = s.execute(select(ReportRun).where(ReportRun.report_key == "health_check").order_by(ReportRun.id.desc()).limit(enabled)).scalars().all()
        assert len(runs) == enabled and all(run.status == "ok" for run in runs), "one run per enabled tenant with All tenants selected"
        assert len(s.execute(select(ReportRun.id)).scalars().all()) == before + enabled

    tid = next(t["id"] for t in c.get("/api/tenants").json() if t["name"] == "RunNow B")
    c.post("/select-tenant", data={"tenant": str(tid), "next": "/reports"}, follow_redirects=False)
    c.post("/reports/executive_summary/run", data={"period_kind": "monthly", "recipients": "", "output_format": "html"}, follow_redirects=False)
    with session_scope() as s:
        run = s.execute(select(ReportRun).where(ReportRun.report_key == "executive_summary").order_by(ReportRun.id.desc())).scalars().first()
        assert run.tenant_id == tid and run.status == "ok"

    r = c.post("/reports/cross_tenant_rollup/run", data={"period_kind": "weekly", "recipients": "", "output_format": "html"}, follow_redirects=False)
    assert "msg=" in r.headers["location"]
    r = c.post("/reports/cross_tenant_rollup/run", data={"period_kind": "weekly", "recipients": "soc@example.com", "output_format": "pdf"}, follow_redirects=False)
    assert "err=" in r.headers["location"], "recipients without SMTP configured is rejected up front"
    assert c.post("/reports/nope/run", data={}, follow_redirects=False).headers["location"].count("err=") == 1
    page = c.get("/reports").text
    assert page.count("Run now") >= 4
