"""0.5.1: report cards and the archive browser."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.db import session_scope
from app.models import ReportRun
from app.web.presenters import ago, period_label
from tests.conftest import make_tenant
from tests.test_rbac import _grant, _login, _user

STHLM = ZoneInfo("Europe/Stockholm")


def _local(y: int, m: int, d: int) -> datetime:
    return datetime(y, m, d, tzinfo=STHLM).astimezone(UTC)


def test_period_labels():
    assert period_label(_local(2026, 9, 22), _local(2026, 9, 23), STHLM) == "Tue 22 Sep 2026"
    assert period_label(_local(2026, 9, 14), _local(2026, 9, 21), STHLM) == "Week 38 · 14 Sep – 20 Sep 2026"
    assert period_label(_local(2026, 10, 19), _local(2026, 10, 26), STHLM).startswith("Week 43 ·")  # DST ends 25 Oct
    assert period_label(_local(2026, 8, 1), _local(2026, 9, 1), STHLM) == "August 2026"
    assert period_label(_local(2026, 4, 1), _local(2026, 7, 1), STHLM) == "Q2 2026"
    assert period_label(_local(2026, 9, 3), _local(2026, 9, 10), STHLM) == "3 Sep 2026 – 9 Sep 2026"
    assert period_label(None, None, STHLM) == "–"


def test_relative_times():
    now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
    assert ago(now - timedelta(seconds=20), now) == "just now"
    assert ago(now - timedelta(minutes=5), now) == "5 min ago"
    assert ago(now - timedelta(hours=3), now) == "3 h ago"
    assert ago(now - timedelta(hours=30), now) == "yesterday"
    assert ago(now - timedelta(days=4), now) == "4 days ago"
    assert ago(now - timedelta(days=70), now) == "2 months ago"


def _run(tenant_id: int | None, key: str, days_ago: int, status: str = "ok", *, error: str | None = None, delivered: str | None = None) -> int:
    now = datetime.now(UTC)
    start = (now - timedelta(days=days_ago + 7)).replace(hour=0, minute=0, second=0, microsecond=0)
    with session_scope() as s:
        run = ReportRun(
            tenant_id=tenant_id, report_key=key, period_start=start, period_end=start + timedelta(days=7),
            started_at=now - timedelta(days=days_ago), finished_at=now - timedelta(days=days_ago) + timedelta(seconds=12),
            status=status, html_path=f"/tmp/{key}-{days_ago}.html" if status == "ok" else None,
            pdf_path=f"/tmp/{key}-{days_ago}.pdf" if status == "ok" else None, delivered_to=delivered, error=error,
        )
        s.add(run)
        s.flush()
        return run.id


def _selected_id(page: str) -> int | None:
    m = re.search(r'class="run-item selected"[^>]*?data-id="(\d+)"', page, re.S)
    return int(m.group(1)) if m else None


def test_report_cards(logged_in):
    make_tenant("Cards-Co")  # per-tenant reports can only be run when there is a tenant to run them for
    logged_in.post("/select-tenant", data={"tenant": "all", "next": "/reports"}, follow_redirects=False)
    page = logged_in.get("/reports").text
    assert page.count('<article class="report-card') == 12
    for label in ("Overview", "Threats", "Exposure and risk", "Operations and compliance"):
        assert f"<h2>{label}</h2>" in page
    assert 'href="/archive?report=vendor_risk"' in page and 'form="run-vendor_risk"' in page
    assert page.index("Executive summary") < page.index("Posture and effectiveness") < page.index("Techniques and business risk")


def test_archive_filters_preview_and_run_now(logged_in):
    c = logged_in
    a, b = make_tenant("Archive-A"), make_tenant("Archive-B")
    a1 = _run(a, "vendor_risk", 1, delivered="soc@example.com")
    a2 = _run(a, "vendor_risk", 8)
    a3 = _run(a, "vendor_risk", 40, "failed", error="Boom: DNS unavailable")
    b1 = _run(b, "vendor_risk", 2)
    x1 = _run(None, "cross_tenant_rollup", 3)

    page = c.get(f"/archive?report=vendor_risk&tenant={a}").text
    assert page.count('class="run-item') == 3 and f'data-id="{b1}"' not in page
    assert _selected_id(page) == a1 and f'src="/reports/{a1}/html"' in page and f'href="/reports/{a1}/pdf"' in page
    assert "sent to soc@example.com" in page and 'class="run-group"' in page
    assert "Vendor risk" in page and f'name="tenant_id" value="{a}"' in page  # hero with Run now for this tenant

    page = c.get(f"/archive?report=vendor_risk&tenant={a}&run={a2}").text
    assert _selected_id(page) == a2

    page = c.get(f"/archive?report=vendor_risk&tenant={a}&status=failed").text
    assert page.count('class="run-item') == 1 and "Boom: DNS unavailable" in page
    assert f'src="/reports/{a3}/html"' not in page

    page = c.get("/archive?report=vendor_risk&tenant=all").text
    assert f'data-id="{a1}"' in page and f'data-id="{b1}"' in page and f'data-id="{x1}"' not in page

    page = c.get(f"/archive?report=cross_tenant_rollup&tenant={a}").text  # cross-tenant runs ignore the tenant filter
    assert f'data-id="{x1}"' in page and "Runs across all tenants" in page

    page = c.get(f"/archive?report=audit_compliance&tenant={a}").text
    assert "No Audit and compliance reports for Archive-A yet" in page and "Run Audit and compliance now" in page

    target = f"/archive?report=health_check&tenant={a}"
    r = c.post("/reports/health_check/run", data={"tenant_id": str(a), "next": target, "output_format": "html"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(target + "&msg=")
    with session_scope() as s:
        latest = s.execute(select(ReportRun).where(ReportRun.report_key == "health_check").order_by(ReportRun.id.desc())).scalars().first()
        assert latest.tenant_id == a and latest.status == "ok"
    page = c.get(target).text
    assert _selected_id(page) == latest.id and f'src="/reports/{latest.id}/html"' in page

    assert c.get("/archive?report=nope&tenant=999999&status=weird&run=abc&page=x").status_code == 200


def test_archive_respects_tenant_access(client):
    a, b = make_tenant("Arch-RBAC-A"), make_tenant("Arch-RBAC-B")
    ra = _run(a, "exposure", 1)
    rb = _run(b, "exposure", 1)
    rx = _run(None, "cross_tenant_rollup", 1)
    uid = _user("archviewer")
    _grant(uid, a, "viewer")
    try:
        _login(client, "archviewer")
        page = client.get(f"/archive?run={rb}").text
        assert f'data-id="{ra}"' in page and f'data-id="{rb}"' not in page and f'data-id="{rx}"' not in page
        assert f"/reports/{rb}/html" not in page and "Arch-RBAC-B" not in page
        page = client.get(f"/archive?tenant={b}").text
        assert f'data-id="{rb}"' not in page
        cards = client.get("/reports").text
        assert "Cross-tenant roll-up" not in cards and 'form="run-' not in cards and "Archive" in cards
        r = client.post("/reports/exposure/run", data={"tenant_id": str(a), "output_format": "html"}, follow_redirects=False)
        assert "err=" in r.headers["location"], "a viewer cannot run reports from the archive either"
    finally:
        _login(client, "admin", "test-password")
