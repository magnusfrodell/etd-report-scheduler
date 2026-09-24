"""0.6: operations and data quality - gap filling, atomic API usage, per-collector errors,
archive retention with files, and tenant erasure."""

from __future__ import annotations

import os
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from app.collectors.runner import collect_stats_for_tenant, purge_old_data, record_api_usage
from app.config import get_config
from app.db import session_scope
from app.models import ReportRun, Tenant, utcnow
from app.services import run_report
from tests.conftest import make_tenant


class _Client:
    def __init__(self, used: int) -> None:
        self.request_count = used


def test_stats_gap_after_an_outage_is_filled(tenant_id, mock_etd):
    assert collect_stats_for_tenant(tenant_id)["days"] == 90
    with session_scope() as s:
        s.get(Tenant, tenant_id).stats_collected_at = utcnow() - timedelta(days=10)  # the service was down for ten days
    assert collect_stats_for_tenant(tenant_id)["days"] == 11, "from the day of the last success through today"
    assert collect_stats_for_tenant(tenant_id)["days"] == 4, "then back to the trailing window"


def test_api_usage_from_overlapping_collectors_adds_up(tenant_id):
    with session_scope() as s:
        s.get(Tenant, tenant_id).api_calls_count, s.get(Tenant, tenant_id).api_calls_day = 100, utcnow().date()
    with session_scope() as first:
        slow = first.get(Tenant, tenant_id)  # loaded before the other collector finishes
        with session_scope() as second:
            record_api_usage(second.get(Tenant, tenant_id), _Client(7))
        record_api_usage(slow, _Client(5))
    with session_scope() as s:
        assert s.get(Tenant, tenant_id).api_calls_count == 112, "neither collector's usage is lost"


def test_collector_errors_are_kept_per_stream(tenant_id, mock_etd):
    with session_scope() as s:
        t = s.get(Tenant, tenant_id)
        t.collector_errors = {"logs": {"error": "ETDError: 503", "at": utcnow().isoformat()}}
        t.last_error = "ETDError: 503"
    collect_stats_for_tenant(tenant_id)
    with session_scope() as s:
        t = s.get(Tenant, tenant_id)
        assert set(t.collector_errors) == {"logs"} and t.last_error == "ETDError: 503", "a healthy collector no longer hides another one's error"


def _archived_run(tid: int, days_old: int, reports: Path) -> tuple[int, list[Path]]:
    with session_scope() as s:
        run = ReportRun(tenant_id=tid, report_key="health_check", status="ok", triggered_by="manual", started_at=utcnow() - timedelta(days=days_old))
        s.add(run)
        s.flush()
        folder = reports / "retention-co" / "health_check"
        folder.mkdir(parents=True, exist_ok=True)
        files = [folder / f"20240101-070000-run{run.id}.html", folder / f"20240101-070000-run{run.id}.pdf"]
        for f in files:
            f.write_text("x")
        run.html_path, run.pdf_path = str(files[0]), str(files[1])
        return run.id, files


def test_retention_removes_archived_files_and_orphans_only(client):
    reports = get_config().reports_dir
    tid = make_tenant("Retention-Co")
    old_id, old_files = _archived_run(tid, 500, reports)
    new_id, new_files = _archived_run(tid, 5, reports)
    stray = reports / "retention-co" / "health_check"
    old_orphan, fresh_orphan, unrelated = stray / "20230101-070000-run999999.pdf", stray / "20230101-070000-run999998.pdf", stray / "notes.txt"
    for f in (old_orphan, fresh_orphan, unrelated):
        f.write_text("x")
    two_days_ago = time.time() - 2 * 86400
    os.utime(old_orphan, (two_days_ago, two_days_ago))
    result = purge_old_data()
    assert result["report_runs"] >= 1 and result["report_files"] >= 2 and result["orphan_report_files"] >= 1
    assert not any(f.exists() for f in old_files) and all(f.exists() for f in new_files)
    assert not old_orphan.exists(), "a file no run refers to is swept"
    assert fresh_orphan.exists(), "a file younger than a day might belong to a run being written"
    assert unrelated.exists(), "only files named like archived runs are touched"
    with session_scope() as s:
        assert s.get(ReportRun, old_id) is None and s.get(ReportRun, new_id) is not None


def test_deleting_a_tenant_removes_its_report_files(logged_in):
    gone, kept = make_tenant("Erase-Co"), make_tenant("Keep-Co")
    gone_run, kept_run = run_report("health_check", tenant_id=gone, output_format="html"), run_report("health_check", tenant_id=kept, output_format="html")
    with session_scope() as s:
        gone_file, kept_file = Path(s.get(ReportRun, gone_run).html_path), Path(s.get(ReportRun, kept_run).html_path)
    assert gone_file.exists() and kept_file.exists()
    r = logged_in.post(f"/tenants/{gone}/delete", follow_redirects=False)
    assert "including%201%20archived%20report%20file" in r.headers["location"]
    assert not gone_file.exists() and not gone_file.parent.exists(), "files and the emptied folder are gone"
    assert kept_file.exists()
    with session_scope() as s:
        assert s.execute(select(ReportRun).where(ReportRun.tenant_id == gone)).first() is None
