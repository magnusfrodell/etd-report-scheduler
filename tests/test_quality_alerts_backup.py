"""0.6: data-quality view, alerts, encryption-key check and backups."""

from __future__ import annotations

import email
import email.policy
import socket
import sqlite3
import tarfile
from datetime import UTC, datetime, timedelta

import pytest
from aiosmtpd.controller import Controller
from cryptography.fernet import Fernet
from sqlalchemy import select

from app import crypto
from app.alerts import check_collection
from app.backup import create_backup
from app.config import get_config
from app.db import session_scope
from app.models import AlertState, ReportRun, ReportSchedule, Tenant, utcnow
from app.quality import encryption_key_problem
from app.services import run_schedule
from app.settings_store import load_settings, save_settings
from tests.conftest import make_tenant
from tests.test_rbac import _grant, _login, _user


class _Inbox:
    def __init__(self) -> None:
        self.subjects: list[str] = []
        self.bodies: list[str] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001 - aiosmtpd signature
        message = email.message_from_bytes(envelope.content, policy=email.policy.default)  # decoded, as a mail client reads it
        body = message.get_body(preferencelist=("html", "plain"))
        self.subjects.append(str(message["Subject"]))
        self.bodies.append(body.get_content() if body else "")
        return "250 OK"


@pytest.fixture
def alert_inbox(client):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    inbox = _Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=port)
    controller.start()
    with session_scope() as s:
        save_settings(s, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "etd@example.com", "smtp_starttls": False,
                          "alert_recipients": "ops@example.com"})
    yield inbox
    controller.stop()
    with session_scope() as s:
        save_settings(s, {"smtp_host": "", "smtp_from": "", "smtp_port": 587, "smtp_starttls": True, "alert_recipients": ""})


# ------------------------------------------------------------------ data quality
def test_data_quality_page_shows_each_stream(logged_in):
    tid = make_tenant("Quality-Co")
    with session_scope() as s:
        t = s.get(Tenant, tid)
        t.stats_collected_at = utcnow() - timedelta(hours=60)
        t.collector_errors = {"convictions": {"error": "ETDError: 401 invalid_client", "at": utcnow().isoformat()}}
    logged_in.post("/select-tenant", data={"tenant": str(tid), "next": "/quality"})
    page = logged_in.get("/quality").text
    assert "Quality-Co" in page and "Stalled" in page and "ETDError: 401 invalid_client" in page and "need attention" in page
    assert f'action="/tenants/{tid}/collect"' in page
    logged_in.post("/select-tenant", data={"tenant": "all", "next": "/quality"})


def test_data_quality_respects_tenant_access(client):
    mine, other = make_tenant("Quality-Mine"), make_tenant("Quality-Other")
    _grant(_user("qualityviewer"), mine, "viewer")
    try:
        _login(client, "qualityviewer")
        page = client.get("/quality").text
        assert "Quality-Mine" in page and "Quality-Other" not in page and "/collect" not in page
    finally:
        _login(client, "admin", "test-password")
    assert other


# ------------------------------------------------------------------ alerts
def test_stalled_collection_is_alerted_once_a_day(alert_inbox):
    tid = make_tenant("Stalled-Co")
    now = utcnow()
    with session_scope() as s:
        s.get(Tenant, tid).stats_collected_at = now - timedelta(hours=80)
    assert check_collection(now) >= 1 and len(alert_inbox.subjects) == 1
    assert "Stalled-Co" in alert_inbox.bodies[0] and "Data collection stalled" in alert_inbox.subjects[0]
    assert check_collection(now + timedelta(hours=1)) == 0 and len(alert_inbox.subjects) == 1, "not again the next hour"
    assert check_collection(now + timedelta(hours=25)) >= 1 and len(alert_inbox.subjects) == 2, "but again the next day"
    with session_scope() as s:
        s.get(Tenant, tid).stats_collected_at = now + timedelta(hours=25)
    check_collection(now + timedelta(hours=26))
    with session_scope() as s:
        assert s.get(AlertState, f"collect:{tid}:stats") is None, "a cleared problem is forgotten, so a relapse alerts at once"


def test_failed_scheduled_report_is_alerted(alert_inbox, monkeypatch):
    tid = make_tenant("Failing-Co")
    with session_scope() as s:
        schedule = ReportSchedule(tenant_id=tid, report_key="health_check", cron="0 7 * * *", recipients="", output_format="html",
                                  enabled=True, created_at=datetime(2026, 1, 1, tzinfo=UTC))
        s.add(schedule)
        s.flush()
        sid = schedule.id

    def boom(*_args, **_kwargs):
        raise RuntimeError("template exploded")

    monkeypatch.setattr("app.services.render_report", boom)
    run_id = run_schedule(sid)
    with session_scope() as s:
        assert s.get(ReportRun, run_id).status == "failed"
    assert len(alert_inbox.subjects) == 1 and "Scheduled report failed" in alert_inbox.subjects[0] and "template exploded" in alert_inbox.bodies[0]
    run_schedule(sid, triggered_by="manual")
    assert len(alert_inbox.subjects) == 1, "a failed manual run is seen by the person who started it - no alert"


# ------------------------------------------------------------------ encryption key
def test_wrong_encryption_key_is_reported_not_fatal(client):
    make_tenant("Key-Co")
    with session_scope() as s:
        save_settings(s, {"smtp_password": "relay-secret"})
    assert encryption_key_problem() is None
    crypto.init_secret_box(Fernet.generate_key().decode())  # the service restarted with a different key
    try:
        assert "ENCRYPTION_KEY does not match" in encryption_key_problem()
        with session_scope() as s:
            assert load_settings(s).smtp_password == "", "settings still load, so the UI can explain the problem"
    finally:
        crypto.init_secret_box(get_config().encryption_key)
        with session_scope() as s:
            save_settings(s, {"smtp_password": ""})
    assert client.get("/api/health").json()["encryption_key"] == "ok"


# ------------------------------------------------------------------ backups
def test_backup_is_a_consistent_snapshot_and_is_pruned(client, tmp_path):
    make_tenant("Backup-Co")
    for day in (1, 2, 3):
        path = create_backup(tmp_path, keep=2, now=datetime(2026, 9, day, 3, 45, tzinfo=UTC))
    assert sorted(p.name for p in tmp_path.glob("*.tar.gz")) == ["etd-backup-20260902-034500.tar.gz", "etd-backup-20260903-034500.tar.gz"]
    with tarfile.open(path) as tar:
        assert set(tar.getnames()) == {"etd.db", "RESTORE.txt"}
        tar.extract("etd.db", tmp_path / "restore", filter="data")
        assert "ENCRYPTION_KEY" in tar.extractfile("RESTORE.txt").read().decode()
    with sqlite3.connect(tmp_path / "restore" / "etd.db") as db:
        assert db.execute("SELECT count(*) FROM tenants WHERE name = 'Backup-Co'").fetchone()[0] == 1
    full = create_backup(tmp_path, with_reports=True)
    with tarfile.open(full) as tar:
        assert any(n == "reports" or n.startswith("reports/") for n in tar.getnames())


def test_backup_command_and_settings_button(logged_in, tmp_path, monkeypatch, capsys):
    from app import manage

    monkeypatch.setattr(manage, "_init", lambda: None)
    assert manage.main(["backup", "--dest", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip().endswith(".tar.gz")
    r = logged_in.post("/settings/backup", follow_redirects=False)
    assert "Backup%20written%20to" in r.headers["location"]
    page = logged_in.get("/settings").text
    assert "Storage and backups" in page and "etd-backup-" in page
    with session_scope() as s:
        assert s.execute(select(Tenant)).first() is not None
