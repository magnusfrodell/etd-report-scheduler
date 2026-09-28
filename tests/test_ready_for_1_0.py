"""0.16.0: ready for 1.0 - upgrades with data, scale, API key reminders and a year of demo history."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, date, datetime, timedelta

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app import db as app_db
from app.alerts import check_api_keys
from app.db import session_scope
from app.demo import simulator
from app.demo.seed import extend_history
from app.models import AlertState, ApiKey, Base, ConvictedMessage, DailyStat, Tenant, User, utcnow
from app.reports.registry import REPORTS
from app.services import build_context
from app.settings_store import load_settings, save_settings
from app.web import api_keys
from tests.conftest import make_tenant

# ---------------------------------------------------------------------------------------- upgrades

_SAMPLE = {sa.Integer: 1, sa.BigInteger: 1, sa.SmallInteger: 1, sa.Boolean: False, sa.Float: 1.0, sa.Numeric: 1}


def _sample(col: sa.Column) -> object:
    t = col.type
    if isinstance(t, sa.DateTime):
        return datetime(2026, 1, 1, tzinfo=UTC)
    if isinstance(t, sa.Date):
        return date(2026, 1, 1)
    if isinstance(t, sa.JSON):
        return {}
    for kind, value in _SAMPLE.items():
        if isinstance(t, kind):
            return value
    length = getattr(t, "length", None) or 20
    return "x" * min(length, 8)


def _fill_empty_tables(engine: sa.Engine) -> None:
    """One row in every table that has none - parents first, children pointing at them - with a value for
    every column that must have one. This is what an installation that has been running looks like."""
    meta = sa.MetaData()
    meta.reflect(engine)
    with engine.begin() as conn:
        for table in meta.sorted_tables:
            if table.name == "alembic_version" or conn.execute(sa.select(sa.func.count()).select_from(table)).scalar():
                continue
            row = {}
            for col in table.columns:
                if col.primary_key and isinstance(col.type, sa.Integer):
                    continue
                if col.foreign_keys:
                    row[col.name] = 1
                elif not col.nullable and col.server_default is None:
                    row[col.name] = _sample(col)
            conn.execute(table.insert().values(**row))


def test_every_migration_upgrades_and_downgrades_a_database_that_has_data(tmp_path, monkeypatch):
    """A migration that adds a required column without a default passes on an empty test database and breaks
    every real installation. Here each step runs on a database with a row in every table."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    revisions = [r.revision for r in reversed(list(ScriptDirectory.from_config(cfg).walk_revisions()))]
    assert len(revisions) >= 13
    engine = sa.create_engine(url)
    for revision in revisions:
        command.upgrade(cfg, revision)
        _fill_empty_tables(engine)
    meta = sa.MetaData()
    meta.reflect(engine)
    with engine.connect() as conn:
        empty = [t.name for t in meta.sorted_tables if not conn.execute(sa.select(sa.func.count()).select_from(t)).scalar()]
    assert not empty, f"tables that lost their rows: {empty}"
    with Session(engine) as session:  # the models read what the migrations built
        for mapper in Base.registry.mappers:
            session.execute(select(mapper.class_).limit(1)).first()
    command.downgrade(cfg, revisions[0])  # back to the first release: tables from later releases go, the first ones keep their rows
    command.upgrade(cfg, "head")
    with Session(engine) as session:
        assert session.execute(select(sa.func.count()).select_from(Tenant)).scalar() == 1
        assert session.execute(select(sa.func.count()).select_from(DailyStat)).scalar() == 1
    engine.dispose()


# ---------------------------------------------------------------------------------------- scale

def _queries_for(key: str) -> int:
    count = 0

    def counter(*_args: object) -> None:
        nonlocal count
        count += 1

    engine = app_db.get_engine()
    event.listen(engine, "before_cursor_execute", counter)
    try:
        with session_scope() as s:
            definition = REPORTS[key]
            definition.build(s, build_context(s, definition, None, datetime(2026, 9, 15, tzinfo=UTC), "UTC"))
    finally:
        event.remove(engine, "before_cursor_execute", counter)
    return count


@pytest.mark.parametrize("key", ["trends_all", "cross_tenant_rollup"])
def test_reports_across_tenants_do_not_ask_the_database_once_per_tenant(client, key):
    before = _queries_for(key)
    for _ in range(12):
        tid = make_tenant(f"Scale-{uuid.uuid4().hex[:8]}")
        with session_scope() as s:
            s.add(DailyStat(tenant_id=tid, day=date(2026, 8, 3), total_messages=5000, incoming=5000, phishing=3))
    after = _queries_for(key)
    assert after - before <= 1, f"{key}: {before} queries before and {after} after adding 12 tenants"


# ---------------------------------------------------------------------------------------- API key reminders

def test_api_keys_are_announced_a_week_and_a_day_before_they_expire(client, monkeypatch):
    sent: list[tuple[str, list[str]]] = []
    monkeypatch.setattr("app.alerts._send", lambda settings, subject, lines, link="": sent.append((subject, lines)) or True)
    with session_scope() as s:
        before = load_settings(s).base_url
        uid = s.execute(select(User.id).where(User.username == "admin")).scalar_one()
        key, _raw = api_keys.create(s, s.get(User, uid), "Nightly export", "read", "30", created_by="admin")
        s.flush()
        key.expires_at = utcnow() + timedelta(days=5)
        kid = key.id
    try:
        assert check_api_keys() == 1 and "'Nightly export'" in sent[-1][1][0] and "API key(s) expire within a week" in sent[-1][0]
        assert check_api_keys() == 0, "the week's reminder is sent once"
        with session_scope() as s:
            s.get(ApiKey, kid).expires_at = utcnow() + timedelta(hours=20)
        assert check_api_keys() == 1, "and once more on the last day"
        assert check_api_keys() == 0
        with session_scope() as s:
            s.get(ApiKey, kid).revoked_at = utcnow()
        check_api_keys()
        with session_scope() as s:
            assert s.get(AlertState, f"api_key:{kid}") is None, "a revoked key is forgotten"
            s.get(ApiKey, kid).revoked_at = None
            s.get(ApiKey, kid).expires_at = utcnow() + timedelta(days=3)
            assert api_keys.status(s.get(ApiKey, kid)) == "expires soon"
    finally:
        with session_scope() as s:
            s.delete(s.get(ApiKey, kid))
            save_settings(s, {"base_url": before})


# ---------------------------------------------------------------------------------------- demo history

def test_the_demo_gets_a_year_of_history_that_adds_up(client):
    tid = make_tenant(f"Demo-History-{uuid.uuid4().hex[:6]}")
    assert extend_history([tid], days=40) == 40
    assert extend_history([tid], days=40) == 0, "running it again adds nothing"
    with session_scope() as s:
        stats = list(s.execute(select(DailyStat).where(DailyStat.tenant_id == tid).order_by(DailyStat.day)).scalars())
        messages = list(s.execute(select(ConvictedMessage).where(ConvictedMessage.tenant_id == tid)).scalars())
        tenant_key = simulator.simulator.spec_for(s.get(Tenant, tid)).key
    assert len(stats) == 40 and stats[-1].day == datetime.now(UTC).date() - timedelta(days=1)
    per_day = Counter(m.timestamp.date() for m in messages)
    for row in stats:  # the statistics count exactly the messages that were stored for the day
        assert row.malicious + row.phishing + row.bec + row.scam == per_day.get(row.day, 0), (tenant_key, row.day)
    assert messages, "threat messages come with the statistics"
