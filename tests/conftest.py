"""Test configuration: isolated data dir, scheduler off, fake ETD transport."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime

import pytest

_TMP = tempfile.mkdtemp(prefix="etd-test-")
os.environ.update({
    "SECRET_KEY": "test-secret-key-please-change-0123456789",
    "ENCRYPTION_KEY": "b3d0z2KcW1iJ4G6M9v7c0H1t5Yq8L2n4P6r8T0v2X4Y=",
    "ADMIN_PASSWORD": "test-password",
    "DATA_DIR": _TMP,
    "SCHEDULER_ENABLED": "false",
    "LOG_LEVEL": "WARNING",
})

from fastapi.testclient import TestClient  # noqa: E402

from app.crypto import secret_box  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.etd import factory  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Tenant  # noqa: E402
from tests.etd_mock import MockETD  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def logged_in(client):
    r = client.post("/login", data={"username": "admin", "password": "test-password"}, follow_redirects=False)
    assert r.status_code == 303
    yield client
    client.cookies.clear()


@pytest.fixture
def mock_etd(monkeypatch):
    from app.etd import client as etd_client

    fake = MockETD()
    monkeypatch.setattr(factory, "transport_factory", lambda tenant: fake.transport)
    # No real sleeping in tests: replace the per-tenant limiter registry with unlimited limiters.
    monkeypatch.setattr(etd_client, "limiter_for", lambda key, per_second=2.0: etd_client.RateLimiter(0))
    return fake


def make_tenant(name: str, region: str = "de") -> int:
    with session_scope() as s:
        box = secret_box()
        t = Tenant(name=name, region=region, client_id=f"cid-{name}", client_secret_enc=box.encrypt("secret") or "", api_key_enc=box.encrypt("apikey") or "")
        s.add(t)
        s.flush()
        return t.id


@pytest.fixture
def tenant_id(client) -> int:
    return make_tenant(f"Tenant-{datetime.now(UTC).timestamp()}")
