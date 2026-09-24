"""0.8.0: partner brands on reports, e-mails, the login page and per tenant."""

from __future__ import annotations

import email
import email.policy
import socket
import struct
import zlib
from pathlib import Path
from urllib.parse import unquote

import pytest
from aiosmtpd.controller import Controller
from sqlalchemy import delete, select

from app.branding import brand_for, view
from app.db import session_scope
from app.delivery.pdf import pdf_available
from app.models import Brand, ReportRun, Tenant
from app.services import build_context, get_report, render_report, run_report
from app.settings_store import load_settings, save_settings
from tests.conftest import make_tenant
from tests.test_posture_reports import NOW
from tests.test_rbac import _grant, _login, _user


def _png(width: int = 4, height: int = 2, rgb: tuple[int, int, int] = (15, 42, 67)) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    rows = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


@pytest.fixture(autouse=True)
def no_brands_left(client):
    """Brands change every report; leave the neutral look for the rest of the suite."""
    yield
    with session_scope() as s:
        s.execute(delete(Brand))


FORM = {"name": "Nordic Partner SOC", "primary_color": "#123456", "accent_color": "#ff6600", "footer_text": "Nordic Partner AB\nsoc@partner.example",
        "subject_prefix": "[Partner SOC]", "sender_name": "Partner SOC", "reply_to": "soc@partner.example", "show_tool_credit": "on"}


def _create(c, logo: bytes | None = None, **overrides: str):
    files = {"logo": ("logo.png", logo if logo is not None else _png(), "image/png")}
    return c.post("/branding", data={**FORM, **overrides}, files=files, follow_redirects=False)


def test_brand_validation_and_default(logged_in):
    assert "Colours" in unquote(_create(logged_in, primary_color="red").headers["location"])
    assert "PNG or JPEG" in unquote(_create(logged_in, logo=b"<svg onload=alert(1)>").headers["location"])
    assert "300 KB" in unquote(_create(logged_in, logo=_png() + b"\0" * 300_001).headers["location"])
    assert "Reply-To" in unquote(_create(logged_in, reply_to="a@b.example, c@d.example").headers["location"])
    r = _create(logged_in)
    assert "as the default" in unquote(r.headers["location"]), "the first brand applies straight away"
    _create(logged_in, name="Second Brand", is_default="on")
    with session_scope() as s:
        defaults = [b.name for b in s.execute(select(Brand).where(Brand.is_default.is_(True))).scalars()]
    assert defaults == ["Second Brand"], "only one default"
    page = logged_in.get("/branding").text
    assert "Nordic Partner SOC" in page and "Second Brand" in page and "data:image/png;base64," in page


def _render(tid: int | None, key: str = "executive_summary") -> str:
    with session_scope() as s:
        tenant = s.get(Tenant, tid) if tid else None
        definition = get_report(key)
        ctx = build_context(s, definition, tenant, NOW, load_settings(s).timezone)
        return render_report(s, definition, ctx, brand=brand_for(s, tenant))


def test_reports_carry_the_tenants_brand_or_the_default(client):
    with session_scope() as s:
        default = Brand(name="Default & Co", primary_color="#222222", accent_color="#00aa55", is_default=True, show_tool_credit=True)
        own = Brand(name="<script>alert(1)</script> Reseller", primary_color="#123456", accent_color="#ff6600", footer_text="Reseller AB",
                    logo_type="image/png", logo_b64=__import__("base64").b64encode(_png()).decode(), show_tool_credit=False)
        s.add_all([default, own])
        s.flush()
        own_id = own.id
    branded, plain = make_tenant("Branded-Co"), make_tenant("Default-Branded-Co")
    with session_scope() as s:
        s.get(Tenant, branded).profile = {"brand_id": own_id}
    html = _render(branded)
    assert "&lt;script&gt;alert(1)&lt;/script&gt; Reseller" in html and "<script>alert(1)" not in html
    assert "data:image/png;base64," in html and "#123456" in html and "#ff6600" in html and "Reseller AB" in html
    assert "ETD Report Scheduler v" not in html, "the credit can be switched off"
    html = _render(plain)
    assert "Default &amp; Co" in html and "#222222" in html and "ETD Report Scheduler v" in html
    assert "Default &amp; Co" in _render(None, "cross_tenant_rollup"), "the partner roll-up uses the default brand"
    with session_scope() as s:
        s.execute(delete(Brand))
    html = _render(plain)
    assert "#0f2a43" in html and "Default &amp; Co" not in html, "without brands, the neutral look"


class _Relay:
    def __init__(self) -> None:
        self.messages: list[email.message.EmailMessage] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001 - aiosmtpd signature
        self.messages.append(email.message_from_bytes(envelope.content, policy=email.policy.default))
        return "250 OK"


def test_emailed_report_embeds_the_logo_and_sender_details(client):
    with session_scope() as s:
        s.add(Brand(name="Mail Brand", logo_type="image/png", logo_b64=__import__("base64").b64encode(_png()).decode(), subject_prefix="[Partner SOC]",
                    sender_name="Partner SOC", reply_to="soc@partner.example", is_default=True))
    tid = make_tenant("Mail-Brand-Co")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    relay = _Relay()
    controller = Controller(relay, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        with session_scope() as s:
            save_settings(s, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "ETD <etd@example.com>", "smtp_starttls": False})
        run_id = run_report("health_check", tenant_id=tid, recipients=["ciso@corp.example"], output_format="html")
    finally:
        controller.stop()
        with session_scope() as s:
            save_settings(s, {"smtp_host": "", "smtp_from": "", "smtp_port": 587, "smtp_starttls": True})
    message = relay.messages[0]
    assert message["From"] == "Partner SOC <etd@example.com>" and message["Reply-To"] == "soc@partner.example"
    assert message["Subject"].startswith("[Partner SOC] ")
    html = message.get_body(preferencelist=("html",)).get_content()
    assert 'src="cid:brand-logo"' in html and "data:image/png" not in html, "mail clients block data: images"
    logo = next(part for part in message.walk() if part["Content-ID"] == "<brand-logo>")
    assert logo.get_content_type() == "image/png" and logo.get_content() == _png()
    with session_scope() as s:
        archived = Path(s.get(ReportRun, run_id).html_path).read_text()
    assert "data:image/png;base64," in archived, "the archive keeps the self-contained copy"


def test_tenant_brand_choice_preview_and_deletion(logged_in):
    _create(logged_in)
    with session_scope() as s:
        brand_id = s.execute(select(Brand.id)).scalar_one()
    tid = make_tenant("Brand-Choice-Co")
    logged_in.post(f"/tenants/{tid}/profile", data={"brand_id": str(brand_id)})
    with session_scope() as s:
        assert s.get(Tenant, tid).profile["brand_id"] == brand_id
    assert f'<option value="{brand_id}" selected>' in logged_in.get("/tenants").text
    preview = logged_in.get(f"/branding/{brand_id}/preview")
    assert preview.status_code == 200 and "Nordic Partner SOC" in preview.text
    if pdf_available():
        pdf = logged_in.get(f"/branding/{brand_id}/preview?format=pdf")
        assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")
    login = logged_in.get("/login").text
    assert "login-logo" in login and "Nordic Partner SOC" in login
    r = logged_in.post(f"/branding/{brand_id}/delete", follow_redirects=False)
    assert "default brand" in unquote(r.headers["location"])
    with session_scope() as s:
        assert brand_for(s, s.get(Tenant, tid)) == view(None), "falls back to the neutral look"


def test_branding_is_for_administrators_only(client):
    tid = make_tenant("Brand-Guard-Co")
    _grant(_user("brandmanager"), tid, "manager")
    try:
        _login(client, "brandmanager")
        r = client.get("/branding", follow_redirects=False)
        assert r.status_code == 403 or "err=" in r.headers.get("location", "")
        r = client.post("/branding", data=FORM, follow_redirects=False)
        assert r.status_code == 403 or "err=" in r.headers.get("location", "")
        assert 'href="/branding"' not in client.get("/reports").text
    finally:
        _login(client, "admin", "test-password")
    with session_scope() as s:
        assert s.execute(select(Brand)).first() is None
