"""0.5.2: browser hardening, redirect targets, sign-in throttling and SMTP certificate verification."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import ssl
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from starlette.datastructures import Headers

from app.delivery.email import send_email
from app.settings_store import RuntimeSettings
from app.web.security import LoginLimiter, origin_allowed, safe_next
from tests.conftest import make_tenant
from tests.test_rbac import _login, _user

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"


# ------------------------------------------------------------------ F01 + CSP
def test_templates_have_no_inline_script():
    offenders = [
        str(f.relative_to(TEMPLATES))
        for f in TEMPLATES.rglob("*.html")
        if re.search(r"\son[a-z]+\s*=", f.read_text(encoding="utf-8")) or re.search(r"<script(?![^>]*\bsrc=)", f.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"inline event handlers or scripts would be blocked by the CSP: {offenders}"


def test_tenant_name_stays_inert(logged_in):
    make_tenant("x'+(globalThis.pwned=1)+'\"><script>alert(1)</script>")
    page = logged_in.get("/tenants").text
    assert "onsubmit" not in page and "<script>alert(1)</script>" not in page
    assert 'data-confirm="Delete tenant x&#39;+(globalThis.pwned=1)+&#39;&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt; and all stored data?"' in page


def test_security_headers(logged_in, tenant_id):
    from app.services import run_report

    r = logged_in.get("/reports")
    csp = r.headers["content-security-policy"]
    script_src = csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "'self'" in script_src and "unsafe-inline" not in script_src and "frame-ancestors 'self'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert "cdn.jsdelivr.net" in logged_in.get("/api/docs").headers["content-security-policy"]
    static = logged_in.get("/static/app.js")
    assert static.status_code == 200 and "content-security-policy" not in static.headers
    run_id = run_report("health_check", tenant_id=tenant_id, deliver=False, output_format="html")
    report = logged_in.get(f"/reports/{run_id}/html")
    assert report.status_code == 200 and report.headers["content-security-policy"].startswith("sandbox;")


# ------------------------------------------------------------------ F13
def test_cross_origin_posts_are_refused(logged_in):
    c, data = logged_in, {"tenant": "all", "next": "/"}

    def post(headers: dict[str, str] | None = None) -> int:
        return c.post("/select-tenant", data=data, headers=headers or {}, follow_redirects=False).status_code

    assert post({"Sec-Fetch-Site": "same-site"}) == 403, "another port on the same host is the same site"
    assert post({"Sec-Fetch-Site": "cross-site"}) == 403
    assert post({"Origin": "http://testserver:8081"}) == 403
    assert post({"Origin": "null"}) == 403
    assert post({"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}) == 303
    assert post({"Origin": "http://testserver"}) == 303
    assert post() == 303, "scripts and curl send neither header"
    assert c.get("/reports", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


def test_trusted_origins_for_proxies():
    trusted = frozenset({"https://reports.example.com"})

    def headers(**kw: str) -> Headers:
        return Headers(headers={k.replace("_", "-"): v for k, v in kw.items()})

    assert origin_allowed(headers(origin="https://reports.example.com", host="127.0.0.1:8080"), trusted)
    assert not origin_allowed(headers(origin="https://evil.example", host="127.0.0.1:8080"), trusted)
    assert origin_allowed(headers(sec_fetch_site="same-origin", host="127.0.0.1:8080"))


# ------------------------------------------------------------------ redirects
@pytest.mark.parametrize("target", ["//evil.example", "/\\evil.example", "/\t/evil.example", "https://evil.example", "javascript:alert(1)"])
def test_redirect_targets_stay_local(logged_in, target):
    r = logged_in.post("/select-tenant", data={"tenant": "all", "next": target}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_safe_next():
    assert safe_next("/archive?report=x&tenant=2", "/reports", ("/reports", "/archive")) == "/archive?report=x&tenant=2"
    assert safe_next("/tenants", "/reports", ("/reports", "/archive")) == "/reports"
    assert safe_next("/reports/5/html") == "/reports/5/html"


# ------------------------------------------------------------------ sign-in throttling
def test_login_limiter_window():
    now = [1000.0]
    limiter = LoginLimiter(window_seconds=60, per_account=2, per_client=3, clock=lambda: now[0])
    limiter.failed("anna", "10.0.0.1")
    limiter.failed("anna", "10.0.0.1")
    assert limiter.retry_after("ANNA", "10.0.0.1") > 0
    assert limiter.retry_after("anna", "10.0.0.2") == 0, "another client is not locked out"
    limiter.failed("bert", "10.0.0.1")
    assert limiter.retry_after("carl", "10.0.0.1") > 0, "per-client limit"
    now[0] += 61
    assert limiter.retry_after("anna", "10.0.0.1") == 0


def test_sign_in_throttling(client):
    _user("throttled")
    try:
        for _ in range(5):
            r = client.post("/login", data={"username": "throttled", "password": "wrong-password"}, follow_redirects=False)
            assert "Wrong%20username" in r.headers["location"]
        r = client.post("/login", data={"username": "throttled", "password": "Passw0rd!x"}, follow_redirects=False)
        assert "Too%20many" in r.headers["location"], "the right password is refused too while throttled"
        r = client.post("/login", data={"username": "someone-else", "password": "x"}, follow_redirects=False)
        assert "Too%20many" not in r.headers["location"]
    finally:
        _login(client, "admin", "test-password")


# ------------------------------------------------------------------ F02
def _certificates(tmp_path: Path) -> tuple[str, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test relay CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert = (
        x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay.test")])).issuer_name(ca_name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "relay.pem", tmp_path / "relay.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert_path, key_path


class _Inbox:
    def __init__(self) -> None:
        self.messages: list[object] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001 - aiosmtpd handler signature
        self.messages.append(envelope)
        return "250 OK"


@pytest.fixture
def tls_relay(tmp_path):
    ca_pem, cert, key = _certificates(tmp_path)
    server_tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_tls.load_cert_chain(cert, key)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    inbox = _Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=port, tls_context=server_tls, require_starttls=True)
    controller.start()
    yield port, inbox, ca_pem
    controller.stop()


def _smtp(port: int, **overrides: object) -> RuntimeSettings:
    return RuntimeSettings(**{"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "etd@example.com", "smtp_starttls": True, **overrides})


def test_smtp_starttls_verifies_the_relay(tls_relay):
    port, inbox, ca_pem = tls_relay
    with pytest.raises(ssl.SSLCertVerificationError):
        send_email(_smtp(port), ["soc@example.com"], "Report", "<p>x</p>")
    assert inbox.messages == [], "nothing is sent to a relay that cannot prove who it is"
    send_email(_smtp(port, smtp_ca_pem=ca_pem), ["soc@example.com"], "Report", "<p>x</p>")
    send_email(_smtp(port, smtp_tls_verify=False), ["soc@example.com"], "Report", "<p>x</p>")
    assert len(inbox.messages) == 2


def test_settings_reject_invalid_ca(logged_in):
    r = logged_in.post("/settings", data={"timezone": "Europe/Stockholm", "smtp_ca_pem": "not a certificate"}, follow_redirects=False)
    assert "err=" in r.headers["location"] and "PEM" in r.headers["location"]
