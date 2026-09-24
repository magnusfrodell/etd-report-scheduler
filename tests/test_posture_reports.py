"""0.5.0: Log Export collector, domain intelligence and the five posture and risk reports."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from app.collectors import runner
from app.collectors.logs import RETENTION_DAYS, collect_logs, parse_lines, path_date_hour, path_hash
from app.db import session_scope
from app.etd.factory import client_for_tenant
from app.models import AuditEvent, ConvictedMessage, LogFile, MessageEvent, SenderDomainDaily, Tenant
from app.reports import domains
from app.reports.base import ReportContext
from app.reports.periods import period_for
from app.reports.registry import get_report
from app.services import render_report
from app.settings_store import save_settings
from tests.conftest import make_tenant

NOW = datetime(2026, 9, 22, 6, 0, tzinfo=UTC)
P = period_for("weekly", NOW, ZoneInfo("UTC"))  # 2026-09-14 .. 2026-09-20


# ---------------------------------------------------------------- Log Export
def test_parse_lines_and_paths():
    objs = [{"a": 1}, {"b": 2}]
    nd = "\n".join(json.dumps(o) for o in objs).encode()
    assert list(parse_lines(nd)) == objs
    assert list(parse_lines(json.dumps(objs).encode())) == objs
    assert list(parse_lines(gzip.compress(nd))) == objs
    assert list(parse_lines(b"")) == []
    assert list(parse_lines(b'{"a": 1}\nnot json\n')) == [{"a": 1}]
    url = "https://x/tenant_id%3Dt/log_date%3D2025-07-16/hour%3D03/log_type%3Dmessage/f.jsonl?X-Amz-Signature=1"
    assert path_date_hour(url) == (date(2025, 7, 16), 3)
    assert path_hash("https://h/p.json?sig=1") == path_hash("https://h/p.json?sig=2")


def _collect(tid: int, now: datetime) -> dict:
    with session_scope() as s:
        t = s.get(Tenant, tid)
        client = client_for_tenant(t)
        try:
            return collect_logs(s, t, client, budget=5000, now=now)
        finally:
            client.close()


def _log_counts(tid: int) -> dict:
    def total(column, *where):
        return s.scalar(select(func.coalesce(func.sum(column), 0)).where(SenderDomainDaily.tenant_id == tid, *where))

    with session_scope() as s:
        count = lambda model: s.scalar(select(func.count()).select_from(model).where(model.tenant_id == tid))  # noqa: E731
        return {
            "files": count(LogFile),
            "audit": count(AuditEvent),
            "events": count(MessageEvent),
            "message_files": s.scalar(select(func.count()).select_from(LogFile).where(LogFile.tenant_id == tid, LogFile.log_type == "message")),
            "supplier": total(SenderDomainDaily.messages, SenderDomainDaily.domain == "supplier.example"),
            "supplier_rp": total(SenderDomainDaily.rp_mismatch, SenderDomainDaily.domain == "supplier.example"),
            "lookalike_rt": total(SenderDomainDaily.reply_to_mismatch, SenderDomainDaily.domain == "supp1ier.example"),
            "spoof_convicted": total(SenderDomainDaily.convicted, SenderDomainDaily.domain == "corp.example", SenderDomainDaily.direction == "incoming"),
            "outgoing": total(SenderDomainDaily.messages, SenderDomainDaily.direction == "outgoing"),
        }


def test_log_export_is_idempotent_and_never_sends_credentials(client, mock_etd):
    tid = make_tenant("Logs-Co")
    now = datetime(2026, 9, 1, 10, 30, tzinfo=UTC)
    first = _collect(tid, now)
    assert first["status"] == "ok", first
    assert mock_etd.downloads, "log files were fetched (the fake S3 rejects requests that carry credentials)"

    hours = RETENTION_DAYS * 24 + 1  # every hour from the horizon to the current hour, inclusive
    c1 = _log_counts(tid)
    assert c1["message_files"] == hours
    assert c1["supplier"] == hours and c1["lookalike_rt"] == hours and c1["spoof_convicted"] == hours and c1["outgoing"] == hours
    assert c1["supplier_rp"] == 0, "bounce@mail.supplier.example is organisationally aligned"
    assert c1["audit"] == 3 * 29  # 09:00 on Aug 4 .. Sep 1
    assert c1["events"] == 2 * 29  # 12:00 on Aug 3 .. Aug 31

    second = _collect(tid, now)
    assert second["files"] == 0 and second["windows"] == 2  # only the 6 h look-back is re-requested
    assert _log_counts(tid) == c1

    with session_scope() as s:
        t = s.get(Tenant, tid)
        assert t.logs_first_hour == datetime(2026, 8, 3, 10, tzinfo=UTC) and t.logs_cursor == datetime(2026, 9, 1, 10, tzinfo=UTC)
        t.logs_cursor = datetime(2026, 7, 1, tzinfo=UTC)  # collector "down" longer than ETD keeps logs
    _collect(tid, now)
    with session_scope() as s:
        gaps = s.get(Tenant, tid).logs_gaps
    assert gaps and gaps[0][0].startswith("2026-07-01")
    assert _log_counts(tid) == c1


def test_log_export_runner_status(client, mock_etd):
    tid = make_tenant("Logs-Runner")
    with session_scope() as s:
        save_settings(s, {"log_export_enabled": False})
    assert runner.collect_logs_for_tenant(tid)["status"] == "disabled"
    with session_scope() as s:
        assert s.get(Tenant, tid).logs_status == "disabled"
        save_settings(s, {"log_export_enabled": True})
    result = runner.collect_logs_for_tenant(tid)
    assert result["status"] == "ok", result
    with session_scope() as s:
        t = s.get(Tenant, tid)
        assert t.logs_status == "ok" and t.logs_collected_at is not None and t.api_calls_count > 0


# ---------------------------------------------------------- domain intelligence
def test_lookalike_detection():
    protected = ["supplier.example", "corp.example", "acme.co.uk"]
    assert domains.find_lookalike("supp1ier.example", protected).method == "homoglyph"
    typo = domains.find_lookalike("suplier.example", protected)
    assert typo.method == "typosquat" and typo.distance == 1
    assert domains.find_lookalike("supplier.com", protected).method == "TLD swap"
    assert domains.find_lookalike("supplier-payments.example", protected).method == "combosquat"
    assert domains.find_lookalike("corp.example.secure-login.net", protected).method == "subdomain spoof"
    assert domains.find_lookalike("acme.com", protected).method == "TLD swap"
    assert domains.find_lookalike("mail.supplier.example", protected) is None
    assert domains.find_lookalike("totally-different.example", protected) is None
    assert domains.registrable("mail.acme.co.uk") == "acme.co.uk"
    assert domains.registrable("contoso.onmicrosoft.com") == "contoso.onmicrosoft.com"


def test_dns_posture_parsing():
    spf = domains.parse_spf(["v=spf1 include:a.example include:b.example ip4:192.0.2.1 -all"])
    assert spf["level"] == "ok" and spf["lookups"] == 2 and spf["all"] == "-all"
    assert domains.parse_spf(["v=spf1 +all"])["level"] == "critical"
    assert domains.parse_spf([])["status"] == "missing"
    assert domains.parse_spf(["v=spf1 -all", "v=spf1 ~all"])["level"] == "critical"
    dmarc = domains.parse_dmarc(["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@example.com"])
    assert dmarc["level"] == "warning" and dmarc["pct"] == 50 and dmarc["rua"]
    assert domains.parse_dmarc(["v=DMARC1; p=reject"])["level"] == "ok"
    own = domains.check_domain("corp.example")  # answered by the FAKE_DNS fixture
    assert own["dmarc"]["policy"] == "none" and own["spf"]["all"] == "-all" and own["grade"] == "D" and not own["mta_sts"]
    sub = domains.check_dmarc("mail.evil.example")
    assert sub["dmarc"]["inherited"] and sub["dmarc"]["policy"] == "reject"


def test_dns_failures_are_reported_not_raised(client, monkeypatch):
    def broken(name):
        raise LookupError("DNS lookup failed (Timeout)")

    monkeypatch.setattr(domains, "resolve_txt", broken)
    res = domains.check_many(["a.example", "b.example", "c.example", "d.example"], kind="dmarc")
    assert all(r["error"] for r in res.values())
    assert res["d.example"]["error"] == "DNS unavailable"


def test_quarterly_periods():
    p = period_for("quarterly", datetime(2026, 9, 23, 8, tzinfo=UTC), ZoneInfo("Europe/Stockholm"))
    assert (p.start_day, p.end_day, p.label) == (date(2026, 4, 1), date(2026, 6, 30), "Q2 2026")
    assert p.previous_start_day == date(2026, 1, 1) and p.previous_label == "Q1 2026"
    q = period_for("quarterly", datetime(2026, 2, 10, 12, tzinfo=UTC), ZoneInfo("UTC"))
    assert (q.start_day, q.label, q.previous_start_day) == (date(2025, 10, 1), "Q4 2025", date(2025, 7, 1))


# ------------------------------------------------------------------ reports
def _msg(tid: int, i: int, **kw) -> ConvictedMessage:
    ts = kw.pop("timestamp", P.start + timedelta(days=i % 6, hours=9 + i))
    base = dict(
        tenant_id=tid, etd_id=f"p050-{tid}-{i}", timestamp=ts, direction="incoming", verdict="phishing",
        from_address=f"sender{i}@evil.example", to_addresses=[f"user{i % 3}@corp.example"], mailboxes=[f"user{i % 3}@corp.example"],
        subject=f"Message {i}", urls=["http://pay-now.example/login"], attachments=[], techniques=[{"technique": "Malicious URL"}],
        action_type="move", action_folder="junkemail", action_timestamp=ts + timedelta(minutes=2), is_auto_remediated=True,
        verdict_timestamp=ts, is_retro_verdict=False,
    )
    base.update(kw)
    return ConvictedMessage(**base)


def _day(offset: int) -> date:
    return P.start_day + timedelta(days=offset)


def _sdd(tid: int, day: date, domain: str, direction: str = "incoming", messages: int = 1, convicted: int = 0, rp: int = 0, rt: int = 0, crt: int = 0) -> SenderDomainDaily:
    return SenderDomainDaily(tenant_id=tid, day=day, domain=domain, direction=direction, messages=messages, convicted=convicted,
                             rp_mismatch=rp, reply_to_mismatch=rt, convicted_reply_to_mismatch=crt)


def _seed(tid: int) -> None:
    with session_scope() as s:
        t = s.get(Tenant, tid)
        t.profile = {"own_domains": ["corp.example"], "vendor_domains": ["supplier.example"], "vip_addresses": ["cfo@corp.example"],
                     "user_labels": {"user-analyst-1": "Anna Analyst"}}
        t.logs_first_hour, t.logs_cursor, t.logs_status = P.start - timedelta(days=20), NOW, "ok"
        t.convictions_collected_at = t.stats_collected_at = NOW  # as the collectors leave it: the period is covered
        for d in range(1, 11):  # clean history before the period
            s.add(_sdd(tid, _day(-d), "supplier.example", messages=20))
            s.add(_sdd(tid, _day(-d), "partner.example", messages=5))
        s.add_all([
            _sdd(tid, _day(1), "supp1ier.example", messages=3, rp=3, rt=3),  # look-alike, delivered (not convicted)
            _sdd(tid, _day(1), "corp.example", messages=4, convicted=4, rp=4, rt=2, crt=2),  # own domain in From:
            _sdd(tid, _day(2), "bank-alerts.example", messages=10, convicted=2, rt=2, crt=2),
            _sdd(tid, _day(2), "corp.example", direction="outgoing", messages=50),
        ])
        s.add_all([
            _msg(tid, 1, verdict="bec", from_address="ap@partner.example", urls=[], subject="Updated bank details",
                 techniques=[{"technique": "Frequent sender for recipient"}, {"technique": "Urgency"}], raw={"replyTo": "ap-payments@gmail.com"}),
            _msg(tid, 2, from_address="ceo@corp.example", urls=["http://qr-login.example/"],
                 techniques=[{"technique": "QR code"}, {"technique": "Sender name impersonation"}],
                 raw={"urlMetadata": [{"url": "http://qr-login.example/", "isQrCode": True}]}),
            _msg(tid, 3, verdict="scam", from_address="invoice@supplier-payments.example", urls=[], attachments=[{"fileName": "invoice.pdf"}],
                 techniques=[{"technique": "Young domain"}, {"technique": "Call to action"}], business_risk="high"),
            _msg(tid, 4, verdict="malicious", from_address="noreply@evil.example", urls=["https://bad.pages.dev/x", "https://bit.ly/abc"],
                 attachments=[{"fileName": "remittance.pdf.html"}, {"fileName": "archive.zip"}],
                 techniques=[{"technique": "Malicious HTML attachment"}, {"technique": "Shortened URL"}], business_risk="high"),
            _msg(tid, 5, verdict="scam", from_address="alerts@bank-alerts.example", urls=[], techniques=[{"technique": "Call to action"}], rule_type="allowlist"),
            _msg(tid, 6, from_address="x@evil.example", is_retro_verdict=True, action_type=None, action_timestamp=None, is_auto_remediated=None),
            _msg(tid, 7, timestamp=P.previous_start + timedelta(days=1)),
        ])
        s.add_all([
            AuditEvent(tenant_id=tid, event_hash="h1", timestamp=P.start + timedelta(days=1), category="tenant", action="create_public_api_client",
                       status="success", user_id="user-admin-1", user_ip="10.0.0.9", user_agent="python-requests/2.32", meta={"clientId": "c1"}),
            AuditEvent(tenant_id=tid, event_hash="h2", timestamp=P.start + timedelta(days=2), category="email", action="reclassify",
                       status="success", user_id="user-analyst-1", user_ip="10.0.0.5", user_agent="Mozilla/5.0", meta={"verdict": "neutral"}),
            AuditEvent(tenant_id=tid, event_hash="h3", timestamp=P.start + timedelta(days=3), category="user", action="login",
                       status="failure", user_id="user-x", user_ip="203.0.113.9", user_agent="Mozilla/5.0"),
            MessageEvent(tenant_id=tid, event_hash="m1", timestamp=P.start + timedelta(days=2), kind="reclassify", method="user",
                         user_id="user-analyst-1", verdict="neutral"),
            MessageEvent(tenant_id=tid, event_hash="m2", timestamp=P.start + timedelta(days=2), kind="remediate", method="manual",
                         user_id="user-analyst-1", action="move", folder="trash"),
        ])


def _build(tid: int, key: str) -> dict:
    with session_scope() as s:
        ctx = ReportContext(period=P, generated_at=NOW, timezone="UTC", tenant=s.get(Tenant, tid))
        return get_report(key).build(s, ctx)


def test_posture_and_risk_reports(client):
    tid = make_tenant("Posture-Co")
    _seed(tid)

    v = _build(tid, "vendor_risk")
    comp = {r["domain"]: r for r in v["compromised"]}
    assert comp["partner.example"]["severity"] == "critical" and comp["partner.example"]["reply_to_elsewhere"] == 1
    assert any("frequent sender" in r for r in comp["partner.example"]["reasons"])
    la = {r["domain"]: r for r in v["lookalikes"]}
    assert la["supp1ier.example"]["method"] == "homoglyph" and la["supp1ier.example"]["delivered"] == 3
    assert la["supp1ier.example"]["severity"] == "critical"
    assert la["supplier-payments.example"]["method"] == "combosquat" and la["supplier-payments.example"]["threats"] == 1
    assert "gmail.com" not in la
    rare = {r["domain"]: r for r in v["rare"]}
    assert set(rare) == {"supplier-payments.example", "bank-alerts.example"}
    assert rare["supplier-payments.example"]["signals"] == ["young domain"]
    assert rare["bank-alerts.example"]["signals"] == ["first seen this period"]
    assert v["inventory"][0] == {**v["inventory"][0], "domain": "supplier.example", "clean_days_before": 10, "lookalikes": 2}

    a = _build(tid, "auth_posture")
    assert a["own_checks"][0]["domain"] == "corp.example" and a["own_checks"][0]["dmarc"]["policy"] == "none"
    assert a["spoofed_count"] == 1 and a["alignment"]["claimed_own"] == 4
    assert {r["policy"]: r["messages"] for r in a["policy_rows"]} == {"reject": 2, "quarantine": 1, "missing": 2}
    assert a["threat_enforcing_pct"] == 60.0
    assert any("p=none" in r for r in a["recommendations"])

    t = _build(tid, "techniques")
    assert t["qr_count"] == 1 and t["callback_count"] == 2 and t["bec_nopayload_count"] == 1
    classes = {r["class"]: r["count"] for r in t["attachment_rows"]}
    assert classes["HTML / SVG"] == 1 and classes["Archive / disk image"] == 1 and classes["PDF"] == 1
    assert t["double_extensions"][0]["name"] == "remittance.pdf.html"
    assert {"Cloudflare", "URL shorteners"} <= {r["service"] for r in t["service_rows"]}
    fams = {r["family"]: r["messages"] for r in t["family_rows"]}
    assert fams["Known relationship"] == 1 and fams["Malicious link"] == 3
    assert [r["risk"] for r in t["risk_rows"]] == ["high"]
    assert any(".html" in r for r in t["recommendations"])

    au = _build(tid, "audit_compliance")
    assert (au["total"], au["failed_count"], au["privileged_count"]) == (3, 1, 1)
    assert {r["group"]: r["events"] for r in au["group_rows"]} == {"API access": 1, "Reclassification": 1, "Sign-in and session": 1}
    assert au["to_neutral"] == 1 and au["per_user"][0]["who"] == "Anna Analyst" and au["per_user"][0]["remediated"] == 1
    assert au["coverage"]["pct"] == 100.0
    assert "Anna Analyst" in {x["label"] for x in au["actors"]} and "user-x" in au["unlabelled_users"]

    pe = _build(tid, "posture_effectiveness")
    checks = {c["name"]: c for c in pe["checks"]}
    assert checks["DMARC enforcement on own domains"]["status"] == "critical"
    assert checks["No threats through allow-lists"]["status"] == "warning"
    assert checks["Threats remediated"]["status"] == "critical"  # 5 of 6
    assert checks["VIPs defined"]["status"] == "ok"
    assert 0 <= pe["score"] <= 100 and pe["recommendations"]
    assert pe["landscape"]["compromised"] == 1 and pe["landscape"]["lookalikes"] == 2 and pe["landscape"]["spoofed"] == 1

    with session_scope() as s:
        ctx = ReportContext(period=P, generated_at=NOW, timezone="UTC", tenant=s.get(Tenant, tid))
        for key in ("vendor_risk", "auth_posture", "techniques", "audit_compliance", "posture_effectiveness"):
            html = render_report(s, get_report(key), ctx)
            assert "Posture-Co" in html and "Traceback" not in html, key
        assert "supp1ier.example" in render_report(s, get_report("vendor_risk"), ctx)
        assert "Anna Analyst" in render_report(s, get_report("audit_compliance"), ctx)


def test_tenant_profile_form(logged_in):
    tid = make_tenant("Profile-Co")
    r = logged_in.post(
        f"/tenants/{tid}/profile",
        data={"own_domains": "corp.example, bad_domain", "vendor_domains": "supplier.example\nbank.example",
              "vip_addresses": "CEO@corp.example, nope", "user_labels": "uuid-1 = Anna Analyst\nbroken line"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    with session_scope() as s:
        profile = s.get(Tenant, tid).profile
    assert profile == {"own_domains": ["corp.example"], "vendor_domains": ["supplier.example", "bank.example"],
                       "vip_addresses": ["ceo@corp.example"], "user_labels": {"uuid-1": "Anna Analyst"}}
    page = logged_in.get("/tenants").text
    assert "Reporting profile" in page and "supplier.example, bank.example" in page and "Log export" in page
