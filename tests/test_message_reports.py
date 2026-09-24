"""Very Attacked People, campaign clusters and exposure - built from seeded convicted messages."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from app.db import session_scope
from app.models import ConvictedMessage, Tenant
from app.reports import analysis
from app.reports.base import ReportContext
from app.reports.periods import period_for
from app.reports.registry import get_report
from app.settings_store import save_settings
from tests.conftest import make_tenant

NOW = datetime(2026, 9, 22, 6, 0, tzinfo=UTC)
P = period_for("weekly", NOW, ZoneInfo("UTC"))  # 2026-09-14 .. 2026-09-20


def _msg(tid: int, i: int, **kw) -> ConvictedMessage:
    ts = kw.pop("timestamp", P.start + timedelta(days=i % 7, hours=i % 24))
    base = dict(
        tenant_id=tid, etd_id=f"seed-{tid}-{i}", timestamp=ts, direction="incoming", verdict="phishing",
        from_address=f"attacker{i % 3}@evil-mail.example", to_addresses=[f"user{i % 5}@corp.example"], mailboxes=[f"user{i % 5}@corp.example"],
        subject=f"Invoice {1000 + i} overdue", urls=[f"http://pay-now-{i % 2}.example/login"], attachments=[],
        techniques=[{"type": "Malicious URL", "severity": "high"}], action_type="move", action_folder="junkemail",
        action_timestamp=ts + timedelta(minutes=2), is_auto_remediated=True, verdict_timestamp=ts, is_retro_verdict=False,
    )
    base.update(kw)
    return ConvictedMessage(**base)


def _seed(tid: int) -> None:
    with session_scope() as s:
        msgs = [_msg(tid, i) for i in range(12)]  # campaign A: "Invoice #### overdue" from evil-mail.example, 2 URL hosts
        # campaign B: shared attachment hash, rotating subjects/senders - links only through the hash
        for i in range(12, 16):
            msgs.append(_msg(tid, i, subject=f"Document {i}", from_address=f"random{i}@other{i}.example", urls=[],
                             attachments=[{"fileName": "inv.pdf", "fileHashSha256": "abc123"}], verdict="malicious"))
        # BEC against the CEO: targeted, impersonation, retro, unremediated
        ceo_ts = P.start + timedelta(days=2, hours=9)
        msgs.append(_msg(tid, 20, subject="Urgent wire transfer", verdict="bec", to_addresses=["ceo@corp.example"], mailboxes=["ceo@corp.example"],
                         from_address="ceo.assistant@gmail.example", urls=[], techniques=[{"type": "Display name impersonation", "severity": "high"}],
                         is_retro_verdict=True, original_verdict="neutral", verdict_timestamp=ceo_ts + timedelta(hours=5),
                         action_type=None, action_folder=None, action_timestamp=None, is_auto_remediated=None, timestamp=ceo_ts))
        # retro phishing remediated after 3 hours
        r_ts = P.start + timedelta(days=4, hours=8)
        msgs.append(_msg(tid, 21, subject="Password expires today", is_retro_verdict=True, original_verdict="neutral",
                         verdict_timestamp=r_ts + timedelta(hours=1), action_timestamp=r_ts + timedelta(hours=3), timestamp=r_ts,
                         to_addresses=["user1@corp.example"], mailboxes=["user1@corp.example"], urls=["http://reset-pw.example/"]))
        # mass mailing (25 recipients) - should count little for the index
        msgs.append(_msg(tid, 22, subject="Newsletter special offer", verdict="scam", to_addresses=[f"m{k}@corp.example" for k in range(25)],
                         mailboxes=[f"m{k}@corp.example" for k in range(25)], urls=["http://offers.example/"]))
        # previous period message for comparison
        msgs.append(_msg(tid, 30, timestamp=P.previous_start + timedelta(days=1), to_addresses=["user1@corp.example"], mailboxes=["user1@corp.example"]))
        s.add_all(msgs)
        save_settings(s, {"vip_addresses": "CEO@corp.example, cfo@corp.example"})


def _ctx(s, tid: int) -> ReportContext:
    return ReportContext(period=P, generated_at=NOW, timezone="UTC", tenant=s.get(Tenant, tid))


def test_analysis_helpers():
    assert analysis.normalize_subject("RE: Fwd: Invoice 1234 overdue!") == "invoice # overdue"
    assert analysis.email_domain("Bob <bob@Example.COM>") == "example.com"
    assert analysis.url_host("https://www.Pay-Now.example/login?x=1") == "pay-now.example"
    assert analysis.url_host({"url": "http://a.b.example/"}) == "a.b.example"
    assert analysis.fmt_hours(0.5) == "30 min" and analysis.fmt_hours(3.25) == "3.2 h" and analysis.fmt_hours(72) == "3.0 d"
    assert analysis.percentile([1, 2, 3, 4], 0.5) == 2.5


def test_campaign_clusters(client):
    tid = make_tenant("Msg-Campaigns")
    _seed(tid)
    with session_scope() as s:
        data = get_report("campaigns").build(s, _ctx(s, tid))
    assert data["campaign_count"] == 2, data
    top = data["rows"][0]
    assert top["messages"] == 12 and top["recipients"] == 5 and top["label"].startswith("Invoice")
    assert "evil-mail.example" in dict(top["sender_domains"])
    hash_campaign = data["rows"][1]
    assert hash_campaign["messages"] == 4 and hash_campaign["verdicts"] == {"malicious": 4}, "linked only through the attachment hash"
    assert data["singletons"] == 3  # BEC, retro phishing, newsletter
    assert data["still_exposed"] == 0 and data["critical"] == []


def test_vap_index(client):
    tid = make_tenant("Msg-VAP")
    _seed(tid)
    with session_scope() as s:
        data = get_report("vap_index").build(s, _ctx(s, tid))
    rows = {r["mailbox"]: r for r in data["rows"]}
    ceo = rows["ceo@corp.example"]
    assert ceo["vip"] and ceo["index"] == int(round((10 + 4 + 4 + 3 + 5) * 1.5)) and ceo["unremediated"] == 1
    assert "not remediated" in ceo["reasons"] and "impersonation" in ceo["reasons"] and "targeted" in ceo["reasons"]
    assert ceo["index"] > max(r["index"] for r in data["rows"] if r["messages"] == 1 and not r["vip"]), "one BEC beats any single ordinary phish"
    assert data["rows"][0]["messages"] >= 3, "volume of targeted high-severity phish ranks first"
    assert rows["user1@corp.example"]["movement"] == "up" or rows["user1@corp.example"]["previous_rank"] == 1
    mass = rows["m0@corp.example"]
    assert mass["index"] < rows["user0@corp.example"]["index"], "mass mailings weigh little"
    assert data["attacked_vips"][0]["mailbox"] == "ceo@corp.example" and data["vip_count"] == 2
    assert data["with_unremediated"] == 1 and data["top10_share"] > 0


def test_exposure(client):
    tid = make_tenant("Msg-Exposure")
    _seed(tid)
    with session_scope() as s:
        data = get_report("exposure").build(s, _ctx(s, tid))
    assert data["retro_count"] == 2 and data["unremediated_count"] == 1 and data["overall"] == "warning"
    assert data["to_action"]["count"] == 1 and data["to_action"]["median"] == "3.0 h"
    assert data["to_verdict"]["count"] == 2 and data["to_verdict"]["max"] == "5.0 h"
    assert dict(data["buckets"])["1–4 h"] == 1
    exposed = data["exposed"][0]
    assert exposed["verdict"] == "bec" and exposed["to"] == ["ceo@corp.example"] and exposed["retro"]
    assert data["retro_rows"][0]["to_action"] == "not remediated"
    assert data["auto_count"] == 18 and data["manual_count"] == 0
