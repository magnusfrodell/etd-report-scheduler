"""0.11.0: reports and alerts posted to the SOC's Webex space or Microsoft Teams channel."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from urllib.parse import unquote

import httpx
import pytest
from sqlalchemy import select

from app.alerts import _send
from app.crypto import secret_box
from app.db import session_scope
from app.delivery import chat
from app.delivery.summary import summarize
from app.models import ChatChannel, ReportRun, ReportSchedule, Tenant
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS
from app.services import build_context, render_report, run_report, run_schedule
from app.settings_store import load_settings, save_settings
from tests.conftest import make_tenant
from tests.test_posture_reports import NOW, _seed
from tests.test_rbac import _login, _user

TEAMS_URL = "https://prod-01.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=secret"
ROOM = "Y2lzY29zcGFyazovL3VzL1JPT00vc29j"


@pytest.fixture
def calls(monkeypatch):
    """Every chat HTTP call, answered like Webex and Teams do. A URL or message containing FAILME gets a 500."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = request.content.decode("utf-8", "replace")
        if "FAILME" in str(request.url) or "FAILME" in body:
            return httpx.Response(500, text="boom")
        if request.url.host == "webexapis.com":
            if request.url.path.endswith("/people/me"):
                return httpx.Response(200, json={"displayName": "SOC bot", "emails": ["soc@webex.bot"]})
            if request.url.path.endswith("/rooms"):
                return httpx.Response(200, json={"items": [{"id": ROOM, "title": "SOC alerts"}]})
            return httpx.Response(200, json={"id": "message-1"})
        return httpx.Response(202)

    monkeypatch.setattr(chat, "transport_factory", lambda: httpx.MockTransport(handler))
    return seen


@pytest.fixture
def chat_settings(client):
    """A Webex bot token and the tool's address, restored afterwards (the test database is shared)."""
    with session_scope() as s:
        before = load_settings(s)
        save_settings(s, {"webex_bot_token": "bot-token", "base_url": "https://etd.example"})
    yield
    with session_scope() as s:
        save_settings(s, {"base_url": before.base_url, "alert_chat_channel_id": before.alert_chat_channel_id})


def _channel(kind: str, address: str) -> tuple[int, str]:
    name = f"SOC {kind} {uuid.uuid4().hex[:6]}"
    with session_scope() as s:
        channel = ChatChannel(name=name, kind=kind, target_enc=secret_box().encrypt(address), target_hint=chat.target_hint(kind, address))
        s.add(channel)
        s.flush()
        return channel.id, name


def _card(request: httpx.Request) -> dict:
    payload = json.loads(request.content)
    assert payload["type"] == "message" and payload["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    return payload["attachments"][0]["content"]


# ---------------------------------------------------------------------------------------- formatting

@pytest.mark.parametrize("lang", ["en", "sv"])
def test_every_report_has_a_headline_for_chat(client, lang):
    tid = make_tenant(f"Chat-Co-{lang}")
    _seed(tid)
    with session_scope() as s:
        for key, definition in REPORTS.items():
            tenant = None if definition.scope == SCOPE_ALL else s.get(Tenant, tid)
            summary = summarize(render_report(s, definition, build_context(s, definition, tenant, NOW, "UTC", lang=lang)))
            assert summary.title and summary.meta, key
            assert summary.facts or summary.lead, f"{key}: no KPI tiles and no lead paragraph"
            assert all(label and value for label, value in summary.facts), key


def test_webex_and_teams_render_the_same_message():
    msg = chat.ChatMessage(title="Exposure and dwell time", subtitle="Acme · weekly report", status="warning", status_text="warning",
                           facts=[("Delivered before verdict", "13")], text="Lead.", link="https://etd.example/archive?run=7",
                           link_text="Open the report")
    md = chat.webex_markdown(msg)
    assert md.startswith("**⚠️ Exposure and dwell time**") and "- **13** Delivered before verdict" in md
    assert "[Open the report](https://etd.example/archive?run=7)" in md
    card = chat.teams_payload(msg)["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][2]["color"] == "Warning"
    assert {"title": "Delivered before verdict", "value": "13"} in card["body"][3]["facts"]
    assert card["actions"] == [{"type": "Action.OpenUrl", "title": "Open the report", "url": "https://etd.example/archive?run=7"}]


@pytest.mark.parametrize("url,error", [
    ("https://outlook.office.com/webhook/abc", "switched those off in May 2026"),
    ("https://acme.webhook.office.com/webhookb2/abc", "switched those off in May 2026"),
    ("http://prod-01.westeurope.logic.azure.com/workflows/abc", "https"),
    ("https://example.com/workflows/abc", "not a Microsoft Workflows host"),
    ("", "https"),
    ("https://prod-01.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01", "sig="),
])
def test_teams_webhooks_must_be_workflows_urls(url, error):
    with pytest.raises(ValueError, match=error):
        chat.validate_teams_url(url)
    assert chat.validate_teams_url(TEAMS_URL) == TEAMS_URL
    assert chat.validate_teams_url("https://default1.environment.api.powerplatform.com/powerautomate/automations/direct/x?sv=1.0&sig=s")


# ---------------------------------------------------------------------------------------- transports

def test_webex_posts_markdown_and_the_file(calls):
    target = chat.Target(1, "SOC", "webex", ROOM)
    chat.send(target, chat.ChatMessage(title="Health check"), "bot-token")
    chat.send(target, chat.ChatMessage(title="Vendor risk", attachment=("vendor_risk.pdf", b"%PDF-1.7 x", "application/pdf")), "bot-token")
    plain, with_file = calls
    assert plain.headers["Authorization"] == "Bearer bot-token" and json.loads(plain.content) == {"roomId": ROOM, "markdown": "**Health check**"}
    body = with_file.content
    assert b'name="roomId"' in body and ROOM.encode() in body and b'filename="vendor_risk.pdf"' in body and b"application/pdf" in body


def test_webex_waits_when_rate_limited_and_explains_failures(monkeypatch):
    answers = [httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={})]
    monkeypatch.setattr(chat, "transport_factory", lambda: httpx.MockTransport(lambda r: answers.pop(0)))
    chat.send_webex("t", ROOM, chat.ChatMessage(title="x"))
    assert not answers
    for status, words in ((401, "bot token"), (404, "member"), (400, "400")):
        monkeypatch.setattr(chat, "transport_factory", lambda s=status: httpx.MockTransport(lambda r: httpx.Response(s, json={"message": "no"})))
        with pytest.raises(chat.ChatError, match=words):
            chat.send_webex("t", ROOM, chat.ChatMessage(title="x"))
    with pytest.raises(chat.ChatError, match="No Webex bot token"):
        chat.send_webex("", ROOM, chat.ChatMessage(title="x"))


def test_teams_explains_a_dead_workflow(monkeypatch):
    monkeypatch.setattr(chat, "transport_factory", lambda: httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(chat.ChatError, match="workflow may have been turned off"):
        chat.send_teams(TEAMS_URL, chat.ChatMessage(title="x"))


def test_demo_mode_saves_messages_instead_of_posting(tmp_path, monkeypatch, calls):
    monkeypatch.setattr(chat, "get_config", lambda: SimpleNamespace(demo_mode=True, data_dir=tmp_path))
    chat.send(chat.Target(1, "SOC", "teams", TEAMS_URL), chat.ChatMessage(title="Campaigns"), "")
    saved = json.loads(next((tmp_path / "demo-outbox").glob("*-teams.json")).read_text())
    assert saved["channel"] == "SOC" and saved["message"]["attachments"][0]["content"]["body"][0]["text"] == "Campaigns"
    assert not calls


# ---------------------------------------------------------------------------------------- real runs

def test_run_now_posts_the_headline_and_a_link_to_teams(calls, chat_settings, tenant_id):
    cid, name = _channel("teams", TEAMS_URL)
    run_id = run_report("health_check", tenant_id=tenant_id, deliver=True, output_format="html", chat_channel_id=cid, language="sv")
    card = _card(calls[-1])
    assert card["body"][0]["text"] == "Hälsokontroll"
    assert card["actions"][0] == {"type": "Action.OpenUrl", "title": "Öppna rapporten",
                                  "url": f"https://etd.example/archive?report=health_check&tenant={tenant_id}&run={run_id}"}
    with session_scope() as s:
        run, channel = s.get(ReportRun, run_id), s.get(ChatChannel, cid)
        assert run.status == "ok" and run.chat_channel == name and run.chat_error is None
        assert channel.last_sent_at is not None and channel.last_error is None


def test_a_schedule_posts_to_webex_with_the_pdf_and_a_chat_outage_never_fails_the_report(calls, chat_settings, tenant_id):
    good, name = _channel("webex", ROOM)
    bad, bad_name = _channel("webex", ROOM + "FAILME")
    with session_scope() as s:
        schedules = [ReportSchedule(tenant_id=tenant_id, report_key="vendor_risk", cron="0 7 * * 1", recipients="", output_format="pdf",
                                    enabled=True, chat_channel_id=cid) for cid in (good, bad)]
        s.add_all(schedules)
        s.flush()
        ids = [x.id for x in schedules]
    ok_run, failed_run = (run_schedule(sid, deliver=True, force=True, triggered_by="manual") for sid in ids)
    posted = [r for r in calls if r.url.path.endswith("/messages")]
    assert b'filename="' in posted[0].content and (b"application/pdf" in posted[0].content or b"text/html" in posted[0].content)
    with session_scope() as s:
        ok, failed = s.get(ReportRun, ok_run), s.get(ReportRun, failed_run)
        assert ok.chat_channel == name and ok.chat_error is None
        assert failed.status == "ok" and failed.chat_channel == bad_name and "500" in failed.chat_error
        assert s.get(ChatChannel, bad).last_error and s.get(ChatChannel, good).last_error is None
        for sid in ids:
            s.delete(s.get(ReportSchedule, sid))


def test_nothing_is_posted_when_a_findings_only_schedule_has_nothing_to_report(calls, chat_settings):
    tid = make_tenant(f"Quiet-{uuid.uuid4().hex[:6]}")
    cid, _name = _channel("teams", TEAMS_URL)
    run_id = run_report("compromise_indicators", tenant_id=tid, deliver=True, output_format="html", chat_channel_id=cid,
                        only_with_findings=True)
    assert not calls
    with session_scope() as s:
        run = s.get(ReportRun, run_id)
        assert run.chat_channel is None and "nothing to report" in run.delivery_note


def test_alerts_go_to_the_alert_channel(calls, chat_settings):
    cid, _name = _channel("teams", TEAMS_URL)
    with session_scope() as s:
        save_settings(s, {"alert_chat_channel_id": cid})
        settings = load_settings(s)
    assert _send(settings, "[ETD] Scheduled report failed: Vendor risk - Acme", ["Vendor risk for Acme failed.", "boom"], "https://etd.example/x")
    card = _card(calls[-1])
    assert card["body"][0]["text"].startswith("[ETD] Scheduled report failed") and card["body"][2]["text"] == "- Vendor risk for Acme failed."
    assert card["actions"][0]["url"] == "https://etd.example/x"


# ---------------------------------------------------------------------------------------- the Chat page

def test_only_administrators_manage_chat(client):
    _user("chat-viewer")
    try:
        _login(client, "chat-viewer")
        for r in (client.get("/chat", follow_redirects=False),
                  client.post("/chat/channels", data={"kind": "teams", "name": "x", "webhook_url": TEAMS_URL}, follow_redirects=False)):
            assert r.status_code == 403 or "err=" in r.headers.get("location", "")
        assert 'href="/chat"' not in client.get("/reports").text
    finally:
        client.cookies.clear()
    with session_scope() as s:
        assert s.execute(select(ChatChannel).where(ChatChannel.name == "x")).scalar_one_or_none() is None


def test_setting_up_channels_on_the_chat_page(logged_in, calls, chat_settings, tenant_id):
    c = logged_in
    r = c.post("/chat/webex", data={"token": "new-bot-token"}, follow_redirects=False)
    assert r.status_code == 303 and "the bot is SOC bot" in unquote(r.headers["location"])
    with session_scope() as s:
        assert load_settings(s).webex_bot_token == "new-bot-token"
    page = c.get("/chat").text
    assert "SOC alerts" in page and "Add a Microsoft Teams channel" in page  # the bot's spaces are offered

    old = c.post("/chat/channels", data={"kind": "teams", "name": "Old hook", "webhook_url": "https://outlook.office.com/webhook/x"},
                 follow_redirects=False)
    assert "err=" in old.headers["location"] and "switched those off in May 2026" in unquote(old.headers["location"])
    name = f"SOC Teams {uuid.uuid4().hex[:6]}"
    c.post("/chat/channels", data={"kind": "teams", "name": name, "webhook_url": TEAMS_URL}, follow_redirects=False)
    with session_scope() as s:
        channel = s.execute(select(ChatChannel).where(ChatChannel.name == name)).scalar_one()
        assert channel.target_enc != TEAMS_URL and secret_box().decrypt(channel.target_enc) == TEAMS_URL
        assert channel.target_hint == "prod-01.westeurope.logic.azure.com"
        cid = channel.id
    assert "Test message posted" in unquote(c.post(f"/chat/channels/{cid}/test", follow_redirects=False).headers["location"])

    c.post("/schedules", data={"report_key": "health_check", "target": str(tenant_id), "chat_channel_id": str(cid)}, follow_redirects=False)
    with session_scope() as s:
        schedule = s.execute(select(ReportSchedule).order_by(ReportSchedule.id.desc())).scalars().first()
        assert schedule.chat_channel_id == cid
    assert f"posts to {name}" in c.get("/schedules").text

    c.post("/chat/alerts", data={"channel_id": str(cid)}, follow_redirects=False)
    c.post(f"/chat/channels/{cid}/delete", follow_redirects=False)
    with session_scope() as s:
        assert s.get(ChatChannel, cid) is None and s.get(ReportSchedule, schedule.id).chat_channel_id is None
        assert load_settings(s).alert_chat_channel_id == 0
