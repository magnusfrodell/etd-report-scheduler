# Copyright (c) 2026 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.
"""Reports and alerts posted to a Webex space or a Microsoft Teams channel - the SOC's own channel.

Webex: a bot token for the installation; the message carries the report's headline and the PDF.
Teams: a Workflows webhook ("Post to a channel when a webhook request is received") per channel; the
message is an Adaptive Card with the headline and a link to the report in the archive (Workflows
webhooks cannot carry a file). All traffic is outbound - nothing has to reach this container."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from app.config import get_config
from app.crypto import secret_box
from app.db import session_scope
from app.delivery.summary import summarize
from app.models import ChatChannel, utcnow

log = logging.getLogger(__name__)

KINDS = {"webex": "Webex", "teams": "Microsoft Teams"}
WEBEX_API = "https://webexapis.com/v1"
# Where Microsoft hosts Workflows (Power Automate) webhooks.
TEAMS_HOSTS = ("logic.azure.com", "powerplatform.com", "powerautomate.com")
# Office 365 connector webhooks - Microsoft switched them off in May 2026.
RETIRED_TEAMS_HOSTS = ("webhook.office.com", "outlook.office.com", "outlook.office365.com")
STATUS_EMOJI = {"ok": "✅", "warning": "⚠️", "critical": "🔴", "unknown": "❔"}
STATUS_COLOR = {"ok": "Good", "warning": "Warning", "critical": "Attention"}
MAX_RETRIES = 2
MAX_WAIT = 10.0  # seconds to honour a Retry-After before giving up

def _default_transport() -> httpx.BaseTransport | None:
    return None


# Tests replace this to capture the HTTP calls.
transport_factory: Callable[[], httpx.BaseTransport | None] = _default_transport


class ChatError(Exception):
    """Posting failed - the message says why, in words an operator can act on."""


@dataclass
class ChatMessage:
    title: str
    subtitle: str = ""
    status: str | None = None  # ok | warning | critical | unknown
    status_text: str = ""
    facts: list[tuple[str, str]] = field(default_factory=list)  # (label, value)
    text: str = ""
    link: str = ""
    link_text: str = "Open"
    attachment: tuple[str, bytes, str] | None = None  # (file name, content, MIME type) - Webex only


@dataclass(frozen=True)
class Target:
    """What posting needs, read while a database session is open."""

    channel_id: int
    name: str
    kind: str
    address: str  # Webex room id or Teams Workflows URL (decrypted)


# ------------------------------------------------------------------------------------------ validation

def validate_teams_url(url: str) -> str:
    url = (url or "").strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if any(host == h or host.endswith("." + h) for h in RETIRED_TEAMS_HOSTS):
        raise ValueError("This is an Office 365 connector webhook, and Microsoft switched those off in May 2026. In the Teams "
                         "channel, open Workflows and create 'Post to a channel when a webhook request is received', then paste "
                         "that URL.")
    if parts.scheme != "https" or not host:
        raise ValueError("The Teams webhook must be an https URL from a Workflows webhook.")
    if not any(host == h or host.endswith("." + h) for h in TEAMS_HOSTS):
        raise ValueError(f"'{host}' is not a Microsoft Workflows host. Paste the URL that the Teams workflow "
                         "'Post to a channel when a webhook request is received' shows.")
    if "sig=" not in parts.query:
        raise ValueError("The URL has no 'sig=' signature at the end. Copy the whole URL again - and in the workflow's trigger, "
                         "'Who can trigger the flow' must be 'Anyone': a trigger limited to the tenant's users needs a sign-in "
                         "this tool cannot make.")
    return url


def target_hint(kind: str, address: str, room_title: str = "") -> str:
    if kind == "teams":
        return urlsplit(address).hostname or ""
    return room_title or (address[:12] + "…" if len(address) > 12 else address)


# ------------------------------------------------------------------------------------------ formatting

def report_message(html: str, link: str, link_text: str, attachment: tuple[str, bytes, str] | None) -> ChatMessage:
    s = summarize(html)
    return ChatMessage(title=s.title, subtitle=s.meta, status=s.status, status_text=s.status_text, facts=s.facts,
                       text=s.lead, link=link, link_text=link_text, attachment=attachment)


def webex_markdown(msg: ChatMessage) -> str:
    emoji = STATUS_EMOJI.get(msg.status or "", "")
    lines = [f"**{(emoji + ' ') if emoji else ''}{msg.title}**"]
    if msg.subtitle:
        lines.append(msg.subtitle)
    if msg.status_text and msg.status:
        lines.append(f"Status: **{msg.status_text}**")
    if msg.facts:
        lines.append("")
        lines += [f"- **{value}** {label}" for label, value in msg.facts]
    if msg.text:
        lines += ["", msg.text]
    if msg.link:
        lines += ["", f"[{msg.link_text}]({msg.link})"]
    return "\n".join(lines)


def teams_payload(msg: ChatMessage) -> dict[str, Any]:
    body: list[dict[str, Any]] = [{"type": "TextBlock", "text": msg.title, "weight": "Bolder", "size": "Medium", "wrap": True}]
    if msg.subtitle:
        body.append({"type": "TextBlock", "text": msg.subtitle, "isSubtle": True, "spacing": "None", "wrap": True})
    if msg.status and msg.status_text:
        body.append({"type": "TextBlock", "text": f"{STATUS_EMOJI.get(msg.status, '')} {msg.status_text}".strip(), "weight": "Bolder",
                     "color": STATUS_COLOR.get(msg.status, "Default"), "wrap": True})
    if msg.facts:
        body.append({"type": "FactSet", "facts": [{"title": label, "value": value} for label, value in msg.facts]})
    for paragraph in [p for p in msg.text.split("\n") if p.strip()]:
        body.append({"type": "TextBlock", "text": paragraph, "wrap": True})
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "msteams": {"width": "Full"}, "body": body}
    if msg.link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": msg.link_text, "url": msg.link}]
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                                                "content": card}]}


# ------------------------------------------------------------------------------------------ sending

def _client() -> httpx.Client:
    return httpx.Client(timeout=30.0, transport=transport_factory())


def _request(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    """One call, repeated after a 429 when the service asks for a short wait."""
    for attempt in range(MAX_RETRIES + 1):
        response = client.request(method, url, **kwargs)
        if response.status_code != 429 or attempt == MAX_RETRIES:
            return response
        try:
            wait = float(response.headers.get("Retry-After", "2"))
        except ValueError:
            wait = 2.0
        if wait > MAX_WAIT:
            return response
        time.sleep(wait)
    return response  # pragma: no cover - the loop always returns


def _webex_reason(response: httpx.Response) -> str:
    try:
        return str(response.json().get("message") or response.text)[:200]
    except ValueError:
        return response.text[:200]


def _webex_call(token: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
    if not token:
        raise ChatError("No Webex bot token is set - add it on the Chat page.")
    try:
        with _client() as client:
            response = _request(client, method, f"{WEBEX_API}{path}", headers={"Authorization": f"Bearer {token}"}, **kwargs)
    except httpx.HTTPError as exc:
        raise ChatError(f"Webex could not be reached: {type(exc).__name__}: {exc}") from exc
    if response.status_code == 401:
        raise ChatError("Webex rejected the bot token (401) - check it on the Chat page.")
    if response.status_code == 404 and path.startswith("/messages"):
        raise ChatError("Webex does not know the space (404) - is the bot still a member of it?")
    if response.status_code >= 400:
        raise ChatError(f"Webex answered {response.status_code}: {_webex_reason(response)}")
    return response


def send_webex(token: str, room_id: str, msg: ChatMessage) -> None:
    fields = {"roomId": room_id, "markdown": webex_markdown(msg)}
    if msg.attachment:
        name, content, mime = msg.attachment
        _webex_call(token, "POST", "/messages", data=fields, files={"files": (name, content, mime)})
    else:
        _webex_call(token, "POST", "/messages", json=fields)


def send_teams(url: str, msg: ChatMessage) -> None:
    try:
        with _client() as client:
            response = _request(client, "POST", url, json=teams_payload(msg))
    except httpx.HTTPError as exc:
        raise ChatError(f"Teams could not be reached: {type(exc).__name__}: {exc}") from exc
    if response.status_code in (401, 403, 404):
        raise ChatError(f"Teams rejected the webhook ({response.status_code}) - the workflow may have been turned off, deleted "
                        "or lost its owner; create a new one and update the channel.")
    if response.status_code >= 400:
        raise ChatError(f"Teams answered {response.status_code}: {response.text[:200]}")


def webex_identity(token: str) -> str:
    """The bot's name and address, to show that the token works."""
    me = _webex_call(token, "GET", "/people/me").json()
    return f"{me.get('displayName', '?')} ({', '.join(me.get('emails') or [])})"


def webex_rooms(token: str) -> list[tuple[str, str]]:
    """The spaces the bot is a member of: (room id, title), most recently active first."""
    items = _webex_call(token, "GET", "/rooms", params={"max": 100, "sortBy": "lastactivity"}).json().get("items") or []
    return [(r["id"], r.get("title") or r["id"]) for r in items if r.get("id")]


def _demo_outbox(target: Target, msg: ChatMessage) -> None:
    folder = get_config().data_dir / "demo-outbox"
    folder.mkdir(parents=True, exist_ok=True)
    payload = webex_markdown(msg) if target.kind == "webex" else teams_payload(msg)
    record = {"channel": target.name, "kind": target.kind, "message": payload,
              "attachment": msg.attachment[0] if msg.attachment and target.kind == "webex" else None}
    path = folder / f"{datetime.now(UTC):%Y%m%d-%H%M%S-%f}-{target.kind}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    for old in sorted(folder.glob("*.json"))[:-200]:
        old.unlink(missing_ok=True)
    log.info("Demo mode: chat message for '%s' saved to %s instead of being posted", target.name, path)


def send(target: Target, msg: ChatMessage, webex_token: str) -> None:
    if get_config().demo_mode:
        _demo_outbox(target, msg)
    elif target.kind == "webex":
        send_webex(webex_token, target.address, msg)
    elif target.kind == "teams":
        send_teams(target.address, msg)
    else:
        raise ChatError(f"Unknown channel type '{target.kind}'")


# ------------------------------------------------------------------------------------------ channels

def load_target(session: Session, channel_id: int | None) -> Target | None:
    channel = session.get(ChatChannel, channel_id) if channel_id else None
    if channel is None:
        return None
    return Target(channel.id, channel.name, channel.kind, secret_box().decrypt(channel.target_enc) or "")


def record_result(channel_id: int, error: str | None) -> None:
    with session_scope() as session:
        channel = session.get(ChatChannel, channel_id)
        if channel is None:
            return
        if error:
            channel.last_error = error[:500]
        else:
            channel.last_sent_at, channel.last_error = utcnow(), None


def post(target: Target, msg: ChatMessage, webex_token: str) -> str | None:
    """Post and record the outcome on the channel. Returns the error, or None - never raises, so a chat
    outage cannot fail the report or alert that triggered it."""
    try:
        send(target, msg, webex_token)
        error = None
    except ChatError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001
        log.exception("Posting to chat channel '%s' failed", target.name)
        error = f"{type(exc).__name__}: {exc}"
    if error:
        log.warning("Chat channel '%s': %s", target.name, error)
    try:
        record_result(target.channel_id, error)
    except Exception:  # noqa: BLE001 - bookkeeping only
        log.exception("Could not record the result for chat channel '%s'", target.name)
    return error
