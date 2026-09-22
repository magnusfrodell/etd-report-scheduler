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
"""E-mail delivery through the customer's own SMTP relay."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app.settings_store import RuntimeSettings

log = logging.getLogger(__name__)


class EmailNotConfigured(RuntimeError):
    pass


def build_message(settings: RuntimeSettings, to: list[str], subject: str, html: str, attachments: list[tuple[str, bytes, str]] | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content("This report is best viewed in an HTML capable mail client.")
    msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    return msg


def send_email(settings: RuntimeSettings, to: list[str], subject: str, html: str, attachments: list[tuple[str, bytes, str]] | None = None) -> None:
    if not settings.smtp_configured:
        raise EmailNotConfigured("SMTP host and sender address are not configured (Settings > E-mail)")
    if not to:
        raise ValueError("No recipients")
    msg = build_message(settings, to, subject, html, attachments)
    log.info("Sending '%s' to %s via %s:%s", subject, ", ".join(to), settings.smtp_host, settings.smtp_port)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        smtp.ehlo()
        if settings.smtp_starttls:
            smtp.starttls()
            smtp.ehlo()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)
