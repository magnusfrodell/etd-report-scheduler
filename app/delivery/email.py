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
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr

from app.settings_store import RuntimeSettings

log = logging.getLogger(__name__)


class EmailNotConfigured(RuntimeError):
    pass


def build_message(settings: RuntimeSettings, to: list[str], subject: str, html: str, attachments: list[tuple[str, bytes, str]] | None = None,
                  *, inline_images: list[tuple[str, bytes, str]] | None = None, from_name: str | None = None,
                  reply_to: str | None = None) -> EmailMessage:
    """``inline_images`` are (content id, data, mime type) shown in the HTML as ``cid:<content id>`` -
    mail clients do not display data: URIs."""
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, parseaddr(settings.smtp_from)[1])) if from_name else settings.smtp_from
    msg["To"] = ", ".join(to)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content("This report is best viewed in an HTML capable mail client.")
    msg.add_alternative(html, subtype="html")
    if inline_images:
        html_part = msg.get_payload()[-1]
        for cid, data, mime in inline_images:
            maintype, _, subtype = mime.partition("/")
            html_part.add_related(data, maintype=maintype, subtype=subtype, cid=f"<{cid}>", disposition="inline")
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    return msg


def tls_context(settings: RuntimeSettings) -> ssl.SSLContext:
    """TLS for the relay connection: the system CAs plus an optional internal CA, host name checked.

    ``smtplib`` does *not* verify certificates unless it is given a context - without this anyone who
    can intercept the connection could pose as the relay and read the reports and the SMTP password."""
    context = ssl.create_default_context()
    if settings.smtp_ca_pem.strip():
        context.load_verify_locations(cadata=settings.smtp_ca_pem)
    if not settings.smtp_tls_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def send_email(settings: RuntimeSettings, to: list[str], subject: str, html: str, attachments: list[tuple[str, bytes, str]] | None = None,
               *, inline_images: list[tuple[str, bytes, str]] | None = None, from_name: str | None = None,
               reply_to: str | None = None) -> dict[str, tuple[int, bytes]]:
    if not settings.smtp_configured:
        raise EmailNotConfigured("SMTP host and sender address are not configured (Settings > E-mail)")
    if not to:
        raise ValueError("No recipients")
    msg = build_message(settings, to, subject, html, attachments, inline_images=inline_images, from_name=from_name, reply_to=reply_to)
    log.info("Sending '%s' to %s via %s:%s", subject, ", ".join(to), settings.smtp_host, settings.smtp_port)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        smtp.ehlo()
        if settings.smtp_starttls:
            smtp.starttls(context=tls_context(settings))
            smtp.ehlo()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        refused = smtp.send_message(msg)
    # The relay may accept the message for some recipients and refuse others without raising.
    return dict(refused or {})
