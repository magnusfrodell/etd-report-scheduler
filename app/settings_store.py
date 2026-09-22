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
"""Runtime settings (editable in the UI) with sane defaults."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.crypto import secret_box
from app.models import Setting

THREAT_VERDICTS = ("bec", "scam", "phishing", "malicious")
ALL_VERDICTS = ("bec", "scam", "phishing", "malicious", "spam", "graymail")


@dataclass
class RuntimeSettings:
    timezone: str = "UTC"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""  # decrypted in memory only
    smtp_from: str = ""
    smtp_starttls: bool = True
    partner_recipients: str = ""
    retention_days: int = 400
    convictions_verdicts: list[str] = field(default_factory=lambda: list(THREAT_VERDICTS))
    stats_days_back: int = 3
    convictions_initial_days: int = 7  # quick first pull; the backfill job fills the rest of the 90 days
    convictions_rescan_days: int = 7
    api_daily_budget: int = 8000  # of ETD's 10 000/day per tenant; the rest is headroom for manual actions
    backfill_window_days: int = 7
    base_url: str = ""

    SECRET_KEYS = ("smtp_password",)

    def tzinfo(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.timezone or "UTC")
        except ZoneInfoNotFoundError:
            return ZoneInfo("UTC")

    @property
    def partner_recipient_list(self) -> list[str]:
        return [r.strip() for r in self.partner_recipients.replace(";", ",").split(",") if r.strip()]

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)


def load_settings(session: Session) -> RuntimeSettings:
    rows = {row.key: row.value for row in session.query(Setting).all()}
    result = RuntimeSettings()
    for f in fields(result):
        if f.name in rows and rows[f.name] is not None:
            value = rows[f.name]
            if f.name in RuntimeSettings.SECRET_KEYS:
                value = secret_box().decrypt(value) or ""
            setattr(result, f.name, value)
    if isinstance(result.convictions_verdicts, str):  # tolerate comma separated storage
        result.convictions_verdicts = [v.strip() for v in result.convictions_verdicts.split(",") if v.strip()]
    result.convictions_verdicts = [v for v in result.convictions_verdicts if v in ALL_VERDICTS] or list(THREAT_VERDICTS)
    return result


def save_settings(session: Session, values: dict[str, Any]) -> None:
    """Persist a subset of settings. Unknown keys are ignored, secrets are encrypted."""
    known = {f.name for f in fields(RuntimeSettings)}
    for key, value in values.items():
        if key not in known:
            continue
        if key in RuntimeSettings.SECRET_KEYS:
            if value == "":  # empty submit keeps the existing password
                continue
            value = secret_box().encrypt(value)
        row = session.get(Setting, key)
        if row is None:
            row = Setting(key=key, value=value)
            session.add(row)
        else:
            row.value = value
    session.flush()
