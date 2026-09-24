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
"""Partner branding for reports and e-mails: name, logo, colours, footer and sender details.

Tenants use the brand named in their reporting profile, else the default brand, else the
neutral look the tool has always had.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Brand, Tenant
from app.tenant_profile import get_profile

DEFAULT_PRIMARY = "#0f2a43"
DEFAULT_ACCENT = "#1f77b4"
MAX_LOGO_BYTES = 300_000
_HEX = re.compile(r"^#[0-9a-f]{6}$")
_ADDRESS = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[a-z0-9-]{2,}$", re.IGNORECASE)


def logo_type(data: bytes) -> str | None:
    """PNG or JPEG - the formats every mail client and the PDF renderer show."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    return None


def valid_color(value: str | None) -> bool:
    """Colours end up inside CSS, where HTML escaping does not help - only #rrggbb gets through."""
    return bool(_HEX.match((value or "").strip().lower()))


def valid_address(value: str | None) -> bool:
    return bool(_ADDRESS.match((value or "").strip()))


def _mix(color: str, other: str, weight: float) -> str:
    """``weight`` parts of ``color`` mixed with ``1 - weight`` parts of ``other``."""
    a = [int(color[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(other[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * weight + y * (1 - weight)):02x}" for x, y in zip(a, b, strict=True))


@dataclass(frozen=True)
class BrandView:
    """A brand ready for templates and e-mail - plain values, safe to use after the session closes."""

    name: str = ""
    logo_type: str | None = None
    logo_b64: str | None = None
    primary: str = DEFAULT_PRIMARY
    accent: str = DEFAULT_ACCENT
    footer: str = ""
    subject_prefix: str = ""
    sender_name: str = ""
    reply_to: str = ""
    show_credit: bool = True

    @property
    def primary_dark(self) -> str:
        return _mix(self.primary, "#000000", 0.72)

    @property
    def accent_tint(self) -> str:
        return _mix(self.accent, "#ffffff", 0.14)

    @property
    def logo_src(self) -> str | None:
        """A data URI for the archive and PDFs. Mail clients block these; e-mails use cid: instead."""
        return f"data:{self.logo_type};base64,{self.logo_b64}" if self.logo_b64 and self.logo_type else None

    @property
    def logo_bytes(self) -> bytes | None:
        return base64.b64decode(self.logo_b64) if self.logo_b64 else None


NEUTRAL = BrandView()


def view(brand: Brand | None) -> BrandView:
    if brand is None:
        return NEUTRAL
    primary = (brand.primary_color or "").lower()
    accent = (brand.accent_color or "").lower()
    return BrandView(
        name=brand.name or "",
        logo_type=brand.logo_type if brand.logo_b64 else None,
        logo_b64=brand.logo_b64,
        primary=primary if valid_color(primary) else DEFAULT_PRIMARY,
        accent=accent if valid_color(accent) else DEFAULT_ACCENT,
        footer=brand.footer_text or "",
        subject_prefix=brand.subject_prefix or "",
        sender_name=brand.sender_name or "",
        reply_to=brand.reply_to or "",
        show_credit=brand.show_tool_credit,
    )


def default_brand(session: Session) -> Brand | None:
    return session.execute(select(Brand).where(Brand.is_default.is_(True)).order_by(Brand.id).limit(1)).scalar()


def brand_for(session: Session, tenant: Tenant | None) -> BrandView:
    """The tenant's own brand, else the default brand, else the neutral look."""
    brand = None
    if tenant is not None:
        brand_id = get_profile(tenant)["brand_id"]
        if brand_id:
            brand = session.get(Brand, brand_id)
    return view(brand or default_brand(session))
