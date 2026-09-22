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
"""HTML -> PDF rendering with WeasyPrint (optional dependency).

WeasyPrint needs Pango/Cairo system libraries; the Docker image ships them.
If the import fails the report is delivered as HTML only and a warning is
logged - reporting never breaks because of the PDF step.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_available: bool | None = None


def pdf_available() -> bool:
    global _available
    if _available is None:
        try:
            import weasyprint  # noqa: F401

            _available = True
        except Exception as exc:  # noqa: BLE001 - ImportError or OSError from missing libs
            log.warning("PDF rendering unavailable (%s); reports will be delivered as HTML", exc)
            _available = False
    return _available


def render_pdf(html: str, base_url: str | None = None) -> bytes | None:
    if not pdf_available():
        return None
    from weasyprint import HTML

    return HTML(string=html, base_url=base_url).write_pdf()
