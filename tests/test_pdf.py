"""Every report renders to an A4 PDF. Runs where WeasyPrint and its system libraries are installed -
in CI and in the image; skipped elsewhere (for example on Windows)."""

from __future__ import annotations

import pytest

from app.db import session_scope
from app.delivery.pdf import pdf_available, render_pdf
from app.models import Tenant
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS
from app.services import build_context, render_report

if pdf_available():
    from weasyprint import HTML
from tests.conftest import make_tenant
from tests.test_posture_reports import NOW, _seed

pytestmark = pytest.mark.skipif(not pdf_available(), reason="WeasyPrint is not available here")
A4 = (793.7, 1122.5)  # CSS pixels at 96 dpi


def test_every_report_renders_to_an_a4_pdf(client):
    tid = make_tenant("Pdf-Co")
    _seed(tid)
    with session_scope() as s:
        for key, definition in REPORTS.items():
            tenant = None if definition.scope == SCOPE_ALL else s.get(Tenant, tid)
            html = render_report(s, definition, build_context(s, definition, tenant, NOW, "UTC"))
            document = HTML(string=html).render()
            off_a4 = [(round(page.width), round(page.height)) for page in document.pages
                      if abs(page.width - A4[0]) > 1 or abs(page.height - A4[1]) > 1]
            assert document.pages and not off_a4, f"{key}: every page is A4, got {off_a4}"
            assert document.write_pdf().startswith(b"%PDF"), key
    assert render_pdf("<p>x</p>").startswith(b"%PDF")
