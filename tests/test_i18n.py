"""0.10.0: report languages - catalogs, Swedish reports, the language choice and number formatting."""

from __future__ import annotations

import html
import re
import string
from collections import Counter
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
from babel.messages.extract import extract_from_dir
from babel.messages.frontend import parse_mapping_cfg
from babel.messages.pofile import read_po
from markupsafe import Markup
from sqlalchemy import select

from app.db import session_scope
from app.delivery.pdf import pdf_available
from app.demo import scenario
from app.demo.seed import add_demo_tenant, collect_history
from app.demo.simulator import simulator
from app.etd import client as etd_client
from app.etd import factory
from app.i18n import _DECIMAL_COMMA as DECIMAL_COMMA_LANGUAGES
from app.i18n import LANGUAGES, LOCALE_DIR, Translator, active_language, catalog, local_decimal, use_language
from app.models import ReportRun, ReportSchedule, Tenant, utcnow
from app.reports import domains
from app.reports.analysis import by_count, fmt_hours
from app.reports.base import SCOPE_ALL
from app.reports.registry import REPORTS
from app.services import build_context, render_report, resolve_language, run_report, run_schedule
from app.settings_store import load_settings, save_settings

ROOT = Path(__file__).resolve().parent.parent
KEYWORDS = {"tr": None, "N_": None, "_": None, "pgettext": ((1, "c"), 2)}
# A decimal number with a point that is not part of a date, version, IP address or host name.
DECIMAL_POINT = re.compile(r"(?<![\w.@/-])\d+\.\d+(?![\w.@/-])")


def _fields(text: str) -> list[tuple[str, str, str]]:
    return sorted((f, s or "", c or "") for _, f, s, c in string.Formatter().parse(text) if f is not None)


def _report_texts() -> set[tuple[str | None, str]]:
    """Every translatable text in the report code and templates, found the way pybabel finds them."""
    with (ROOT / "babel.cfg").open() as cfg:
        method_map, options_map = parse_mapping_cfg(cfg)
    found = set()
    for _file, _line, message, _comments, context in extract_from_dir(str(ROOT), method_map, options_map, keywords=KEYWORDS):
        if isinstance(message, str) and message:
            found.add((context, message))
    return found


def _po(path: Path) -> dict[tuple[str | None, str], str]:
    with path.open("rb") as handle:
        return {(m.context, m.id): m.string for m in read_po(handle) if m.id}


def _text(raw: str) -> str:
    raw = re.sub(r"<style.*?</style>", " ", raw, flags=re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " | ", raw)))


# ---------------------------------------------------------------------------------------- the catalog

TRANSLATED = [lang for lang in LANGUAGES if lang != "en"]


@pytest.mark.parametrize("lang", TRANSLATED)
def test_every_report_text_is_translated_with_the_same_placeholders(lang):
    texts = _report_texts()
    assert len(texts) > 400
    translations = _po(LOCALE_DIR / lang / "LC_MESSAGES" / "messages.po")
    missing = sorted(message for key in texts if not translations.get(key) for message in [key[1]])
    assert not missing, f"{len(missing)} report text(s) have no '{lang}' translation (docs/TRANSLATING.md): {missing[:5]}"
    wrong = [message for (_ctx, message), text in translations.items() if text and _fields(message) != _fields(text)]
    assert not wrong, f"'{lang}' translations whose placeholders differ from the English text: {wrong[:5]}"


def test_the_catalog_template_is_up_to_date():
    template = set(_po(LOCALE_DIR / "messages.pot"))
    texts = _report_texts()
    assert texts <= template, (
        "app/locale/messages.pot is out of date - run: pybabel extract -F babel.cfg -k tr -k N_ -k _ "
        f"-k pgettext:1c,2 --no-location --omit-header --sort-output -o app/locale/messages.pot .  New: {sorted(texts - template)[:5]}")


# ---------------------------------------------------------------------------------------- the translator

def test_english_needs_no_catalog_and_unknown_languages_fall_back_to_it():
    en = Translator("en")
    assert catalog("en") == {}
    assert en("{n} threat(s)", n=3) == "3 threat(s)"
    assert en.month(date(2026, 8, 1)) == "August 2026"
    assert en.pgettext("action", "none") == "none"
    assert Translator("xx").lang == "en" and Translator(None).lang == "en" and Translator("SV").lang == "sv"


def test_swedish_words_months_decimals_and_context():
    sv = Translator("sv")
    assert sv("Threats") == "Hot" and sv("Vendor risk") == "Leverantörsrisk"
    assert sv.month(date(2026, 8, 1)) == "augusti 2026"
    assert sv("{remediated_count} of {threats_count} threats were moved or deleted ({cov:.1f} %).",
              remediated_count=9, threats_count=10, cov=90.0) == "9 av 10 hot flyttades eller raderades (90,0 %)."
    assert sv("×{factor} (≤{n} recipients)", factor=1.5, n=3) == "×1,5 (≤3 mottagare)"
    # The same English word, two Swedish ones: "no action" versus "no reclassifications".
    assert sv.pgettext("action", "none") == "ingen" and sv("none") == "inga"


def test_template_texts_are_escaped_but_intended_markup_is_kept():
    en = Translator("en")
    out = en.markup("{a} and {b}", a="<script>", b=Markup("<strong>x</strong>"))
    assert str(out) == "&lt;script&gt; and <strong>x</strong>"
    assert str(en.markup('Say "hi" & go')) == "Say &#34;hi&#34; &amp; go"


def test_a_translation_that_does_not_fit_its_values_falls_back_to_english():
    sv = Translator("sv")
    sv._messages = {**sv._messages, "{n} probes": "{m} sonder"}
    assert sv("{n} probes", n=2) == "2 probes"
    assert str(sv.markup("{n} probes", n=2)) == "2 probes"


def test_numbers_formatted_inside_report_code_follow_the_active_language():
    assert active_language() == "en" and fmt_hours(20.8) == "20.8 h"
    with use_language("sv"):
        assert active_language() == "sv"
        assert fmt_hours(20.8) == "20,8 h" and fmt_hours(80) == "3,3 d" and fmt_hours(0.5) == "30 min"
        assert local_decimal("1.5") == "1,5"
    assert active_language() == "en" and fmt_hours(80) == "3.3 d"


def test_tied_counts_are_listed_in_the_same_order_on_every_run():
    assert by_count(Counter({"b": 2, "a": 2, "c": 3})) == [("c", 3), ("a", 2), ("b", 2)]
    assert by_count(Counter({"b": 2, "a": 2}), 1) == [("a", 2)]


# ---------------------------------------------------------------------------------------- the choice

def test_explicit_choice_beats_the_tenant_which_beats_the_installation_default(client):
    with session_scope() as s:
        settings = load_settings(s)
    en_default, sv_default = replace(settings, report_language="en"), replace(settings, report_language="sv")
    swedish_tenant = Tenant(name="x", profile={"language": "sv"})
    assert resolve_language(en_default, None) == "en"
    assert resolve_language(sv_default, None) == "sv"
    assert resolve_language(en_default, swedish_tenant) == "sv"
    assert resolve_language(sv_default, Tenant(name="y", profile={})) == "sv"
    assert resolve_language(en_default, swedish_tenant, "en") == "en"
    assert resolve_language(en_default, Tenant(name="z", profile={"language": "xx"})) == "en"


def test_language_is_chosen_per_tenant_schedule_run_and_api(logged_in, tenant_id):
    c = logged_in
    r = c.post(f"/tenants/{tenant_id}/profile", data={"language": "sv"}, follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as s:
        assert s.get(Tenant, tenant_id).profile["language"] == "sv"
    assert 'value="sv" selected' in c.get("/tenants").text

    r = c.post("/schedules", data={"report_key": "health_check", "target": str(tenant_id), "language": "en"}, follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as s:
        schedule = s.execute(select(ReportSchedule).order_by(ReportSchedule.id.desc())).scalars().first()
        assert schedule.language == "en"
    assert "in English" in c.get("/schedules").text

    c.post("/reports/health_check/run", data={"tenant_id": str(tenant_id), "language": "sv"}, follow_redirects=False)
    with session_scope() as s:
        run = s.execute(select(ReportRun).where(ReportRun.tenant_id == tenant_id).order_by(ReportRun.id.desc())).scalars().first()
        assert run.language == "sv" and run.status == "ok"
        assert "Hälsokontroll" in Path(run.html_path).read_text()
    assert "in Swedish" in c.get("/archive").text

    assert c.post(f"/api/reports/health_check/run?tenant_id={tenant_id}&language=xx").status_code == 400
    ok = c.post(f"/api/reports/health_check/run?tenant_id={tenant_id}&language=en")
    assert ok.status_code == 200 and ok.json()["language"] == "en"


def test_the_installation_default_is_a_setting(logged_in):
    with session_scope() as s:
        before = load_settings(s).report_language
    try:
        logged_in.post("/settings", data={"timezone": "Europe/Stockholm", "smtp_port": "587", "retention_days": "365",
                                          "report_language": "sv"}, follow_redirects=False)
        with session_scope() as s:
            assert load_settings(s).report_language == "sv"
    finally:
        with session_scope() as s:
            save_settings(s, {"report_language": before})


# ---------------------------------------------------------------------------------------- real reports

@pytest.fixture(scope="module")
def demo_tenant(client) -> int:
    """One demo tenant with its simulated history, collected by the real collectors (shared with test_demo)."""
    spec = next(t for t in scenario.TENANTS if t.key == "nordic-freight")
    with session_scope() as s:
        existing = s.execute(select(Tenant).where(Tenant.name == spec.name)).scalar_one_or_none()
        tid = existing.id if existing else add_demo_tenant(s, spec).id
    if existing is None:
        patch = pytest.MonkeyPatch()
        patch.setattr(factory, "transport_factory", simulator.transport_for)
        patch.setattr(etd_client, "limiter_for", lambda key, per_second=2.0: etd_client.RateLimiter(0))
        records = scenario.dns_records()
        patch.setattr(domains, "resolve_txt", lambda name: list(records.get(name, [])))
        try:
            collect_history([tid])
        finally:
            patch.undo()
    return tid


@pytest.mark.parametrize("lang", TRANSLATED)
def test_translated_reports_keep_every_number_and_use_decimal_commas(demo_tenant, lang):
    """Through run_report, the path scheduled reports take: a translation may change words and word order,
    never a count - and a Swedish report has no decimal points (a helper formatting numbers outside the
    active language would show up here)."""
    now = utcnow()
    for key, definition in REPORTS.items():
        tid = None if definition.scope == SCOPE_ALL else demo_tenant
        run_ids = {code: run_report(key, tenant_id=tid, output_format="html", deliver=False, now=now, language=code, alert=False)
                   for code in ("en", lang)}
        with session_scope() as s:
            runs = {code: s.get(ReportRun, rid) for code, rid in run_ids.items()}
            assert runs["en"].status == runs[lang].status == "ok", (key, runs[lang].error)
            assert runs["en"].language == "en" and runs[lang].language == lang
            raw = {code: Path(run.html_path).read_text() for code, run in runs.items()}
        en, translated = _text(raw["en"]), _text(raw[lang])
        assert Counter(re.findall(r"\d+", en)) == Counter(re.findall(r"\d+", translated)), key
        if lang in DECIMAL_COMMA_LANGUAGES:
            assert not DECIMAL_POINT.findall(translated), (key, DECIMAL_POINT.findall(translated)[:3])
        assert f'<html lang="{lang}">' in raw[lang] and '<html lang="en">' in raw["en"]
        assert re.findall(r'style="width:[0-9.]+%"', raw[lang]) == re.findall(r'style="width:[0-9.]+%"', raw["en"])


def test_a_schedule_uses_each_tenants_language_unless_it_names_one(demo_tenant):
    with session_scope() as s:
        tenant = s.get(Tenant, demo_tenant)
        original = dict(tenant.profile or {})
        tenant.profile = {**original, "language": "sv"}
        each = ReportSchedule(tenant_id=demo_tenant, report_key="vendor_risk", cron="0 7 * * 1", recipients="", output_format="html",
                              enabled=True, language="")
        english = ReportSchedule(tenant_id=demo_tenant, report_key="vendor_risk", cron="0 7 * * 1", recipients="", output_format="html",
                                 enabled=True, language="en")
        s.add_all([each, english])
        s.flush()
        ids = (each.id, english.id)
    try:
        runs = [run_schedule(sid, deliver=False, force=True, triggered_by="manual") for sid in ids]
        with session_scope() as s:
            swedish_run, english_run = (s.get(ReportRun, rid) for rid in runs)
            assert swedish_run.language == "sv" and "Leverantörsrisk" in Path(swedish_run.html_path).read_text()
            assert english_run.language == "en" and "Vendor risk" in Path(english_run.html_path).read_text()
    finally:
        with session_scope() as s:
            s.get(Tenant, demo_tenant).profile = original
            for sid in ids:
                s.delete(s.get(ReportSchedule, sid))


@pytest.mark.skipif(not pdf_available(), reason="WeasyPrint is not available here")
def test_no_report_runs_off_the_paper_in_either_language(demo_tenant):
    """Longer Swedish words and long subjects or addresses must wrap, not push a table past the page edge
    (a numeric column's header and an e-mail subject used to be unbreakable in the PDF)."""
    from weasyprint import HTML

    now = utcnow()
    with session_scope() as s:
        tenant = s.get(Tenant, demo_tenant)
        for key, definition in REPORTS.items():
            for lang in ("en", *TRANSLATED):
                ctx = build_context(s, definition, None if definition.scope == SCOPE_ALL else tenant, now, "Europe/Stockholm", lang=lang)
                document = HTML(string=render_report(s, definition, ctx)).render()
                for number, page in enumerate(document.pages, 1):
                    if not hasattr(page, "_page_box"):
                        pytest.skip("this WeasyPrint version does not expose its layout boxes")
                    past = [type(box).__name__ for box in page._page_box.descendants()
                            if box.border_box_x() + box.border_width() > page.width + 0.5]
                    assert not past, f"{key} ({lang}) page {number}: {len(past)} box(es) run past the paper edge"
