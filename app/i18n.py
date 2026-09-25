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
"""Report languages.

Reports, PDFs and e-mails are translated with gettext-style catalogs
(``app/locale/<lang>/LC_MESSAGES/messages.po``) whose message ids are the English texts, so English
output needs no catalog at all. Dates and numbers follow the language too. The admin UI stays English.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

from markupsafe import Markup

log = logging.getLogger(__name__)

LANGUAGES: dict[str, str] = {"en": "English", "sv": "Svenska"}  # as each language names itself (pickers)
LANGUAGE_NAMES: dict[str, str] = {"en": "English", "sv": "Swedish"}  # in the (English) admin UI
DEFAULT = "en"
LOCALE_DIR = Path(__file__).parent / "locale"
_BABEL_LOCALES = {"en": "en_GB", "sv": "sv_SE"}


def N_(message: str) -> str:
    """Marks a text for the catalog where it is defined; it is translated later, where it is shown
    (group names, technique families and similar values that the logic also uses as keys)."""
    return message


# Texts that reach the templates as data values (status chips, period kinds) rather than literals.
VOCABULARY = (
    N_("ok"), N_("warning"), N_("critical"), N_("unknown"), N_("na"), N_("new"),
    N_("daily report for {period}"), N_("weekly report for {period}"),
    N_("monthly report for {period}"), N_("quarterly report for {period}"),
    N_("missing"), N_("multiple records (invalid)"), N_("multiple records (permerror)"),
    N_("incoming"), N_("outgoing"), N_("internal"),
    N_("redirect"), N_("no all mechanism"), N_("error"), N_("?all (neutral)"), N_("+all (anyone may send)"),
)


# The language of the report being built and rendered right now (set by services.render_report), for
# helpers that format numbers deep inside the report code.
_active: ContextVar[str] = ContextVar("report_language", default=DEFAULT)
_DECIMAL_COMMA = {"sv"}


@contextmanager
def use_language(lang: str | None) -> Iterator[None]:
    token = _active.set(normalize(lang))
    try:
        yield
    finally:
        _active.reset(token)


def active_language() -> str:
    return _active.get()


def local_decimal(text: str) -> str:
    """A number formatted the English way ('20.8'), with the decimal separator of the active report language."""
    return text.replace(".", ",") if _active.get() in _DECIMAL_COMMA else text


class _CommaFloat(float):
    """A float that prints with a decimal comma, also through format specs like {x:.1f}."""

    def __format__(self, spec: str) -> str:
        return float.__format__(self, spec).replace(".", ",")

    def __str__(self) -> str:
        return float.__repr__(self).replace(".", ",")


def normalize(lang: str | None) -> str:
    code = (lang or "").strip().lower()[:2]
    return code if code in LANGUAGES else DEFAULT


@cache
def catalog(lang: str) -> dict[str, str]:
    """Message id -> translation for one language (English needs none)."""
    if lang == DEFAULT:
        return {}
    path = LOCALE_DIR / lang / "LC_MESSAGES" / "messages.po"
    if not path.exists():
        log.warning("No catalog for report language %r at %s - using English", lang, path)
        return {}
    from babel.messages.pofile import read_po

    with path.open("rb") as handle:
        entries = read_po(handle, locale=_BABEL_LOCALES.get(lang, lang))
    return {(f"{m.context}\x04{m.id}" if m.context else m.id): m.string
            for m in entries if isinstance(m.id, str) and m.id and m.string and not m.fuzzy}


class Translator:
    """``tr("text {n}", n=3)`` translates the English text and fills in the values.

    A translation that cannot be filled in (a typo in a placeholder) falls back to English rather
    than failing the report."""

    def __init__(self, lang: str | None = None) -> None:
        self.lang = normalize(lang)
        self._messages = catalog(self.lang)

    def _values(self, values: dict[str, Any]) -> dict[str, Any]:
        if self.lang not in _DECIMAL_COMMA:
            return values
        return {k: _CommaFloat(v) if isinstance(v, float) else v for k, v in values.items()}

    def __call__(self, message: str, **values: Any) -> str:
        text = self._messages.get(message, message)
        if not values:
            return text
        values = self._values(values)
        try:
            return text.format(**values)
        except (KeyError, IndexError, ValueError):
            log.warning("Translation of %r into %s does not fit its values - using English", message, self.lang)
            return message.format(**values)

    def pgettext(self, context: str, message: str, **values: Any) -> str:
        """For a short English text whose translation depends on where it is used ("none" as no action
        versus no reclassifications)."""
        key = f"{context}\x04{message}"
        if key in self._messages:
            return self._messages[key].format(**self._values(values)) if values else self._messages[key]
        return self(message, **values)

    def markup(self, message: str, **values: Any) -> Markup:
        """The template ``_()``: escapes the text and the values the way autoescape would, but keeps
        markup the template passes in on purpose (``{inside}`` built with the ``strong`` filter)."""
        text = self._messages.get(message, message)
        values = self._values(values)
        try:
            return Markup.escape(text).format(**values) if values else Markup.escape(text)
        except (KeyError, IndexError, ValueError):
            log.warning("Translation of %r into %s does not fit its values - using English", message, self.lang)
            return Markup.escape(message).format(**values)

    def month(self, day: date) -> str:
        """'August 2026', 'augusti 2026'."""
        if self.lang == DEFAULT:
            return day.strftime("%B %Y")
        from babel.dates import format_date

        return format_date(day, "LLLL yyyy", locale=_BABEL_LOCALES[self.lang])

    def short_month(self, day: date) -> str:
        """'Jan 2026', 'jan. 2026'."""
        if self.lang == DEFAULT:
            return day.strftime("%b %Y")
        from babel.dates import format_date

        return format_date(day, "LLL yyyy", locale=_BABEL_LOCALES[self.lang])

    def decimal(self, text: str) -> str:
        """A number formatted the English way, with the decimal separator of the language."""
        return text.replace(".", ",") if self.lang in _DECIMAL_COMMA else text
