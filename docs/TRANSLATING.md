# Translating the reports

Reports, their PDFs and the report e-mails can be produced in more than one language. The admin UI stays English. This page explains how the translations work, what to do after changing a report, and how to add a language.

Available today: **English** and **Swedish**.

## How it works

- The English text in the code *is* the message id. `app/locale/messages.pot` lists every report text; `app/locale/<lang>/LC_MESSAGES/messages.po` holds one language's translations. The `.po` files are read when the application starts - there is no compile step.
- In report templates: `{{ _("Threats") }}`. Values go in as named placeholders, so a translation can move them: `{{ _("{n} threat(s)", n=data.total) }}`.
- In report code: `tr = ctx.tr`, then `tr("Statistics collected")` or `tr("{days_with_data} of {days} days", days_with_data=..., days=...)`.
- Texts that the report logic also uses as keys (technique families, audit groups, attachment classes) are marked where they are defined with `N_("Impersonation")`, which changes nothing at runtime, and translated where they are shown (`{{ _(r.family) }}`). **Never compare or look up a translated text** - the logic must keep working on the English value.
- The same English word with different meanings gets a context: `tr.pgettext("action", "none")` ("no action", *ingen*) versus `tr("none")` ("no reclassifications", *inga*).
- Numbers: decimals printed by a template or passed into a translated sentence get the language's decimal separator automatically (20,8 h in Swedish). Format CSS values explicitly so they keep a point: `style="width:{{ pct|string }}%"`. Dates stay ISO (2026-09-14); month names come from Babel.
- A translation whose placeholders do not match the English text is never fatal: the report falls back to English for that sentence and the log says which one.

## After changing report texts

Refresh the template and bring the new texts into each language:

```bash
pybabel extract -F babel.cfg -k tr -k N_ -k _ -k pgettext:1c,2 --no-location --omit-header --sort-output --width 120 \
    -o app/locale/messages.pot .
pybabel update -i app/locale/messages.pot -d app/locale --no-fuzzy-matching --ignore-obsolete --width 120
```

Translate the new, empty entries (any text editor or [Poedit](https://poedit.net)), then run:

```bash
pytest tests/test_i18n.py
```

The tests fail if a report text has no translation in a language, if a translation changes a placeholder, if the template is out of date, if a translated report shows a different number than the English one, or if a table runs past the edge of the PDF page.

## Adding a language

Danish as the example:

1. `pybabel init -i app/locale/messages.pot -d app/locale -l da`
2. Translate every entry in `app/locale/da/LC_MESSAGES/messages.po`.
3. Register the language in `app/i18n.py`: `LANGUAGES` (as the language names itself, `"Dansk"`), `LANGUAGE_NAMES` (in English, `"Danish"`), `_BABEL_LOCALES` (`"da_DK"`), and `_DECIMAL_COMMA` if it writes decimals with a comma.
4. Run `pytest tests/test_i18n.py` - every language in `LANGUAGES` is tested automatically.
5. Open a few PDFs in the new language: long words must wrap, not widen tables.

## Conventions

These come from the Swedish catalog and apply to every language:

- Keep every `{placeholder}` exactly, including format specs such as `{cov:.1f}` and `{when:%Y-%m-%d %H:%M}`.
- Keep ETD's own names in English: verdicts (`bec`, `phishing`), technique names (*Brand Impersonation*), sender signals (*rare sender domain*) and protocol values (`p=reject`, `~all`). Customers see the same names in the ETD console.
- Avoid words that must agree with a number, which can be 1: write *kritiska: {critical}* rather than *{critical} kritiska* ("1 kritiska" is wrong). For nouns, the "(s)" style of the English works: *meddelande(n)*, *dag(ar)*.
- Names of the tool's own pages and settings stay as the (English) UI shows them: *Settings*, *Tenants*, *Log Export*.

Swedish glossary: threat - *hot*; verdict - *bedömning*; retro verdict - *retroaktiv bedömning*; remediate - *åtgärda*; dwell time - *uppehållstid*; mailbox - *postlåda*; convicted - *hotklassad*; look-alike domain - *förväxlingsdomän*; social engineering - *social manipulation*; impersonation - *imitation*; tenant - *tenant*.
