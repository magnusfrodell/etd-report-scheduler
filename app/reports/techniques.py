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
"""Techniques and business risk - plus QR codes, callback lures, attachment types
and abused legitimate services.

Groups ETD's detection techniques (https://developer.cisco.com/docs/message-search-api/techniques/)
into families, compares with the previous period and turns the findings into
concrete gateway and awareness recommendations.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.i18n import N_
from app.models import ConvictedMessage
from app.reports import repo
from app.reports.analysis import by_count, recipients_of, technique_types, url_host
from app.reports.base import ReportContext
from app.settings_store import THREAT_VERDICTS

FAMILIES: dict[str, tuple[str, ...]] = {
    N_("Impersonation"): ("brand impersonation", "domain brand impersonation", "sender domain brand impersonation",
                      "sender name brand impersonation", "sender name impersonation", "user impersonation",
                      "victim impersonation", "unicode masquerade", "sender name mismatch", "external admin",
                      "external support", "fake reply"),
    N_("Social engineering"): ("call to action", "urgency", "data input request", "request for credentials",
                           "request for contact details", "request to open attachment", "link visit request",
                           "references to cryptocurrency", "inferred greeting", "reply", "username in subject",
                           "email address in subject", "suspicious button"),
    N_("Malicious link"): ("malicious url", "link masquerade", "open redirect", "shortened url", "reused url",
                       "victim specific url", "low-reputation tld", "qr code"),
    N_("Malicious attachment"): ("malicious html attachment", "masqueraded file extension"),
    N_("Evasion"): ("hidden text", "hidden text injection", "image-only email", "email without text"),
    N_("Sender reputation"): ("disposable sender address", "rare sender address", "rare sender domain",
                          "rare sender domain for recipient", "rare sender domain for recipient domain",
                          "rare sender for recipient", "rare sender for recipient domain", "sender ip reputation",
                          "sender domain reputation", "suspicious sender address", "suspicious sender domain",
                          "young domain", "low content reputation"),
    N_("Known relationship"): ("frequent sender", "frequent sender for recipient", "frequent sender for recipient's domain",
                           "internal email"),
}
FAMILY_NOTES = {
    N_("Impersonation"): N_("Pretends to be a brand, colleague or the victim. Maintain High Impact Personnel and brand lists in ETD."),
    N_("Social engineering"): N_("Pressure and requests - credentials, contact details, opening attachments."),
    N_("Malicious link"): N_("Link-borne attacks incl. redirects, shorteners and QR codes."),
    N_("Malicious attachment"): N_("HTML smuggling and disguised file types."),
    N_("Evasion"): N_("Hidden text and image-only mail built to fool filters."),
    N_("Sender reputation"): N_("New, rare or disposable senders and poor infrastructure reputation."),
    N_("Known relationship"): N_("Threats from senders the recipient normally talks to - often a compromised partner account."),
}
_FAMILY_OF = {name: fam for fam, names in FAMILIES.items() for name in names}

ATTACHMENT_CLASSES: tuple[tuple[str, frozenset[str]], ...] = (
    (N_("HTML / SVG"), frozenset({"html", "htm", "shtml", "xhtml", "svg", "svgz", "mht", "mhtml"})),
    (N_("Archive / disk image"), frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "arj", "cab", "iso", "img", "vhd", "vhdx", "z"})),
    (N_("Script / shortcut"), frozenset({"js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "bat", "cmd", "ps1", "psm1", "url", "reg", "jar", "scf", "inf"})),
    (N_("Executable / installer"), frozenset({"exe", "dll", "msi", "msix", "appx", "appxbundle", "com", "pif", "scr", "cpl", "xll"})),
    (N_("Office with macros / legacy"), frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "doc", "xls", "ppt", "rtf"})),
    (N_("Office"), frozenset({"docx", "xlsx", "pptx", "odt", "ods", "odp"})),
    (N_("PDF"), frozenset({"pdf"})),
    (N_("OneNote"), frozenset({"one", "onepkg"})),
    (N_("Calendar invite"), frozenset({"ics", "vcs"})),
    (N_("Image"), frozenset({"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "heic"})),
)
RISKY_CLASSES = {"HTML / SVG", "Archive / disk image", "Script / shortcut", "Executable / installer", "Office with macros / legacy", "OneNote"}
_DECOYS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}
_CONTENT_TYPES = {
    "text/html": "html", "image/svg+xml": "svg", "application/pdf": "pdf", "application/zip": "zip",
    "application/x-zip-compressed": "zip", "application/vnd.rar": "rar", "application/x-rar-compressed": "rar",
    "application/vnd.ms-onenote": "one", "text/calendar": "ics", "application/x-msdownload": "exe",
    "application/javascript": "js", "application/x-iso9660-image": "iso",
}

ABUSED_SERVICES: dict[str, tuple[str, ...]] = {
    N_("SharePoint / OneDrive"): ("sharepoint.com", "onedrive.live.com", "1drv.ms"),
    N_("Microsoft Forms / Sway / Dynamics"): ("forms.office.com", "forms.microsoft.com", "sway.cloud.microsoft", "sway.office.com", "dynamics.com"),
    N_("Azure hosting"): ("blob.core.windows.net", "web.core.windows.net", "azurewebsites.net", "azureedge.net", "azurefd.net"),
    N_("Google services"): ("docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "storage.googleapis.com", "firebaseapp.com", "web.app", "script.google.com"),
    N_("Cloudflare"): ("pages.dev", "workers.dev", "r2.dev", "trycloudflare.com"),
    N_("Developer hosting"): ("github.io", "githubusercontent.com", "netlify.app", "vercel.app", "glitch.me", "replit.app", "onrender.com", "herokuapp.com", "fly.dev", "surge.sh"),
    N_("Site builders"): ("webflow.io", "wixsite.com", "weebly.com", "squarespace.com", "wordpress.com", "blogspot.com", "godaddysites.com", "framer.app", "carrd.co", "notion.site", "canva.site", "yolasite.com"),
    N_("File sharing"): ("dropbox.com", "dropboxusercontent.com", "wetransfer.com", "we.tl", "box.com", "mega.nz", "mediafire.com"),
    N_("Forms / surveys"): ("typeform.com", "jotform.com", "surveymonkey.com", "formstack.com", "hsforms.com", "paperform.co"),
    N_("Tunnels / IPFS"): ("ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "w3s.link"),
    N_("URL shorteners"): ("bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "t.ly", "shorturl.at", "rb.gy", "s.id", "buff.ly", "goo.gl"),
}
LURE_TECHNIQUES = {"call to action", "urgency", "request for contact details", "brand impersonation",
                   "sender name brand impersonation", "sender domain brand impersonation", "references to cryptocurrency",
                   "image-only email", "email without text"}
MAX_SAMPLES = 10
PAYLOAD_KINDS = (N_("Link only"), N_("Attachment only"), N_("Link and attachment"), N_("No link or attachment"))


def family_of(technique: str) -> str:
    return _FAMILY_OF.get(technique.strip().lower(), N_("Other"))


def classify_extension(ext: str) -> str:
    for name, exts in ATTACHMENT_CLASSES:
        if ext in exts:
            return name
    return N_("Other")


def attachments_of(msg: ConvictedMessage) -> list[dict[str, Any]]:
    out = []
    for a in msg.attachments or []:
        if isinstance(a, str):
            name, ctype = a, ""
        elif isinstance(a, dict):
            name = str(a.get("fileName") or a.get("filename") or a.get("name") or "")
            ctype = str(a.get("contentType") or a.get("mimeType") or a.get("fileType") or "").lower()
        else:
            continue
        parts = name.lower().rsplit(".", 2)
        ext = parts[-1] if len(parts) > 1 else _CONTENT_TYPES.get(ctype, "")
        cls = classify_extension(ext)
        double = len(parts) == 3 and parts[1] in _DECOYS and ext != parts[1] and cls in RISKY_CLASSES
        out.append({"name": name or "(unnamed)", "ext": ext, "class": cls, "double": double})
    return out


def service_of(host: str) -> str | None:
    for name, suffixes in ABUSED_SERVICES.items():
        for s in suffixes:
            if host == s or host.endswith("." + s):
                return name
    return None


def hosts_of(msg: ConvictedMessage) -> set[str]:
    return {h for h in (url_host(u) for u in (msg.urls or [])) if h}


def has_qr(msg: ConvictedMessage) -> bool:
    if any("qr code" in t.lower() for t in technique_types(msg)):
        return True
    raw = msg.raw if isinstance(msg.raw, dict) else {}
    for u in raw.get("urlMetadata") or []:
        if not isinstance(u, dict):
            continue
        for k, v in u.items():
            key = str(k).lower()
            if "qr" in key and v not in (None, False, "", 0):
                return True
            if isinstance(v, str) and "qr" in v.lower() and key in ("source", "type", "origin", "sourcetype", "urlsource", "location"):
                return True
    return False


def payload_kind(msg: ConvictedMessage) -> str:
    link, att = bool(hosts_of(msg)), bool(attachments_of(msg))
    if link and att:
        return PAYLOAD_KINDS[2]
    if link:
        return PAYLOAD_KINDS[0]
    if att:
        return PAYLOAD_KINDS[1]
    return PAYLOAD_KINDS[3]


def is_text_only_lure(msg: ConvictedMessage) -> bool:
    """Scam/phishing/BEC with no link and at most PDF or image attachments - the shape of callback
    phishing (TOAD) and payload-less BEC. ETD has no phone-number technique, so this is a heuristic."""
    if (msg.verdict or "") not in ("scam", "phishing", "bec") or hosts_of(msg):
        return False
    return {a["class"] for a in attachments_of(msg)} <= {"PDF", "Image"}


def _pct(a: float, b: float) -> float | None:
    return round(a / b * 100, 1) if b else None


def _sample(m: ConvictedMessage) -> dict[str, Any]:
    return {"timestamp": m.timestamp, "from": m.from_address or m.envelope_from, "subject": m.subject, "verdict": m.verdict,
            "to": sorted(recipients_of(m))[:3]}


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "techniques is a per-tenant report"
    p = ctx.period
    msgs = repo.convicted_messages(session, ctx.tenant.id, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    prev = repo.convicted_messages(session, ctx.tenant.id, p.previous_start, p.previous_end, verdicts=list(THREAT_VERDICTS))
    total = len(msgs)

    tech: Counter[str] = Counter()
    tech_rcpts: dict[str, set[str]] = defaultdict(set)
    fam: Counter[str] = Counter()
    fam_rcpts: dict[str, set[str]] = defaultdict(set)
    for m in msgs:
        names = {t.strip() for t in technique_types(m) if t and t.strip()}
        rcpts = recipients_of(m)
        for n in names:
            tech[n] += 1
            tech_rcpts[n] |= rcpts
        for f in {family_of(n) for n in names}:
            fam[f] += 1
            fam_rcpts[f] |= rcpts
    prev_tech: Counter[str] = Counter()
    prev_fam: Counter[str] = Counter()
    for m in prev:
        names = {t.strip() for t in technique_types(m) if t and t.strip()}
        prev_tech.update(names)
        prev_fam.update({family_of(n) for n in names})

    technique_rows = [
        {"name": n, "family": family_of(n), "messages": c, "recipients": len(tech_rcpts[n]), "previous": prev_tech.get(n, 0),
         "delta": c - prev_tech.get(n, 0), "new": n not in prev_tech}
        for n, c in by_count(tech, 30)
    ]
    family_rows = [
        {"family": f, "messages": fam.get(f, 0), "recipients": len(fam_rcpts[f]), "previous": prev_fam.get(f, 0),
         "share": _pct(fam.get(f, 0), total), "note": FAMILY_NOTES.get(f, "")}
        for f in [*FAMILIES, tr("Other")]
        if fam.get(f) or prev_fam.get(f)
    ]
    family_rows.sort(key=lambda r: -r["messages"])

    risk = Counter(m.business_risk for m in msgs if m.business_risk)
    prev_risk = Counter(m.business_risk for m in prev if m.business_risk)
    risk_rows = [{"risk": r, "messages": c, "previous": prev_risk.get(r, 0), "share": _pct(c, total)} for r, c in by_count(risk)]

    payload = Counter(payload_kind(m) for m in msgs)
    prev_payload = Counter(payload_kind(m) for m in prev)
    payload_rows = [{"kind": tr(k), "messages": payload.get(k, 0), "previous": prev_payload.get(k, 0), "share": _pct(payload.get(k, 0), total)}
                    for k in PAYLOAD_KINDS]

    qr = [m for m in msgs if has_qr(m)]
    lures = [m for m in msgs if is_text_only_lure(m)]
    callback = [m for m in lures if m.verdict != "bec"]
    bec_nopayload = [m for m in lures if m.verdict == "bec"]

    att_class: Counter[str] = Counter()
    att_ext: Counter[str] = Counter()
    double: list[dict[str, Any]] = []
    masqueraded = html_attachment = messages_with_attachments = 0
    for m in msgs:
        atts = attachments_of(m)
        messages_with_attachments += 1 if atts else 0
        for a in atts:
            att_class[a["class"]] += 1
            if a["ext"]:
                att_ext[a["ext"]] += 1
            if a["double"] and len(double) < MAX_SAMPLES:
                double.append({"name": a["name"], **_sample(m)})
        names = {t.lower() for t in technique_types(m)}
        masqueraded += 1 if "masqueraded file extension" in names else 0
        html_attachment += 1 if "malicious html attachment" in names else 0
    attachment_rows = [{"class": c, "count": n, "risky": c in RISKY_CLASSES} for c, n in by_count(att_class)]

    services: Counter[str] = Counter()
    service_hosts: dict[str, Counter[str]] = defaultdict(Counter)
    tlds: Counter[str] = Counter()
    shortened = low_rep_tld = 0
    for m in msgs:
        hosts = hosts_of(m)
        names = {t.lower() for t in technique_types(m)}
        for h in hosts:
            svc = service_of(h)
            if svc:
                services[svc] += 1
                service_hosts[svc][h] += 1
            tlds[h.rsplit(".", 1)[-1]] += 1
        if "shortened url" in names or any(service_of(h) == "URL shorteners" for h in hosts):
            shortened += 1
        low_rep_tld += 1 if "low-reputation tld" in names else 0
    service_rows = [{"service": s, "urls": n, "hosts": [h for h, _ in by_count(service_hosts[s], 3)]} for s, n in by_count(services)]
    known_relationship = fam.get("Known relationship", 0)

    recs: list[str] = []
    risky_att = sum(att_class[c] for c in RISKY_CLASSES)
    if att_class.get("HTML / SVG"):
        recs.append(tr("Block or strip .html/.htm/.svg attachments at the gateway - {html_svg} HTML/SVG attachment(s) carried threats (HTML smuggling, SVG phishing).", html_svg=att_class['HTML / SVG']))
    if att_class.get("Script / shortcut") or att_class.get("Executable / installer"):
        recs.append(tr("Block script, shortcut and executable attachments outright; they have no business use in mail."))
    if att_class.get("Archive / disk image"):
        recs.append(tr("Inspect or quarantine archives and disk images (.zip/.iso/.img) - they are used to slip executables past filters."))
    if double or masqueraded:
        recs.append(tr("{disguised} attachment(s) disguised their real type (double extension or masqueraded extension) - show file extensions on endpoints.", disguised=len(double) + masqueraded))
    if qr:
        recs.append(tr("{qr_count} threat(s) used QR codes, which move the click to unmanaged phones - include quishing in awareness training.", qr_count=len(qr)))
    if callback:
        recs.append(tr("{callback_count} text-only lure(s) without a link look like callback phishing - teach finance and the service desk to verify phone numbers independently.", callback_count=len(callback)))
    if bec_nopayload:
        recs.append(tr("{bec_nopayload_count} BEC message(s) carried no payload at all - payment-change requests need out-of-band verification.", bec_nopayload_count=len(bec_nopayload)))
    if known_relationship:
        recs.append(tr("{known_relationship} threat(s) came from senders ETD recognises as regular correspondents - see the Vendor risk report for possibly compromised partners.", known_relationship=known_relationship))
    if fam.get("Impersonation"):
        recs.append(tr("Impersonation in {impersonation_threats} threat(s) - keep High Impact Personnel and brand lists up to date in ETD.", impersonation_threats=fam['Impersonation']))
    if service_rows:
        top = service_rows[0]
        service_name = top["service"]
        recs.append(tr("Most-abused legitimate service: {service} ({urls} URL(s)) - consider stricter handling or sandboxing of links to it.", service=tr(service_name), urls=top['urls']))

    return {
        "total": total,
        "previous_total": len(prev),
        "with_techniques": sum(1 for m in msgs if technique_types(m)),
        "distinct_techniques": len(tech),
        "technique_rows": technique_rows,
        "new_techniques": [r["name"] for r in technique_rows if r["new"]],
        "family_rows": family_rows,
        "risk_rows": risk_rows,
        "payload_rows": payload_rows,
        "qr_count": len(qr),
        "previous_qr": sum(1 for m in prev if has_qr(m)),
        "qr_samples": [_sample(m) for m in qr[:MAX_SAMPLES]],
        "callback_count": len(callback),
        "bec_nopayload_count": len(bec_nopayload),
        "lure_samples": [_sample(m) for m in lures[:MAX_SAMPLES]],
        "attachment_rows": attachment_rows,
        "top_extensions": by_count(att_ext, 10),
        "messages_with_attachments": messages_with_attachments,
        "risky_attachments": risky_att,
        "double_extensions": double,
        "masqueraded": masqueraded,
        "html_attachment": html_attachment,
        "service_rows": service_rows,
        "top_tlds": by_count(tlds, 8),
        "shortened": shortened,
        "low_rep_tld": low_rep_tld,
        "known_relationship": known_relationship,
        "recommendations": recs,
    }
