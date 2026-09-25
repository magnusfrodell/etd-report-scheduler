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
"""Vendor and counterparty risk.

Four views, from the strongest signal to the broadest:

1. Possibly compromised counterparties - threats from listed vendors, from
   domains with a history of clean mail (Log Export), or that ETD itself tags
   as a frequent sender for the recipient.
2. Look-alike domains - TLD swaps, homoglyphs, typos, combos and subdomain
   spoofs of own domains, vendors and established counterparties. With Log
   Export, delivered (not convicted) look-alike mail is flagged as critical.
3. New or rare senders with financial lures (BEC/scam).
4. Inventory of the listed vendors.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models import ConvictedMessage
from app.reports import repo
from app.reports.analysis import email_domain, recipients_of, reply_to_domain, technique_types
from app.reports.base import ReportContext
from app.reports.domains import FREEMAIL, find_lookalike, registrable
from app.settings_store import THREAT_VERDICTS
from app.tenant_profile import get_profile, own_domains

ESTABLISHED_MIN_DAYS = 3
HISTORY_DAYS = 120
MAX_PROTECTED_ESTABLISHED = 150
FREQUENT = {"frequent sender", "frequent sender for recipient", "frequent sender for recipient's domain"}
RARE = {"young domain", "rare sender domain", "rare sender domain for recipient", "rare sender domain for recipient domain",
        "rare sender address", "rare sender for recipient", "rare sender for recipient domain", "disposable sender address"}
FINANCIAL = {"bec", "scam"}
MAX_ROWS = 30


def _sender(m: ConvictedMessage) -> str:
    return email_domain(m.from_address or m.envelope_from)


def _techs(m: ConvictedMessage) -> set[str]:
    return {t.lower() for t in technique_types(m)}


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    tr = ctx.tr
    assert ctx.tenant is not None, "vendor_risk is a per-tenant report"
    p = ctx.period
    tid = ctx.tenant.id
    profile = get_profile(ctx.tenant)
    own, own_auto = own_domains(session, ctx.tenant)
    own_regs = {registrable(d) for d in own}
    explicit = profile["vendor_domains"]
    explicit_regs = {registrable(d) for d in explicit}

    hist_rows = repo.sender_domain_rows(session, tid, p.start_day - timedelta(days=HISTORY_DAYS), p.end_day, direction="incoming")
    has_logs = bool(hist_rows)
    history: dict[str, dict[str, Any]] = {}
    for r in hist_rows:
        reg = registrable(r.domain)
        if not reg:
            continue
        h = history.setdefault(reg, {"days_before": set(), "msgs_before": 0, "first": r.day, "last": r.day,
                                     "period_msgs": 0, "period_convicted": 0, "period_rt": 0})
        h["first"], h["last"] = min(h["first"], r.day), max(h["last"], r.day)
        clean = r.messages - r.convicted
        if r.day < p.start_day:
            if clean > 0:
                h["days_before"].add(r.day)
                h["msgs_before"] += clean
        else:
            h["period_msgs"] += r.messages
            h["period_convicted"] += r.convicted
            h["period_rt"] += r.reply_to_mismatch
    # A domain that imitates one of your own domains or a listed vendor never becomes an established
    # counterparty, however long it has delivered mail - attackers warm look-alike domains up with
    # harmless mail first. Otherwise it would be protected itself and escape look-alike detection.
    anchors = sorted(own_regs | explicit_regs)
    established = {reg: h for reg, h in history.items()
                   if len(h["days_before"]) >= ESTABLISHED_MIN_DAYS and reg not in FREEMAIL and reg not in own_regs
                   and find_lookalike(reg, anchors) is None}

    threats = [m for m in repo.convicted_messages(session, tid, p.start, p.end, verdicts=list(THREAT_VERDICTS))
               if (m.direction or "incoming") == "incoming"]
    by_reg: dict[str, list[ConvictedMessage]] = defaultdict(list)
    for m in threats:
        reg = registrable(_sender(m))
        if reg and reg not in own_regs:
            by_reg[reg].append(m)

    # 1. possibly compromised counterparties
    compromised = []
    for reg, ms in by_reg.items():
        if reg in FREEMAIL:
            continue
        frequent = [m for m in ms if _techs(m) & FREQUENT]
        reasons = []
        if reg in explicit_regs:
            reasons.append(tr("listed vendor"))
        if reg in established:
            reasons.append(tr("{clean_days} days of clean mail before", clean_days=len(established[reg]['days_before'])))
        if frequent:
            reasons.append(tr("ETD: frequent sender ({frequent_count})", frequent_count=len(frequent)))
        if not reasons:
            continue
        verdicts = Counter(m.verdict or "unknown" for m in ms)
        financial = sum(verdicts.get(v, 0) for v in FINANCIAL)
        rcpts: set[str] = set()
        for m in ms:
            rcpts |= recipients_of(m)
        other_reply_to = sum(1 for m in ms if reply_to_domain(m) and registrable(reply_to_domain(m)) != reg)
        compromised.append({
            "domain": reg, "messages": len(ms), "verdicts": dict(verdicts), "financial": financial,
            "recipients": len(rcpts), "senders": sorted({(m.from_address or m.envelope_from or "").lower() for m in ms})[:5],
            "reasons": reasons, "first": min(m.timestamp for m in ms), "last": max(m.timestamp for m in ms),
            "reply_to_elsewhere": other_reply_to, "unremediated": sum(1 for m in ms if not m.action_type),
            "severity": "critical" if financial or len(reasons) >= 2 or other_reply_to else "warning",
            "subjects": [m.subject for m in ms[:3]],
        })
    compromised.sort(key=lambda r: (r["severity"] != "critical", -r["financial"], -r["messages"]))

    # 2. look-alike domains
    top_established = sorted(established, key=lambda reg: -established[reg]["msgs_before"])[:MAX_PROTECTED_ESTABLISHED]
    protected = sorted(own_regs | explicit_regs | set(top_established))
    candidates: dict[str, dict[str, Any]] = defaultdict(lambda: {"threats": 0, "reply_to": 0, "delivered": 0, "recipients": set(), "verdicts": Counter(), "hosts": set()})
    for reg, ms in by_reg.items():
        c = candidates[reg]
        c["threats"] += len(ms)
        for m in ms:
            c["recipients"] |= recipients_of(m)
            c["verdicts"][m.verdict or "unknown"] += 1
            c["hosts"].add((_sender(m) or "").lower())
    for m in threats:
        rt = registrable(reply_to_domain(m))
        if rt and rt != registrable(_sender(m)):
            candidates[rt]["reply_to"] += 1
            candidates[rt]["hosts"].add((reply_to_domain(m) or "").lower())
    for reg, h in history.items():
        if h["period_msgs"]:
            candidates[reg]["delivered"] += h["period_msgs"] - h["period_convicted"]
    lookalikes = []
    if protected:
        for dom, c in candidates.items():
            if dom in FREEMAIL:
                continue
            # Full host names first: a subdomain spoof (brand.example.evil.net) lives in the labels
            # that registrable() strips off, so checking only the registrable domain misses it.
            hit, seen_as = None, None
            for host in sorted(c["hosts"] - {dom, ""}, key=len, reverse=True):
                hit = find_lookalike(host, protected)
                if hit is not None:
                    seen_as = host
                    break
            if hit is None:
                hit = find_lookalike(dom, protected)
            if hit is None:
                continue
            lookalikes.append({
                "domain": dom, "seen_as": seen_as, "protected": hit.protected, "method": hit.method, "distance": hit.distance,
                "threats": c["threats"], "delivered": c["delivered"], "reply_to": c["reply_to"],
                "recipients": len(c["recipients"]), "verdicts": dict(c["verdicts"]),
                "target": tr("own domain") if hit.protected in own_regs else (tr("listed vendor") if hit.protected in explicit_regs else tr("counterparty")),
                "severity": "critical" if c["delivered"] > 0 or c["reply_to"] > 0 else "warning",
            })
    lookalikes.sort(key=lambda r: (r["severity"] != "critical", -(r["delivered"] + r["threats"])))

    # 3. new or rare senders with financial lures
    rare_by_reg: dict[str, list[ConvictedMessage]] = defaultdict(list)
    for reg, ms in by_reg.items():
        first_seen_in_period = has_logs and (reg not in history or history[reg]["first"] >= p.start_day)
        for m in ms:
            if (m.verdict or "") in FINANCIAL and ((_techs(m) & RARE) or first_seen_in_period):
                rare_by_reg[reg].append(m)
    rare_rows = sorted(
        ({"domain": reg, "messages": len(ms), "verdicts": dict(Counter(m.verdict for m in ms)),
          "signals": sorted({t for m in ms for t in _techs(m) & RARE}) or ([tr("first seen this period")] if has_logs else []),
          "recipients": len({r for m in ms for r in recipients_of(m)}), "subjects": [m.subject for m in ms[:2]]}
         for reg, ms in rare_by_reg.items()),
        key=lambda r: -r["messages"],
    )

    # 4. listed vendors
    lookalike_count = Counter(r["protected"] for r in lookalikes)
    inventory = []
    for v in explicit:
        reg = registrable(v)
        h = history.get(reg, {})
        inventory.append({
            "domain": v, "clean_days_before": len(h.get("days_before", ())), "messages": h.get("period_msgs", 0),
            "convicted_logs": h.get("period_convicted", 0), "threats": len(by_reg.get(reg, [])),
            "lookalikes": lookalike_count.get(reg, 0), "reply_to_mismatch": h.get("period_rt", 0),
            "last_seen": h.get("last"),
        })

    recs: list[str] = []
    crit = [r for r in compromised if r["severity"] == "critical"]
    if crit:
        recs.append(tr("Contact {vendors} out of band: threats came from accounts you normally trust - treat as a possible compromise and hold any payment changes.", vendors=', '.join(r['domain'] for r in crit[:3])))
    delivered_la = [r for r in lookalikes if r["delivered"] > 0]
    if delivered_la:
        recs.append(tr("{delivered_la_count} look-alike domain(s) delivered mail that was NOT convicted - search and remediate in ETD and block the domains.", delivered_la_count=len(delivered_la)))
    if lookalikes:
        recs.append(tr("Add the look-alike domains to your block lists and ask the registrar or vendor to act on typosquats."))
    if rare_rows:
        recs.append(tr("{rare_financial} BEC/scam message(s) came from new or rare domains - require call-back verification for bank-detail changes.", rare_financial=sum(r['messages'] for r in rare_rows)))
    if not explicit:
        recs.append(tr("List your key suppliers and partners in the tenant's reporting profile to get look-alike and compromise monitoring for them."))
    if not has_logs:
        recs.append(tr("Enable Log Export in ETD (Administration > Business > Export Log Preferences) to learn counterparties from clean mail and to detect delivered look-alikes."))

    return {
        "has_logs": has_logs, "own_domains": sorted(own_regs), "own_auto": own_auto, "explicit": explicit,
        "established_count": len(established), "protected_count": len(protected), "threat_count": len(threats),
        "compromised": compromised[:MAX_ROWS], "lookalikes": lookalikes[:MAX_ROWS], "rare": rare_rows[:MAX_ROWS],
        "inventory": inventory, "recommendations": recs,
        "counts": {"compromised": len(compromised), "critical": len(crit), "lookalikes": len(lookalikes),
                   "delivered_lookalikes": len(delivered_la), "rare": sum(r["messages"] for r in rare_rows)},
    }
