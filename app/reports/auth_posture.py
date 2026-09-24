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
"""Authentication posture.

ETD's Log Export carries Return-Path and Reply-To but no SPF/DKIM/DMARC results,
so the report combines:

* DNS posture of the tenant's own domains (SPF, DMARC, MTA-STS, TLS-RPT, BIMI);
* spoofing of those domains in convicted mail and - with Log Export - in all
  incoming mail;
* Return-Path and Reply-To misalignment across incoming mail (Log Export);
* the DMARC policy published by the domains that sent threats, weighted by
  message count. A policy published today is not the authentication result of a
  message - ETD does not expose per-message SPF/DKIM/DMARC results - so the report
  only says that the sending domain's DMARC did not keep those threats out.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.reports import domains as dns_posture
from app.reports import repo
from app.reports.analysis import email_domain
from app.reports.base import ReportContext
from app.reports.domains import FREEMAIL, registrable
from app.settings_store import THREAT_VERDICTS
from app.tenant_profile import own_domains

MAX_OWN = 10
MAX_THREAT_DOMAINS = 40
POLICY_ORDER = ("reject", "quarantine", "none", "missing", "unknown")


def _pct(a: float, b: float) -> float | None:
    return round(a / b * 100, 1) if b else None


def policy_bucket(result: dict[str, Any]) -> str:
    if result.get("error"):
        return "unknown"
    dmarc = result.get("dmarc") or {}
    if not dmarc.get("present"):
        return "missing"
    policy = (dmarc.get("policy") or "").lower()
    return policy if policy in ("reject", "quarantine", "none") else "unknown"


def own_domain_recommendations(checks: list[dict[str, Any]], spoofed_by_domain: Counter[str]) -> list[str]:
    recs: list[str] = []
    for c in checks:
        d, dmarc, spf = c["domain"], c["dmarc"], c["spf"]
        if c.get("error"):
            recs.append(f"{d}: DNS could not be checked ({c['error']}).")
            continue
        spoofs = spoofed_by_domain.get(registrable(d), 0)
        tail = f" Attackers used this domain in the From: header {spoofs} time(s) this period." if spoofs else ""
        if not dmarc["present"]:
            recs.append(f"{d}: publish a DMARC record (start with p=none and rua reporting, then move to p=reject).{tail}")
        elif dmarc["policy"] == "none":
            recs.append(f"{d}: DMARC is p=none and offers no protection - move towards p=quarantine and p=reject.{tail}")
        elif dmarc["level"] == "warning":
            recs.append(f"{d}: finish DMARC enforcement ({dmarc['status']} -> p=reject, pct=100).{tail}")
        if dmarc["present"] and not dmarc.get("rua"):
            recs.append(f"{d}: add rua= to the DMARC record so you receive aggregate reports.")
        if spf["level"] == "critical":
            recs.append(f"{d}: fix SPF ({spf['status']}).")
        elif spf["level"] == "warning":
            recs.append(f"{d}: tighten SPF ({spf['status']}) - end with -all or ~all and stay under 10 DNS lookups.")
        if not c["mta_sts"] or not c["tls_rpt"]:
            recs.append(f"{d}: publish MTA-STS and TLS-RPT so inbound TLS cannot be downgraded silently.")
    return recs


def build(session: Session, ctx: ReportContext) -> dict[str, Any]:
    assert ctx.tenant is not None, "auth_posture is a per-tenant report"
    p = ctx.period
    tid = ctx.tenant.id
    own, own_auto = own_domains(session, ctx.tenant)
    own_regs = {registrable(d) for d in own}
    own_checks = [dns_posture.cached_check(d, "full") for d in own[:MAX_OWN]]

    threats = repo.convicted_messages(session, tid, p.start, p.end, verdicts=list(THREAT_VERDICTS))
    spoofed = [m for m in threats if (m.direction or "incoming") == "incoming"
               and registrable(email_domain(m.from_address or m.envelope_from)) in own_regs]
    spoofed_by_domain = Counter(registrable(email_domain(m.from_address or m.envelope_from)) for m in spoofed)

    rows = repo.sender_domain_rows(session, tid, p.start_day, p.end_day)
    incoming = [r for r in rows if r.direction == "incoming"]
    total_in = sum(r.messages for r in incoming)
    conv_in = sum(r.convicted for r in incoming)
    rt_all = sum(r.reply_to_mismatch for r in incoming)
    rt_conv = sum(r.convicted_reply_to_mismatch for r in incoming)
    claimed_own = [r for r in incoming if registrable(r.domain) in own_regs]
    alignment = {
        "incoming": total_in,
        "convicted": conv_in,
        "rp_mismatch_pct": _pct(sum(r.rp_mismatch for r in incoming), total_in),
        "reply_to_pct_threats": _pct(rt_conv, conv_in),
        "reply_to_pct_clean": _pct(rt_all - rt_conv, total_in - conv_in),
        "claimed_own": sum(r.messages for r in claimed_own),
        "claimed_own_convicted": sum(r.convicted for r in claimed_own),
    }

    sender_counts: Counter[str] = Counter()
    for m in threats:
        d = email_domain(m.from_address or m.envelope_from)
        if d and registrable(d) not in own_regs:
            sender_counts[d] += 1
    top = sender_counts.most_common(MAX_THREAT_DOMAINS)
    results = dns_posture.check_many([d for d, _ in top], kind="dmarc")
    by_policy: Counter[str] = Counter()
    domains_by_policy: dict[str, list[tuple[str, int]]] = {k: [] for k in POLICY_ORDER}
    for d, n in top:
        bucket = policy_bucket(results.get(d, {}))
        by_policy[bucket] += n
        domains_by_policy[bucket].append((d, n))
    checked = sum(n for _, n in top)
    enforcing = by_policy["reject"] + by_policy["quarantine"]
    freemail = sum(n for d, n in top if registrable(d) in FREEMAIL)

    recs = own_domain_recommendations(own_checks, spoofed_by_domain)
    if spoofed and all(c["dmarc"]["level"] == "ok" for c in own_checks if not c.get("error")) and own_checks:
        recs.append("Threats using your own domains as sender arrived although your DMARC policy is p=reject - check paths that skip authentication, "
                    "e.g. Microsoft 365 Direct Send or inbound connectors that trust the gateway.")
    if checked and enforcing:
        recs.append(f"{_pct(enforcing, checked)} % of the checked threats came from domains that publish an enforcing DMARC policy today. "
                    "ETD does not show whether each message passed DMARC, and a policy may have changed since delivery, but the sending "
                    "domain's DMARC did not keep these threats out - content and behaviour detection is what stops them.")
    if alignment["reply_to_pct_threats"] and alignment["reply_to_pct_clean"] is not None and alignment["reply_to_pct_threats"] > 2 * (alignment["reply_to_pct_clean"] or 0):
        recs.append("A Reply-To pointing to another domain is far more common in threats than in clean mail - a strong BEC signal to train on.")
    if not rows:
        recs.append("Enable Log Export in ETD to see spoofing and Return-Path/Reply-To alignment across all incoming mail, not only threats.")

    return {
        "own_checks": own_checks,
        "own_auto": own_auto,
        "enforcing_own": sum(1 for c in own_checks if c["dmarc"]["level"] == "ok"),
        "spoofed_count": len(spoofed),
        "spoof_verdicts": dict(Counter(m.verdict or "unknown" for m in spoofed)),
        "spoof_samples": [{"timestamp": m.timestamp, "from": m.from_address, "to": sorted(m.mailboxes or m.to_addresses or [])[:3],
                           "subject": m.subject, "verdict": m.verdict} for m in spoofed[:10]],
        "has_logs": bool(rows),
        "alignment": alignment,
        "threat_domains_checked": len(top),
        "threat_messages_checked": checked,
        "threat_total": len(threats),
        "policy_rows": [{"policy": k, "messages": by_policy.get(k, 0), "share": _pct(by_policy.get(k, 0), checked),
                         "domains": domains_by_policy[k][:6]} for k in POLICY_ORDER if by_policy.get(k)],
        "threat_enforcing_pct": _pct(enforcing, checked),
        "freemail_pct": _pct(freemail, checked),
        "recommendations": recs,
    }
