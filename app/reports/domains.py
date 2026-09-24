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
"""Domain intelligence: organisational domains, look-alike detection and DNS posture.

* :func:`registrable` approximates the organisational domain (no public-suffix
  download needed; common multi-level suffixes are handled).
* :func:`find_lookalike` flags TLD swaps, homoglyphs, typosquats, combosquats and
  subdomain spoofs of protected domains (own domains, vendors, counterparties).
* :func:`check_domain` / :func:`check_dmarc` read SPF, DMARC (with organisational
  fallback), MTA-STS, TLS-RPT and BIMI from DNS. ETD's logs carry no
  authentication results, so posture comes from DNS. Results are cached for a
  day in ``dns_cache``; tests replace :data:`resolve_txt`.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError

from app.db import session_scope
from app.models import DnsCache, utcnow

log = logging.getLogger(__name__)

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "gmx.com", "gmx.de", "gmx.net", "web.de", "mail.com", "proton.me",
    "protonmail.com", "pm.me", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com",
    "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "hotmail.se", "live.se", "outlook.se", "yahoo.se",
    "telia.com", "hotmail.co.uk", "yahoo.co.uk", "btinternet.com", "orange.fr", "free.fr", "laposte.net", "libero.it",
    "t-online.de", "freenet.de", "seznam.cz", "wp.pl", "o2.pl", "interia.pl", "onet.pl", "mail.ee", "inbox.lv", "one.lt",
}

MULTI_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "or.jp", "ne.jp", "com.br", "com.cn", "com.mx", "com.tr", "co.za", "com.sg", "com.hk",
    "co.in", "co.kr", "com.pl", "com.es", "co.il", "com.ar", "com.co", "com.my", "com.ph", "com.tw", "com.ua", "co.th",
    "com.vn", "com.sa", "com.eg", "com.pk", "onmicrosoft.com", "mail.onmicrosoft.com",
}


def registrable(domain: str | None) -> str:
    """Organisational domain: mail.acme.co.uk -> acme.co.uk, a.b.acme.se -> acme.se."""
    if not domain:
        return ""
    d = str(domain).strip().strip("<>").strip(".").lower()
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def split_registrable(domain: str) -> tuple[str, str]:
    label, _, suffix = registrable(domain).partition(".")
    return label, suffix


# ------------------------------------------------------------------ look-alikes
_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("i", "l"), ("5", "s"),
                ("$", "s"), ("3", "e"), ("4", "a"), ("@", "a"))


def skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKD", label.lower())
    s = "".join(c for c in s if not unicodedata.combining(c))
    for a, b in _CONFUSABLES:
        s = s.replace(a, b)
    return s.replace("-", "")


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Optimal string alignment distance (Damerau-Levenshtein with adjacent swaps)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


@dataclass
class Lookalike:
    domain: str
    protected: str
    method: str
    distance: int | None = None


def find_lookalike(domain: str, protected: list[str] | set[str]) -> Lookalike | None:
    cand = (domain or "").strip().strip(".").lower()
    if not cand or "." not in cand:
        return None
    cand_reg = registrable(cand)
    prot_regs = {registrable(p) for p in protected if p}
    if cand_reg in prot_regs:
        return None
    c_label, c_suffix = split_registrable(cand)
    tokens = set(re.split(r"[-.]", cand_reg))
    for p_reg in sorted(prot_regs):
        p_label, p_suffix = split_registrable(p_reg)
        if len(p_label) < 3:
            continue
        if f".{p_reg}." in f".{cand}.":
            return Lookalike(cand, p_reg, "subdomain spoof")
        if c_label == p_label and c_suffix != p_suffix:
            return Lookalike(cand, p_reg, "TLD swap")
        if c_label != p_label and skeleton(c_label) == skeleton(p_label):
            return Lookalike(cand, p_reg, "homoglyph")
        if len(p_label) >= 5:
            limit = 1 if len(p_label) <= 6 else 2
            dist = edit_distance(c_label, p_label, limit)
            if 0 < dist <= limit:
                return Lookalike(cand, p_reg, "typosquat", dist)
        if len(p_label) >= 4 and c_label != p_label and (
            p_label in tokens or (len(p_label) >= 5 and (c_label.startswith(p_label) or c_label.endswith(p_label)))
        ):
            return Lookalike(cand, p_reg, "combosquat")
    return None


# ------------------------------------------------------------------ DNS posture
TxtResolver = Callable[[str], list[str]]


def _dns_txt(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise LookupError(f"DNS lookup failed for {name} ({exc.__class__.__name__})") from exc
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


resolve_txt: TxtResolver = _dns_txt


def _txt(name: str, prefix: str) -> list[str]:
    return [t.strip() for t in resolve_txt(name) if t.strip().lower().startswith(prefix)]


def parse_spf(records: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"present": bool(records), "record": records[0] if records else None, "all": None, "lookups": 0}
    if not records:
        return {**out, "status": "missing", "level": "critical"}
    if len(records) > 1:
        return {**out, "status": "multiple records (permerror)", "level": "critical"}
    terms = records[0].split()[1:]
    out["lookups"] = sum(1 for t in terms if re.match(r"^[+\-~?]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)", t.lower()))
    for t in terms:
        m = re.fullmatch(r"([+\-~?]?)all", t.lower())
        if m:
            out["all"] = (m.group(1) or "+") + "all"
    redirect = any(t.lower().startswith("redirect=") for t in terms)
    if out["all"] == "+all":
        status, level = "+all (anyone may send)", "critical"
    elif out["all"] in ("-all", "~all"):
        status, level = out["all"], "ok"
    elif out["all"] == "?all":
        status, level = "?all (neutral)", "warning"
    elif redirect:
        status, level = "redirect", "ok"
    else:
        status, level = "no all mechanism", "warning"
    if out["lookups"] >= 10 and level == "ok":
        status, level = f"{status}, {out['lookups']} lookups", "warning"
    return {**out, "status": status, "level": level}


def parse_dmarc(records: list[str], *, subdomain: bool = False) -> dict[str, Any]:
    base: dict[str, Any] = {"present": bool(records), "record": records[0] if records else None, "policy": None, "pct": None, "rua": False}
    if not records:
        return {**base, "status": "missing", "level": "critical"}
    if len(records) > 1:
        return {**base, "status": "multiple records (invalid)", "level": "critical"}
    tags: dict[str, str] = {}
    for part in records[0].split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()
    policy = tags.get("p", "").lower()
    if subdomain and tags.get("sp"):
        policy = tags["sp"].lower()
    try:
        pct = int(tags.get("pct", "100") or 100)
    except ValueError:
        pct = 100
    base.update(policy=policy or None, pct=pct, rua="rua" in tags)
    if policy == "reject" and pct >= 100:
        level = "ok"
    elif policy in ("reject", "quarantine"):
        level = "warning"
    else:
        level = "critical"
    status = f"p={policy or '?'}" + (f" pct={pct}" if pct < 100 else "")
    return {**base, "status": status, "level": level}


def _empty(domain: str) -> dict[str, Any]:
    return {
        "domain": domain,
        "error": None,
        "spf": {"present": False, "record": None, "all": None, "lookups": 0, "status": "unknown", "level": "warning"},
        "dmarc": {"present": False, "record": None, "policy": None, "pct": None, "rua": False, "inherited": False, "status": "unknown", "level": "warning"},
        "mta_sts": False,
        "tls_rpt": False,
        "bimi": False,
        "grade": "?",
    }


def _dmarc_lookup(domain: str) -> dict[str, Any]:
    records = _txt(f"_dmarc.{domain}", "v=dmarc1")
    inherited = False
    org = registrable(domain)
    if not records and org and org != domain:
        records = _txt(f"_dmarc.{org}", "v=dmarc1")
        inherited = bool(records)
    result = parse_dmarc(records, subdomain=inherited)
    result["inherited"] = inherited
    return result


def grade(res: dict[str, Any]) -> str:
    d, s = res["dmarc"], res["spf"]
    if d["level"] == "ok" and s["level"] == "ok" and res["mta_sts"]:
        return "A"
    if d["level"] == "ok" and s["level"] != "critical":
        return "B"
    if d.get("policy") in ("quarantine", "reject"):
        return "C"
    if d.get("present"):
        return "D"
    return "F"


def check_domain(domain: str) -> dict[str, Any]:
    out = _empty(domain)
    try:
        out["spf"] = parse_spf(_txt(domain, "v=spf1"))
        out["dmarc"] = _dmarc_lookup(domain)
        out["mta_sts"] = bool(_txt(f"_mta-sts.{domain}", "v=stsv1"))
        out["tls_rpt"] = bool(_txt(f"_smtp._tls.{domain}", "v=tlsrptv1"))
        out["bimi"] = bool(_txt(f"default._bimi.{domain}", "v=bimi1"))
    except LookupError as exc:
        out["error"] = str(exc)
        return out
    out["grade"] = grade(out)
    return out


def check_dmarc(domain: str) -> dict[str, Any]:
    out = _empty(domain)
    try:
        out["dmarc"] = _dmarc_lookup(domain)
    except LookupError as exc:
        out["error"] = str(exc)
    return out


def cached_check(domain: str, kind: str = "full", max_age_hours: int = 24) -> dict[str, Any]:
    """DNS posture for ``domain`` (``full`` or ``dmarc``), from cache when fresh. Failures are never cached."""
    domain = (domain or "").strip().strip(".").lower()
    with session_scope() as s:
        row = s.get(DnsCache, (domain, kind))
        if row is not None and row.checked_at >= utcnow() - timedelta(hours=max_age_hours):
            return dict(row.result or {})
    result = check_domain(domain) if kind == "full" else check_dmarc(domain)
    if result.get("error"):
        return result
    try:
        with session_scope() as s:
            row = s.get(DnsCache, (domain, kind))
            if row is None:
                s.add(DnsCache(domain=domain, kind=kind, checked_at=utcnow(), result=result))
            else:
                row.checked_at, row.result = utcnow(), result
    except IntegrityError:  # a concurrent report cached it first
        pass
    return result


def check_many(domains: list[str], kind: str = "dmarc", deadline_seconds: float = 30.0) -> dict[str, dict[str, Any]]:
    """Check many domains within a time budget; stop early when DNS is clearly unavailable."""
    started = time.monotonic()
    out: dict[str, dict[str, Any]] = {}
    failures = 0
    for d in domains:
        if failures >= 3:
            out[d] = {**_empty(d), "error": "DNS unavailable"}
            continue
        if time.monotonic() - started > deadline_seconds:
            out[d] = {**_empty(d), "error": "not checked (time budget)"}
            continue
        res = cached_check(d, kind)
        if res.get("error"):
            failures += 1
        out[d] = res
    return out
