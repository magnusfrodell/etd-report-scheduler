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
"""Analysis helpers shared by the message-level reports.

* :func:`cluster_campaigns` groups convicted messages into campaigns by linking
  on normalised subject + sender domain, on URL domain and on attachment hash
  (union-find, so a campaign that rotates subjects but keeps its URL still
  clusters).
* :func:`attack_score` turns one message into points for the Very Attacked
  People index: verdict weight, technique severity, impersonation, retro
  delivery, missing remediation and how targeted the message was.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from app.i18n import N_, local_decimal
from app.models import ConvictedMessage
from app.settings_store import THREAT_VERDICTS

# Hosts that many unrelated campaigns share; never link on these.
GENERIC_URL_HOSTS = {
    "microsoft.com", "office.com", "sharepoint.com", "onedrive.live.com", "live.com", "outlook.com",
    "google.com", "docs.google.com", "drive.google.com", "dropbox.com", "wetransfer.com", "box.com",
    "linkedin.com", "facebook.com", "twitter.com", "x.com", "youtube.com", "apple.com", "adobe.com",
    "docusign.com", "docusign.net", "zoom.us", "cisco.com", "aka.ms", "bit.ly", "t.co",
}

VERDICT_WEIGHT = {"bec": 10, "malicious": 8, "phishing": 6, "scam": 5, "spam": 1, "graymail": 0}
SEVERITY_BONUS = {"critical": 5, "high": 4, "medium": 2, "low": 0}
IMPERSONATION_BONUS = 4
RETRO_BONUS = 3
UNREMEDIATED_BONUS = 5
TARGETED_MAX_RECIPIENTS = 3
MASS_MIN_RECIPIENTS = 20

_SUBJECT_PREFIX = re.compile(r"^\s*((re|fw|fwd|sv|vs|vb|aw|wg|tr)\s*:\s*)+", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")
_WS = re.compile(r"\s+")


# ------------------------------------------------------------- normalisers

def by_count(counter: Counter, n: int | None = None) -> list[tuple[Any, int]]:
    """Counter.most_common with a fixed order for ties (by key). Counter keeps insertion order for equal
    counts, and that order often comes from sets of strings, which Python orders differently in every
    process - so tied techniques or domains used to swap places between runs of the same report."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return items if n is None else items[:n]

def normalize_subject(subject: str | None) -> str:
    if not subject:
        return ""
    s = _SUBJECT_PREFIX.sub("", subject)
    s = _DIGITS.sub("#", s.lower())
    s = re.sub(r"[^\w#\s]", " ", s)
    return _WS.sub(" ", s).strip()[:80]


def email_domain(address: str | None) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip("<> ").lower()


def url_host(url: Any) -> str:
    if isinstance(url, dict):
        url = url.get("url") or url.get("value") or ""
    if not isinstance(url, str) or not url:
        return ""
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def attachment_hashes(msg: ConvictedMessage) -> list[str]:
    out = []
    for a in msg.attachments or []:
        if isinstance(a, dict):
            h = a.get("fileHashSha256") or a.get("sha256") or a.get("hash")
            if h:
                out.append(str(h).lower())
    return out


def recipients_of(msg: ConvictedMessage) -> set[str]:
    rcpts = {str(r).lower() for r in (msg.mailboxes or [])} | {str(r).lower() for r in (msg.to_addresses or [])}
    return {r for r in rcpts if r}


def technique_types(msg: ConvictedMessage) -> list[str]:
    out = []
    for t in msg.techniques or []:
        name = (t.get("technique") or t.get("name") or t.get("type")) if isinstance(t, dict) else t
        if name:
            out.append(str(name))
    return out


def technique_severity(msg: ConvictedMessage) -> str | None:
    best: str | None = None
    order = ["critical", "high", "medium", "low"]
    for t in msg.techniques or []:
        sev = str(t.get("severity", "")).lower() if isinstance(t, dict) else ""
        if sev in order and (best is None or order.index(sev) < order.index(best)):
            best = sev
    return best


def reply_to_domain(msg: ConvictedMessage) -> str:
    raw = msg.raw if isinstance(msg.raw, dict) else {}
    value = raw.get("replyTo")
    if isinstance(value, list):
        value = value[0] if value else None
    return email_domain(value) if isinstance(value, str) else ""


def is_threat(msg: ConvictedMessage) -> bool:
    return (msg.verdict or "") in THREAT_VERDICTS


# ---------------------------------------------------------------- scoring
SEVERITY_REASONS = {"low": N_("low severity"), "medium": N_("medium severity"), "high": N_("high severity"),
                    "critical": N_("critical severity")}


def attack_score(msg: ConvictedMessage) -> tuple[float, list[str]]:
    """Points this message contributes to each of its recipients, with the reasons."""
    reasons: list[str] = []
    score = float(VERDICT_WEIGHT.get(msg.verdict or "", 0))
    reasons.append(msg.verdict or N_("unknown"))
    sev = technique_severity(msg)
    if sev and SEVERITY_BONUS.get(sev):
        score += SEVERITY_BONUS[sev]
        reasons.append(SEVERITY_REASONS.get(sev, f"{sev} severity"))
    if any("imperson" in t.lower() or "high impact" in t.lower() for t in technique_types(msg)):
        score += IMPERSONATION_BONUS
        reasons.append(N_("impersonation"))
    if msg.is_retro_verdict:
        score += RETRO_BONUS
        reasons.append(N_("delivered before verdict"))
    if not msg.action_type:
        score += UNREMEDIATED_BONUS
        reasons.append(N_("not remediated"))
    n = len(recipients_of(msg))
    if 0 < n <= TARGETED_MAX_RECIPIENTS:
        score *= 1.5
        reasons.append(N_("targeted"))
    elif n >= MASS_MIN_RECIPIENTS:
        score *= 0.5
        reasons.append(N_("mass mailing"))
    return round(score, 1), reasons


# ------------------------------------------------------------- clustering
@dataclass
class Campaign:
    key: int
    messages: list[ConvictedMessage] = field(default_factory=list)

    @property
    def recipients(self) -> set[str]:
        out: set[str] = set()
        for m in self.messages:
            out |= recipients_of(m)
        return out

    @property
    def first_seen(self) -> datetime:
        return min(m.timestamp for m in self.messages)

    @property
    def last_seen(self) -> datetime:
        return max(m.timestamp for m in self.messages)

    @property
    def label(self) -> str:
        subjects = Counter((m.subject or "(no subject)") for m in self.messages)
        return by_count(subjects, 1)[0][0]

    @property
    def sender_domains(self) -> list[tuple[str, int]]:
        return by_count(Counter(email_domain(m.from_address or m.envelope_from) or "(unknown)" for m in self.messages), 5)

    @property
    def verdicts(self) -> dict[str, int]:
        return dict(Counter(m.verdict or "unknown" for m in self.messages))

    @property
    def techniques(self) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for m in self.messages:
            c.update(set(technique_types(m)))
        return by_count(c, 5)

    @property
    def url_hosts(self) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for m in self.messages:
            c.update({h for h in (url_host(u) for u in (m.urls or [])) if h})
        return by_count(c, 5)

    @property
    def auto_remediated(self) -> int:
        return sum(1 for m in self.messages if m.is_auto_remediated)

    @property
    def not_remediated(self) -> int:
        return sum(1 for m in self.messages if not m.action_type)

    @property
    def retro(self) -> int:
        return sum(1 for m in self.messages if m.is_retro_verdict)

    @property
    def days_active(self) -> int:
        return (self.last_seen.date() - self.first_seen.date()).days + 1

    @property
    def severity(self) -> str:
        if self.not_remediated >= 3 or ("bec" in self.verdicts and len(self.recipients) >= 3):
            return "critical"
        if self.not_remediated or len(self.recipients) >= 10:
            return "warning"
        return "ok"


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def campaign_keys(msg: ConvictedMessage) -> list[str]:
    keys: list[str] = []
    subj = normalize_subject(msg.subject)
    dom = email_domain(msg.from_address or msg.envelope_from)
    if subj:
        keys.append(f"subject:{subj}|{dom}")
    for u in msg.urls or []:
        host = url_host(u)
        if host and _registrable(host) not in GENERIC_URL_HOSTS and host not in GENERIC_URL_HOSTS:
            keys.append(f"url:{host}")
    for h in attachment_hashes(msg):
        keys.append(f"sha256:{h}")
    return keys


def cluster_campaigns(messages: list[ConvictedMessage], min_size: int = 2) -> tuple[list[Campaign], int]:
    """Return campaigns with at least ``min_size`` messages and the number of singletons."""
    uf = _UnionFind(len(messages))
    first_index: dict[str, int] = {}
    for i, msg in enumerate(messages):
        for key in campaign_keys(msg):
            if key in first_index:
                uf.union(first_index[key], i)
            else:
                first_index[key] = i
    groups: dict[int, list[ConvictedMessage]] = defaultdict(list)
    for i, msg in enumerate(messages):
        groups[uf.find(i)].append(msg)
    campaigns = [Campaign(key=k, messages=v) for k, v in groups.items() if len(v) >= min_size]
    singletons = sum(1 for v in groups.values() if len(v) < min_size)
    campaigns.sort(key=lambda c: (-len(c.recipients), -len(c.messages), c.first_seen))
    return campaigns, singletons


# ------------------------------------------------------------ statistics
def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo), 1)


def hours_between(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return round(max(0.0, (b - a).total_seconds()) / 3600.0, 2)


def fmt_hours(h: float | None) -> str:
    if h is None:
        return "–"
    if h < 1:
        return f"{int(round(h * 60))} min"
    if h < 48:
        return local_decimal(f"{h:.1f} h")
    return local_decimal(f"{h / 24:.1f} d")
