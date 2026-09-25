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
"""The demo scenario: four Nordic and Baltic tenants, each with a story the reports can tell.

All names, domains and addresses are invented and use the reserved .example top-level domain.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DemoTenant:
    key: str
    name: str
    domain: str
    group: str
    size: int  # messages scanned on a weekday
    employees: tuple[str, ...]
    vips: tuple[str, ...] = ("ceo", "cfo")
    vendors: tuple[str, ...] = ()
    contacts: tuple[str, ...] = ()
    region: str = "de"
    compromised_vendor: str | None = None  # a supplier whose real accounts send payment fraud
    lookalike: str | None = None  # a look-alike of the tenant's domain that delivers phishing
    internal_compromise: str | None = None  # an own mailbox that sends phishing out
    slow_remediation: bool = False  # retro verdicts cleaned up late, some never
    log_export_broken: bool = False  # Log Export answers 503 - for the Data quality page
    dmarc: str = "reject"  # reject | quarantine | none | "" (no record)
    mta_sts: bool = False
    threat_rate: float = 0.0016  # convicted messages per scanned message

    @property
    def client_id(self) -> str:
        return f"demo-{self.key}"


TENANTS: tuple[DemoTenant, ...] = (
    DemoTenant(
        key="nordic-freight", name="Nordic Freight AB", domain="nordicfreight.example", group="Premium", size=14000,
        employees=("anna.lindqvist", "erik.johansson", "sofia.berg", "lars.nilsson", "maja.holm", "johan.ek", "karin.sundberg",
                   "oskar.dahl", "elin.forsberg", "nils.wikstrom", "ida.lund", "per.sjoberg"),
        vips=("ceo", "cfo", "ap"), vendors=("baltic-shipping.example", "fuelcard.example", "portlogistics.example"),
        contacts=("ciso@nordicfreight.example", "it-security@nordicfreight.example"),
        compromised_vendor="baltic-shipping.example", lookalike="nordicfreigth.example", dmarc="reject", mta_sts=True,
    ),
    DemoTenant(
        key="baltic-pharma", name="Baltic Pharma AS", domain="balticpharma.example", group="Premium", size=9000,
        employees=("kristjan.tamm", "liis.kask", "martin.saar", "kadri.mets", "janis.berzins", "ieva.ozola", "tomas.kazlauskas",
                   "rasa.petraitiene", "andres.rebane", "maarja.pold"),
        vips=("ceo", "cfo", "research.director"), vendors=("labsupply.example", "cro-partners.example"),
        contacts=("security@balticpharma.example",), lookalike="baltlcpharma.example", slow_remediation=True, dmarc="quarantine",
    ),
    DemoTenant(
        key="helios-energy", name="Helios Energy Oy", domain="heliosenergy.example", group="Standard", size=6000,
        employees=("jari.virtanen", "anna.korhonen", "mikko.nieminen", "laura.makinen", "juha.heikkinen", "sanna.koskinen",
                   "timo.laine", "elina.jarvinen"),
        vendors=("gridparts.example",), contacts=("soc@heliosenergy.example",), internal_compromise="jari.virtanen", dmarc="none",
    ),
    DemoTenant(
        key="aurora-retail", name="Aurora Retail ApS", domain="auroraretail.example", group="Standard", size=4000,
        employees=("mette.hansen", "rasmus.nielsen", "camilla.jensen", "frederik.pedersen", "louise.andersen", "mikkel.larsen"),
        vips=("ceo",), vendors=("paymentsolutions.example",), log_export_broken=True, dmarc="",
    ),
)
BY_CLIENT_ID = {t.client_id: t for t in TENANTS}

ANALYSTS = {  # ETD audit logs name users by id only - the demo profiles label them
    "5f94fb97-742b-446a-90f8-d0c49a958e5b": "Anna Analyst (partner SOC)",
    "0c7d2a41-9e3b-4f6a-8d15-2b9e7c4a1f03": "Erik Engineer (partner SOC)",
}


@dataclass(frozen=True)
class Threat:
    key: str
    verdict: str  # phishing | malicious | bec | scam
    risk: str
    techniques: tuple[str, ...]
    sender: str  # may contain {n} (0-9) and {ref}
    subject: str
    url: str | None = None
    attachment: tuple[str, str] | None = None  # (file name, content type)
    weight: int = 10
    vip_bias: bool = False
    extra: dict = field(default_factory=dict, hash=False, compare=False)


THREATS: tuple[Threat, ...] = (
    Threat("m365-login", "phishing", "credential harvesting", ("Malicious URL", "Link Masquerade", "Request for Credentials", "Brand Impersonation"),
           "no-reply@m365-account-security{n}.example", "Action required: your mailbox password expires today",
           url="https://login-m365-verify{n}.example/reset", weight=16),
    Threat("parcel-qr", "phishing", "credential harvesting", ("QR Code", "Brand Impersonation", "Urgency"),
           "notify@parcel-track{n}.example", "Your parcel is held - scan the code to pay the customs fee",
           attachment=("customs_notice.pdf", "application/pdf"), weight=9),
    Threat("invoice-html", "malicious", "malware", ("Malicious HTML Attachment", "Request to Open Attachment", "Rare Sender Domain"),
           "accounts@invoice-portal{n}.example", "Remittance advice {ref}", attachment=("Remittance_{ref}.html", "text/html"), weight=8),
    Threat("iso-drop", "malicious", "malware", ("Masqueraded File Extension", "Rare Sender Address"),
           "hr-services@payroll-update{n}.example", "Updated salary review 2026", attachment=("salary_review.pdf.iso", "application/octet-stream"), weight=3),
    Threat("callback", "scam", "fraud", ("Brand Impersonation", "Call to Action", "Urgency"),
           "billing@secure-renewals{n}.example", "Your subscription has been renewed - order {ref}",
           attachment=("receipt_{ref}.pdf", "application/pdf"), weight=6),
    Threat("gift-card", "bec", "fraud", ("User Impersonation", "Sender Name Impersonation", "Urgency", "Reply"),
           "ceo.private{n}@freemail.example", "Quick favour - are you at your desk?", weight=4, vip_bias=True),
    Threat("crypto", "scam", "fraud", ("References to Cryptocurrency", "Rare Sender Address", "Call to Action"),
           "desk@btc-yield{n}.example", "Guaranteed 18 % monthly return - reserved for you", url="https://btc-yield{n}.example/join", weight=3),
    Threat("docusign", "phishing", "credential harvesting", ("Brand Impersonation", "Malicious URL", "Shortened URL", "Suspicious Button"),
           "dse@docs-sign{n}.example", "Please review and sign: Agreement {ref}", url="https://bit-ly{n}.example/{ref}", weight=7, vip_bias=True),
)

DMARC_OF_VENDORS = {  # vendor domains publish DMARC too - some enforce, some do not
    "baltic-shipping.example": "reject", "fuelcard.example": "none", "portlogistics.example": "quarantine",
    "labsupply.example": "reject", "cro-partners.example": "none", "gridparts.example": "reject", "paymentsolutions.example": "reject",
}


def dns_records() -> dict[str, list[str]]:
    """TXT records for the demo domains; everything else under .example has none."""
    records: dict[str, list[str]] = {}
    for t in TENANTS:
        records[t.domain] = ["v=spf1 include:spf.protection.outlook.com -all"]
        if t.dmarc:
            records[f"_dmarc.{t.domain}"] = [f"v=DMARC1; p={t.dmarc}; rua=mailto:dmarc@{t.domain}"]
        if t.mta_sts:
            records[f"_mta-sts.{t.domain}"] = ["v=STSv1; id=20260101T000000"]
            records[f"_smtp._tls.{t.domain}"] = [f"v=TLSRPTv1; rua=mailto:tlsrpt@{t.domain}"]
    for domain, policy in DMARC_OF_VENDORS.items():
        records[domain] = ["v=spf1 include:_spf.mailhost.example ~all"]
        records[f"_dmarc.{domain}"] = [f"v=DMARC1; p={policy}"]
    return records


def generic_tenant(client_id: str, name: str) -> DemoTenant:
    """A plain scenario for tenants added while the demo runs."""
    slug = re.sub(r"[^a-z0-9]+", "", name.lower())[:20] or "tenant"
    size = 3000 + int(hashlib.sha256(client_id.encode()).hexdigest()[:4], 16) % 6000
    return DemoTenant(key=f"x-{slug}", name=name, domain=f"{slug}.example", group="", size=size,
                      employees=("alex.morgan", "sam.lee", "kim.berg", "robin.holm", "jo.nyberg"))
