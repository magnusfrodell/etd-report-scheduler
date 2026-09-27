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
"""The headline of a rendered report, for a chat message: title, tenant and period, status and KPI tiles.

It is read from the report's own HTML, so a chat message always shows the same numbers, in the same
language, as the report it links to - no second summary per report to keep in step."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

STATUSES = ("critical", "warning", "ok", "unknown")


@dataclass
class ReportSummary:
    title: str = ""
    meta: str = ""  # tenant · period · generated
    status: str | None = None  # ok | warning | critical | unknown - the class of the first status chip in a heading
    status_text: str = ""  # the chip's (translated) text
    facts: list[tuple[str, str]] = field(default_factory=list)  # (label, value · detail) from the first KPI row
    lead: str = ""  # the first paragraph under a heading, for reports without KPI tiles


class _Reader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out = ReportSummary()
        self.stack: list[tuple[str, set[str]]] = []
        self.skip = 0
        self.target: str | None = None
        self.target_depth = 0
        self.text: list[str] = []
        self.kpi: dict[str, str] | None = None
        self.in_kpis = False
        self.kpis_done = False
        self.seen_h2 = False

    def _start_capture(self, target: str) -> None:
        self.target, self.target_depth, self.text = target, len(self.stack), []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = set((dict(attrs).get("class") or "").split())
        if tag in ("style", "script", "title"):
            self.skip += 1
        self.stack.append((tag, classes))
        if self.target is not None:
            return
        if tag == "h1" and not self.out.title:
            self._start_capture("title")
        elif tag == "div" and "meta" in classes and not self.out.meta:
            self._start_capture("meta")
        elif tag == "table" and "kpis" in classes and not self.kpis_done:
            self.in_kpis = True
        elif tag == "td" and "kpi" in classes and self.in_kpis:
            self.kpi = {}
        elif tag == "div" and self.kpi is not None and classes & {"v", "l", "d"}:
            self._start_capture("kpi-" + sorted(classes & {"v", "l", "d"})[0])
        elif tag == "span" and "chip" in classes and self.out.status is None and any(t == "h2" for t, _ in self.stack):
            self.out.status = next((s for s in STATUSES if s in classes), None)
            self._start_capture("status")
        elif tag == "h2":
            self.seen_h2 = True
        elif tag == "p" and self.seen_h2 and not self.out.lead and not any(t == "table" for t, _ in self.stack[:-1]):
            self._start_capture("lead")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("style", "script", "title") and self.skip:
            self.skip -= 1
        if not any(t == tag for t, _ in self.stack):
            return
        while self.stack:
            closed, classes = self.stack.pop()
            if self.target is not None and len(self.stack) < self.target_depth:
                self._finish()
            if closed == "td" and "kpi" in classes and self.kpi is not None:
                if self.kpi.get("v"):
                    value = " · ".join(x for x in (self.kpi.get("v", ""), self.kpi.get("d", "")) if x)
                    self.out.facts.append((self.kpi.get("l", ""), value))
                self.kpi = None
            if closed == "table" and "kpis" in classes and self.in_kpis:
                self.in_kpis, self.kpis_done = False, True
            if closed == tag:
                break

    def handle_data(self, data: str) -> None:
        if self.target is not None and not self.skip:
            self.text.append(data)

    def _finish(self) -> None:
        value = " ".join("".join(self.text).split())
        target, self.target = self.target, None
        if target == "title":
            self.out.title = value
        elif target == "meta":
            self.out.meta = value
        elif target == "status":
            self.out.status_text = value
        elif target == "lead":
            self.out.lead = value
        elif target and target.startswith("kpi-") and self.kpi is not None:
            self.kpi[target[4:]] = value


def summarize(html: str) -> ReportSummary:
    reader = _Reader()
    reader.feed(html)
    reader.close()
    summary = reader.out
    if summary.facts:
        summary.lead = ""  # the KPI tiles are the headline; the first paragraph is detail
    return summary
