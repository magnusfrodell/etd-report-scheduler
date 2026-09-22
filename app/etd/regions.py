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
"""ETD regional API endpoints (see https://developer.cisco.com/docs/message-search-api/)."""

from __future__ import annotations

REGIONS: dict[str, dict[str, str]] = {
    "us": {"label": "Americas", "base_url": "https://api.us.etd.cisco.com"},
    "de": {"label": "Europe", "base_url": "https://api.de.etd.cisco.com"},
    "au": {"label": "Australia", "base_url": "https://api.au.etd.cisco.com"},
    "in": {"label": "India", "base_url": "https://api.in.etd.cisco.com"},
    "ae": {"label": "UAE", "base_url": "https://api.ae.etd.cisco.com"},
    # Beta environment for accounts enrolled in the ETD beta programme.
    "beta": {"label": "Beta", "base_url": "https://api.beta.etd.cisco.com"},
}


def base_url_for(region: str) -> str:
    try:
        return REGIONS[region]["base_url"]
    except KeyError as exc:
        raise ValueError(f"Unknown ETD region {region!r}; expected one of {', '.join(REGIONS)}") from exc
