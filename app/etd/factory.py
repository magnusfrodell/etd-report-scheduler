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
"""Create an :class:`ETDClient` for a stored tenant."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from app.crypto import secret_box
from app.etd.client import ETDClient
from app.models import Tenant

# Tests (or a future mock mode) can swap this for a factory returning a mocked transport.
transport_factory: Callable[[Tenant], httpx.BaseTransport | None] = lambda tenant: None  # noqa: E731


def client_for_tenant(tenant: Tenant, timeout: float = 30.0) -> ETDClient:
    box = secret_box()
    return ETDClient(
        region=tenant.region,
        client_id=tenant.client_id,
        client_secret=box.decrypt(tenant.client_secret_enc) or "",
        api_key=box.decrypt(tenant.api_key_enc) or "",
        timeout=timeout,
        transport=transport_factory(tenant),
    )
