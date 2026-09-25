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
"""Demo mode: invented tenants served by a simulated ETD API, e-mails kept in an outbox.

Start the container with ``DEMO_MODE=true`` on its own, empty data volume. Nothing in demo mode
talks to Cisco's API or to a mail relay.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

log = logging.getLogger(__name__)


def activate(app: Any) -> None:
    """Send every ETD call to the simulator, answer DNS for the demo domains, seed an empty
    database and collect its history in the background."""
    from app.demo import seed
    from app.demo.scenario import dns_records
    from app.demo.simulator import simulator
    from app.etd import client as etd_client
    from app.etd import factory
    from app.reports import domains

    factory.transport_factory = simulator.transport_for
    etd_client.limiter_for = lambda key, per_second=2.0: etd_client.RateLimiter(0)  # no need to pace a simulator
    records, real_lookup = dns_records(), domains.resolve_txt
    domains.resolve_txt = lambda name: list(records.get(name, [])) if name in records or name.endswith(".example") else real_lookup(name)
    seeded = seed.seed_demo()
    app.state.demo_warming = True

    def warm() -> None:
        try:
            seed.warm_up(fill_archive=seeded)
        except Exception:  # noqa: BLE001 - the demo must come up even if the warm-up fails
            log.exception("Demo mode: warm-up failed")
        finally:
            app.state.demo_warming = False

    threading.Thread(target=warm, name="demo-warm-up", daemon=True).start()
