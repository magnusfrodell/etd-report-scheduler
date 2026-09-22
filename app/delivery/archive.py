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
"""Archive rendered reports under ``DATA_DIR/reports/<tenant>/<report>/``."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "tenant"


def archive_paths(reports_dir: Path, tenant_name: str | None, report_key: str, when: datetime, run_id: int) -> tuple[Path, Path]:
    """Unique per run: the run id is part of the name, so two runs of the same report
    for the same tenant within one second can never overwrite each other."""
    folder = reports_dir / (slugify(tenant_name) if tenant_name else "_all-tenants") / report_key
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"{when.strftime('%Y%m%d-%H%M%S')}-run{run_id}"
    return folder / f"{stem}.html", folder / f"{stem}.pdf"


def write_bytes(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)
