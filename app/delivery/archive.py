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

import contextlib
import logging
import re
import time
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)

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


# ------------------------------------------------------------------ removal (retention and erasure)
RUN_FILE = re.compile(r"^\d{8}-\d{6}-run(\d+)\.(?:html|pdf)$")


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def remove_files(paths: Iterable[str | None], root: Path) -> tuple[int, int]:
    """Delete archived report files. Only files inside ``root`` that are named like an archived run
    are touched. Returns (removed, failed); a file that is already gone counts as removed."""
    removed = failed = 0
    for value in paths:
        if not value:
            continue
        path = Path(value)
        if not RUN_FILE.match(path.name) or not _inside(path, root):
            log.warning("Not removing %s: not an archived report inside %s", value, root)
            failed += 1
            continue
        try:
            path.unlink(missing_ok=True)
            removed += 1
        except OSError as exc:
            log.warning("Could not remove %s: %s", value, exc)
            failed += 1
    prune_empty_dirs(root)
    return removed, failed


def prune_empty_dirs(root: Path) -> None:
    """Remove empty folders below ``root`` (never ``root`` itself)."""
    if not root.is_dir():
        return
    for folder in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        with contextlib.suppress(OSError):
            folder.rmdir()  # only succeeds when the folder is empty


def sweep_orphans(root: Path, known_run_ids: set[int], *, min_age: timedelta = timedelta(days=1), now: float | None = None) -> int:
    """Remove archived report files whose run no longer exists (versions before 0.6 kept the files
    when runs were deleted). Only ``<date>-<time>-run<id>.html|pdf`` files inside ``root`` and older
    than ``min_age`` are considered, so a report that is being written is never touched."""
    if not root.is_dir():
        return 0
    cutoff = (now if now is not None else time.time()) - min_age.total_seconds()
    removed = 0
    for path in root.rglob("*"):
        match = RUN_FILE.match(path.name)
        if not match or int(match.group(1)) in known_run_ids or not path.is_file() or not _inside(path, root):
            continue
        try:
            if path.stat().st_mtime > cutoff:
                continue
            path.unlink()
            removed += 1
        except OSError:
            continue
    if removed:
        prune_empty_dirs(root)
        log.info("Removed %d archived report file(s) that no run refers to", removed)
    return removed


def usage(root: Path, limit: int = 500_000) -> dict[str, int]:
    """Number of files and bytes below ``root``."""
    files = size = 0
    if root.is_dir():
        for path in root.rglob("*"):
            if files >= limit:
                break
            try:
                if path.is_file():
                    files += 1
                    size += path.stat().st_size
            except OSError:
                continue
    return {"files": files, "bytes": size}
