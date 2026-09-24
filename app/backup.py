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
"""Backups: a consistent snapshot of the SQLite database (and optionally the report archive).

``python -m app.manage backup`` writes one on demand; the scheduler writes a database-only
backup every night and keeps the newest ``backup_keep``.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from app import __version__
from app.config import get_config
from app.db import session_scope
from app.delivery import archive
from app.models import utcnow
from app.settings_store import load_settings

log = logging.getLogger(__name__)

RESTORE = """ETD Report Scheduler {version} backup, created {created} UTC

Contains: etd.db, a consistent snapshot of the database{reports}.
Not included: SECRET_KEY and ENCRYPTION_KEY. The tenant credentials and the SMTP password in the
database can only be decrypted with the ENCRYPTION_KEY the data was created with - keep it with
this backup, but not in the same place.

Restore:
1. Stop the container.
2. Replace DATA_DIR/etd.db with etd.db from this archive and delete etd.db-wal and etd.db-shm
   next to it if they exist.{restore_reports}
3. Make the files owned by the container user (uid 10001).
4. Start the container with the same ENCRYPTION_KEY and SECRET_KEY.
"""


class BackupNotSupported(RuntimeError):
    pass


def backup_dir() -> Path:
    return get_config().data_dir / "backups"


def _database_path() -> Path:
    url = get_config().resolved_database_url
    if not url.startswith("sqlite:///"):
        raise BackupNotSupported("Only the built-in SQLite database is backed up here - use pg_dump for PostgreSQL.")
    return Path(url.removeprefix("sqlite:///"))


def create_backup(dest: Path | None = None, *, with_reports: bool = False, keep: int | None = None, now: datetime | None = None) -> Path:
    """Write ``etd-backup-<time>[-full].tar.gz`` to ``dest`` and return its path.

    The database is copied with SQLite's online backup API, so the snapshot is consistent even
    while collectors are writing. ``keep`` prunes older backups of the same kind."""
    source = _database_path()
    dest = dest or backup_dir()
    dest.mkdir(parents=True, exist_ok=True)
    stamp = (now or utcnow()).strftime("%Y%m%d-%H%M%S")
    kind = "-full" if with_reports else ""
    target = dest / f"etd-backup-{stamp}{kind}.tar.gz"
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        snapshot = Path(tmp) / "etd.db"
        src, dst = sqlite3.connect(source), sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        readme = Path(tmp) / "RESTORE.txt"
        readme.write_text(RESTORE.format(
            version=__version__, created=stamp,
            reports=" and reports/, the report archive" if with_reports else "",
            restore_reports="\n   Replace DATA_DIR/reports with reports/ from this archive." if with_reports else "",
        ), encoding="utf-8")
        partial = Path(tmp) / "backup.tar.gz"
        with tarfile.open(partial, "w:gz") as tar:
            tar.add(snapshot, arcname="etd.db")
            tar.add(readme, arcname="RESTORE.txt")
            reports = get_config().reports_dir
            if with_reports and reports.is_dir():
                tar.add(reports, arcname="reports")
        os.replace(partial, target)
    if keep:
        prune(dest, keep, full=with_reports)
    log.info("Backup written to %s", target)
    return target


def prune(dest: Path, keep: int, *, full: bool = False) -> int:
    pattern = "etd-backup-*-full.tar.gz" if full else "etd-backup-*[0-9].tar.gz"
    backups = sorted(dest.glob(pattern), key=lambda p: p.name, reverse=True)
    for old in backups[keep:]:
        old.unlink(missing_ok=True)
    return max(0, len(backups) - keep)


def nightly_backup() -> Path | None:
    with session_scope() as session:
        keep = load_settings(session).backup_keep
    if keep <= 0:
        return None
    try:
        return create_backup(keep=keep)
    except BackupNotSupported as exc:
        log.info("Nightly backup skipped: %s", exc)
    except Exception:  # noqa: BLE001
        log.exception("Nightly backup failed")
    return None


def storage_summary() -> dict:
    """Sizes for the Settings page: report archive, database and the newest backups."""
    cfg = get_config()
    try:
        db = _database_path()
        database = sum(p.stat().st_size for p in (db, Path(f"{db}-wal")) if p.exists())
    except BackupNotSupported:
        database = None
    folder = backup_dir()
    backups = sorted(folder.glob("etd-backup-*.tar.gz"), key=lambda p: p.name, reverse=True) if folder.is_dir() else []
    return {
        "reports": archive.usage(cfg.reports_dir),
        "database_bytes": database,
        "backup_dir": str(folder),
        "backups": [{"name": b.name, "bytes": b.stat().st_size} for b in backups[:5]],
        "backup_count": len(backups),
    }
