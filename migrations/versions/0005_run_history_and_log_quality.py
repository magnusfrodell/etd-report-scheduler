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
"""Run history and log quality.

Report runs record what triggered them and any delivery problem; log files record
unreadable lines, so partial files are visible instead of silently complete.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report_runs", sa.Column("triggered_by", sa.String(length=16), nullable=True))
    op.add_column("report_runs", sa.Column("delivery_error", sa.Text(), nullable=True))
    op.execute("UPDATE report_runs SET triggered_by = CASE WHEN schedule_id IS NULL THEN 'manual' ELSE 'schedule' END")
    op.add_column("log_files", sa.Column("parse_errors", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("log_files", sa.Column("status", sa.String(length=12), nullable=False, server_default="ok"))


def downgrade() -> None:
    with op.batch_alter_table("log_files") as batch:
        batch.drop_column("status")
        batch.drop_column("parse_errors")
    with op.batch_alter_table("report_runs") as batch:
        batch.drop_column("delivery_error")
        batch.drop_column("triggered_by")
