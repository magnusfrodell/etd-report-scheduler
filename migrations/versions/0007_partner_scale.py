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
"""Partner scale: schedules for all tenants or a group, recipients per tenant, only-with-findings.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report_schedules", sa.Column("target", sa.String(length=16), nullable=False, server_default="tenant"))
    op.add_column("report_schedules", sa.Column("target_group", sa.String(length=60), nullable=True))
    op.add_column("report_schedules", sa.Column("recipient_mode", sa.String(length=16), nullable=False, server_default="fixed"))
    op.add_column("report_schedules", sa.Column("only_with_findings", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("report_runs", sa.Column("delivery_note", sa.String(length=300), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("report_runs") as batch:
        batch.drop_column("delivery_note")
    with op.batch_alter_table("report_schedules") as batch:
        batch.drop_column("only_with_findings")
        batch.drop_column("recipient_mode")
        batch.drop_column("target_group")
        batch.drop_column("target")
