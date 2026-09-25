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
"""Report languages: a language per schedule and the language each run used.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # "" = each tenant's own report language (tenant profile), falling back to the installation default.
    op.add_column("report_schedules", sa.Column("language", sa.String(length=8), nullable=False, server_default=""))
    op.add_column("report_runs", sa.Column("language", sa.String(length=8), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("report_runs") as batch:
        batch.drop_column("language")
    with op.batch_alter_table("report_schedules") as batch:
        batch.drop_column("language")
