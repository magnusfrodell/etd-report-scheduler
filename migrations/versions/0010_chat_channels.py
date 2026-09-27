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
"""Chat channels: reports and alerts posted to a Webex space or a Microsoft Teams channel.

Revision ID: 0010
Revises: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_channels",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("target_enc", sa.Text(), nullable=False),
        sa.Column("target_hint", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    with op.batch_alter_table("report_schedules") as batch:
        batch.add_column(sa.Column("chat_channel_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_report_schedules_chat_channel", "chat_channels", ["chat_channel_id"], ["id"], ondelete="SET NULL")
    op.add_column("report_runs", sa.Column("chat_channel", sa.String(length=120), nullable=True))
    op.add_column("report_runs", sa.Column("chat_error", sa.String(length=500), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("report_runs") as batch:
        batch.drop_column("chat_error")
        batch.drop_column("chat_channel")
    with op.batch_alter_table("report_schedules") as batch:
        batch.drop_constraint("fk_report_schedules_chat_channel", type_="foreignkey")
        batch.drop_column("chat_channel_id")
    op.drop_table("chat_channels")
