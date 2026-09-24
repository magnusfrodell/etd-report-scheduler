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
"""Partner brands for reports and e-mails.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "brands",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("logo_type", sa.String(length=20), nullable=True),
        sa.Column("logo_b64", sa.Text(), nullable=True),
        sa.Column("primary_color", sa.String(length=7), nullable=False, server_default="#0f2a43"),
        sa.Column("accent_color", sa.String(length=7), nullable=False, server_default="#1f77b4"),
        sa.Column("footer_text", sa.Text(), nullable=True),
        sa.Column("subject_prefix", sa.String(length=60), nullable=True),
        sa.Column("sender_name", sa.String(length=120), nullable=True),
        sa.Column("reply_to", sa.String(length=254), nullable=True),
        sa.Column("show_tool_credit", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("brands")
