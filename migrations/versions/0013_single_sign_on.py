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
"""Single sign-on: the identity provider's id per user and the sign-in method per session.

Revision ID: 0013
Revises: 0012
"""

import sqlalchemy as sa
from alembic import op

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("sso_id", sa.String(length=400), nullable=True))
    op.create_index("ix_users_sso_id", "users", ["sso_id"], unique=True)
    op.add_column("user_sessions", sa.Column("auth_method", sa.String(length=16), nullable=False, server_default="password"))


def downgrade() -> None:
    with op.batch_alter_table("user_sessions") as batch:
        batch.drop_column("auth_method")
    op.drop_index("ix_users_sso_id", table_name="users")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("sso_id")
