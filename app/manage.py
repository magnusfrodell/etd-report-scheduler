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
"""Break-glass command line for user management, e.g. when every admin is locked out::

    docker exec etd-report-scheduler python -m app.manage list-users
    docker exec etd-report-scheduler python -m app.manage reset-password admin 'NewSecret123'
    docker exec etd-report-scheduler python -m app.manage create-user ops --role tenant_admin --password 'Secret123'
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import func, select

from app.config import get_config
from app.crypto import init_secret_box
from app.db import init_engine, run_migrations, session_scope
from app.models import GLOBAL_ROLES, User
from app.web.auth import hash_password, validate_new_password


def _init() -> None:
    cfg = get_config()
    init_secret_box(cfg.encryption_key)
    init_engine(cfg.resolved_database_url)
    run_migrations(cfg.resolved_database_url)


def list_users() -> list[User]:
    with session_scope() as s:
        return list(s.execute(select(User).order_by(User.username)).scalars())


def reset_password(username: str, password: str) -> User:
    if err := validate_new_password(password):
        raise ValueError(err)
    with session_scope() as s:
        user = s.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none()
        if user is None:
            raise ValueError(f"No user named {username!r}")
        user.password_hash = hash_password(password)
        user.enabled = True
        return user


def create_user(username: str, password: str, role: str = "user", display_name: str = "") -> User:
    if role not in GLOBAL_ROLES:
        raise ValueError(f"role must be one of {', '.join(GLOBAL_ROLES)}")
    if err := validate_new_password(password):
        raise ValueError(err)
    with session_scope() as s:
        if s.execute(select(User).where(func.lower(User.username) == username.lower())).scalar_one_or_none():
            raise ValueError(f"User {username!r} already exists")
        user = User(username=username.lower(), display_name=display_name, password_hash=hash_password(password), role=role, enabled=True)
        s.add(user)
        s.flush()
        return user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage", description="ETD Report Scheduler user management")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-users", help="List users and roles")
    rp = sub.add_parser("reset-password", help="Set a new password and re-enable the user")
    rp.add_argument("username")
    rp.add_argument("password")
    bp = sub.add_parser("backup", help="Write a consistent backup of the database (optionally with the report archive)")
    bp.add_argument("--dest", type=Path, default=None, help="folder for the backup (default DATA_DIR/backups)")
    bp.add_argument("--with-reports", action="store_true", help="include the report archive")
    bp.add_argument("--keep", type=int, default=None, help="keep only the newest N backups of this kind")
    cu = sub.add_parser("create-user", help="Create a user")
    cu.add_argument("username")
    cu.add_argument("--password", required=True)
    cu.add_argument("--role", default="user", choices=GLOBAL_ROLES)
    cu.add_argument("--display-name", default="")
    args = parser.parse_args(argv)

    _init()
    try:
        if args.command == "list-users":
            for u in list_users():
                print(f"{u.username:<24} {u.role:<13} {'enabled' if u.enabled else 'disabled':<9} last login {u.last_login_at or '-'}")
        elif args.command == "reset-password":
            u = reset_password(args.username, args.password)
            print(f"Password reset for {u.username}; existing sessions are signed out.")
        elif args.command == "backup":
            from app.backup import create_backup

            print(create_backup(args.dest, with_reports=args.with_reports, keep=args.keep))
        elif args.command == "create-user":
            u = create_user(args.username, args.password, args.role, args.display_name)
            print(f"Created {u.username} with role {u.role}.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
