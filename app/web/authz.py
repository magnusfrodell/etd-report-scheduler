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
"""Authorization.

Global roles:    admin  > tenant_admin > user
Per-tenant roles: manager > operator > viewer   (rows in ``tenant_grants``)

``admin`` and ``tenant_admin`` implicitly hold ``manager`` on every tenant and may
run cross-tenant reports; only ``admin`` manages users and settings. Every route
asks the :class:`Principal` - there is no other place where permissions live.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Tenant, TenantGrant, User
from app.web.auth import user_from_session

ROLE_LEVELS = {"viewer": 1, "operator": 2, "manager": 3}


@dataclass
class Principal:
    user: User
    grants: dict[int, str]  # tenant_id -> role

    # ---------------------------------------------------------------- global
    @property
    def is_admin(self) -> bool:
        return self.user.role == "admin"

    @property
    def is_tenant_admin(self) -> bool:
        return self.user.role in ("admin", "tenant_admin")

    @property
    def can_manage_users(self) -> bool:
        return self.is_admin

    @property
    def can_edit_settings(self) -> bool:
        return self.is_admin

    @property
    def can_create_tenants(self) -> bool:
        return self.is_tenant_admin

    @property
    def can_cross_tenant(self) -> bool:
        return self.is_tenant_admin

    # ------------------------------------------------------------ per tenant
    def tenant_level(self, tenant_id: int | None) -> int:
        if self.is_tenant_admin:
            return ROLE_LEVELS["manager"]
        if tenant_id is None:
            return 0
        return ROLE_LEVELS.get(self.grants.get(tenant_id, ""), 0)

    def tenant_role(self, tenant_id: int) -> str | None:
        if self.is_tenant_admin:
            return "manager"
        return self.grants.get(tenant_id)

    def can(self, tenant_id: int | None, role: str) -> bool:
        return self.tenant_level(tenant_id) >= ROLE_LEVELS[role]

    def visible_tenants(self, db: Session) -> list[Tenant]:
        stmt = select(Tenant).order_by(Tenant.name)
        if not self.is_tenant_admin:
            if not self.grants:
                return []
            stmt = stmt.where(Tenant.id.in_(list(self.grants)))
        return list(db.execute(stmt).scalars())

    def visible_tenant_ids(self, db: Session) -> list[int]:
        return [t.id for t in self.visible_tenants(db)]

    def tenants_where(self, db: Session, role: str) -> list[Tenant]:
        return [t for t in self.visible_tenants(db) if self.can(t.id, role)]


def build_principal(db: Session, user: User) -> Principal:
    grants = {g.tenant_id: g.role for g in db.execute(select(TenantGrant).where(TenantGrant.user_id == user.id)).scalars()}
    return Principal(user=user, grants=grants)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    user = user_from_session(db, request)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        raise HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": f"/login?next={request.url.path}"})
    return build_principal(db, user)


def forbid(message: str = "You do not have permission to do that.") -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, message)


def ensure(principal: Principal, tenant_id: int | None, role: str) -> None:
    if not principal.can(tenant_id, role):
        raise forbid(f"This action needs the '{role}' role on the tenant.")


def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_admin:
        raise forbid("Only administrators can do that.")
    return principal


def require_tenant_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_tenant_admin:
        raise forbid("Only administrators and tenant administrators can do that.")
    return principal
