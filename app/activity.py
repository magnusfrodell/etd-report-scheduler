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
"""The activity log: who did what in this tool, when, from where, and whether it was allowed.

Every request that changes something - through the UI or the API - is recorded by ActivityMiddleware
once it has been answered, whatever the outcome; opening an archived report is recorded too. The
object a request is about is named before the handler runs (``prepare``), so a deleted tenant still
has its name in the log. Handlers add what only they know with ``note()``. Passwords, tokens and
webhook addresses are never written - a changed secret shows as "changed"."""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.db import session_scope
from app.models import (
    ActivityEvent,
    ApiKey,
    Brand,
    ChatChannel,
    ReportRun,
    ReportSchedule,
    Tenant,
    User,
    UserSession,
)

log = logging.getLogger(__name__)

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# Handler name -> action. Every route that changes something must be listed (a test checks it);
# None means the request is not worth recording.
ACTIONS: dict[str, str | None] = {
    "login": "auth.sign_in", "logout": "auth.sign_out", "account_password": "account.password",
    "account_session_end": "session.end", "account_sessions_end_others": "session.end_others",
    "session_end": "session.end", "user_sessions_end": "session.end_user",
    "select_tenant": None,  # which tenant the header shows - a view preference, not a change
    "tenant_create": "tenant.create", "tenant_edit": "tenant.update", "tenant_profile": "tenant.profile", "tenant_test": "tenant.test",
    "tenant_collect": "tenant.collect", "tenant_toggle": "tenant.toggle", "tenant_delete": "tenant.delete",
    "tenant_grant": "access.grant", "tenant_revoke": "access.revoke",
    "schedule_create": "schedule.create", "schedule_run": "schedule.run", "schedule_toggle": "schedule.toggle",
    "schedule_delete": "schedule.delete", "report_run_now": "report.run",
    "chat_webex_token": "chat.webex_token", "chat_channel_create": "chat.channel.create", "chat_channel_test": "chat.channel.test",
    "chat_channel_delete": "chat.channel.delete", "chat_alerts": "chat.alerts",
    "branding_create": "brand.create", "branding_update": "brand.update", "branding_delete": "brand.delete",
    "settings_save": "settings.update", "settings_backup": "backup.create", "settings_test_email": "settings.test_email",
    "user_create": "user.create", "user_role": "user.role", "user_password": "user.password", "user_toggle": "user.toggle",
    "user_delete": "user.delete",
    "api_collect": "tenant.collect", "api_logs": "tenant.collect_logs", "api_backfill": "tenant.backfill", "api_run_report": "report.run",
    "account_api_key_create": "api_key.create", "account_api_key_revoke": "api_key.revoke",
    "user_api_key_create": "api_key.create", "api_key_revoke": "api_key.revoke",
}
# Reads that are worth a line: an archived report holds customer data, an export holds the log itself.
READ_ACTIONS: dict[str, str] = {"report_file": "report.view", "activity_export": "activity.export", "api_activity": "activity.export"}

# Path parameter -> (target type, model, attribute naming it). The last of these in the path is the target.
_TARGETS: dict[str, tuple[str, Any, str | None]] = {
    "tenant_id": ("tenant", Tenant, "name"), "schedule_id": ("schedule", ReportSchedule, None), "user_id": ("user", User, "username"),
    "brand_id": ("brand", Brand, "name"), "channel_id": ("chat_channel", ChatChannel, "name"), "run_id": ("report_run", ReportRun, None),
    "session_id": ("session", UserSession, None), "report_key": ("report", None, None), "api_key_id": ("api_key", ApiKey, "name"),
}

_note: ContextVar[dict[str, Any] | None] = ContextVar("activity_note", default=None)


def note(**values: Any) -> None:
    """Add to the current request's activity event: target, target_id, target_type, tenant_id, actor,
    actor_id, outcome ('ok' | 'failed' | 'denied') or details (merged). Does nothing outside a request."""
    current = _note.get()
    if current is None:
        return
    details = values.pop("details", None)
    current.update({k: v for k, v in values.items() if v is not None})
    if details:
        current.setdefault("details", {}).update(details)


def changes(before: dict[str, Any], after: dict[str, Any], secrets: frozenset[str] | set[str] = frozenset()) -> dict[str, Any]:
    """{'field': [old, new]} for what differs - a secret only as 'changed'."""
    out: dict[str, Any] = {}
    for key, new in after.items():
        old = before.get(key)
        if old != new:
            out[key] = "changed" if key in secrets else [old, new]
    return out


def _name(session: Any, kind: str, model: Any, attr: str | None, key: str) -> tuple[str | None, int | None]:
    """(name, tenant_id) of the object a request is about."""
    if model is None:
        from app.reports.registry import REPORTS  # late: the registry imports the report modules

        return (REPORTS[key].name if key in REPORTS else key), None
    try:
        obj = session.get(model, int(key))
    except (TypeError, ValueError):
        return None, None
    if obj is None:
        return None, None
    if attr:
        return str(getattr(obj, attr)), getattr(obj, "id", None) if kind == "tenant" else None
    if kind == "schedule":
        tenant = session.get(Tenant, obj.tenant_id) if obj.tenant_id else None
        return f"{obj.report_key} for {tenant.name if tenant else obj.target or 'tenants'}", obj.tenant_id
    if kind == "report_run":
        return f"{obj.report_key} #{obj.id}", obj.tenant_id
    if kind == "session":
        owner = session.get(User, obj.user_id)
        return (owner.username if owner else f"user {obj.user_id}"), None
    return None, None


def prepare(request: Request) -> None:
    """Router dependency: name the object before the handler runs - after a delete it is gone."""
    current = _note.get()
    endpoint_name = getattr(request.scope.get("endpoint"), "__name__", "")
    if current is None or (request.method not in MUTATING and endpoint_name not in READ_ACTIONS):
        return
    params = request.path_params
    keys = [k for k in params if k in _TARGETS]  # the last one that names an object: /reports/{run_id}/{fmt} is about the run
    if not keys:
        return
    key = keys[-1]
    kind, model, attr = _TARGETS[key]
    try:
        with session_scope() as session:
            name, tenant_id = _name(session, kind, model, attr, str(params[key]))
    except Exception:  # noqa: BLE001 - naming is a courtesy, never a reason to fail the request
        log.exception("Could not name the target of %s %s", request.method, request.url.path)
        name, tenant_id = None, None
    current.setdefault("target_type", kind)
    current.setdefault("target_id", str(params[key]))
    if name:
        current.setdefault("target", name[:200])
    if "tenant_id" in params:
        current.setdefault("tenant_id", int(params["tenant_id"]))
    elif tenant_id:
        current.setdefault("tenant_id", tenant_id)


def _outcome(status: int, location: str) -> tuple[str, str | None]:
    if status in (401, 403):
        return "denied", None
    if status >= 400:
        return "failed", None
    if 300 <= status < 400 and location:
        parts = urlsplit(location)
        if parts.path == "/login" and "next=" in parts.query:
            return "denied", "not signed in"
        err = parse_qs(parts.query).get("err")
        if err:
            return "failed", err[0][:300]
    return "ok", None


def record(request: Request, action: str, status: int, location: str, noted: dict[str, Any]) -> None:
    principal = getattr(request.state, "principal", None)
    outcome, message = _outcome(status, location)
    details = dict(noted.get("details") or {})
    if message and "message" not in details:
        details["message"] = message
    event = ActivityEvent(
        actor_id=noted.get("actor_id") or (principal.user.id if principal else None),
        actor=str(noted.get("actor") or (principal.user.username if principal else "anonymous"))[:120],
        ip=request.client.host if request.client else None,
        action=action,
        target_type=noted.get("target_type"),
        target_id=str(noted["target_id"])[:60] if noted.get("target_id") is not None else None,
        target=str(noted["target"])[:200] if noted.get("target") else None,
        tenant_id=noted.get("tenant_id"),
        outcome=noted.get("outcome") or outcome,
        details=details or None,
    )
    try:
        with session_scope() as session:
            session.add(event)
    except Exception:  # noqa: BLE001 - the log must never break the request it describes
        log.exception("Could not write the activity event %s", action)


def action_for(request: Request) -> str | None:
    endpoint = request.scope.get("endpoint")
    name = getattr(endpoint, "__name__", None)
    if request.method in MUTATING:
        if name in ACTIONS:
            return ACTIONS[name]
        return f"{request.method} {request.url.path}"[:60] if name else None
    return READ_ACTIONS.get(name or "")


class ActivityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        token = _note.set({})
        try:
            response = await call_next(request)
        except Exception:
            noted = _note.get() or {}
            action = action_for(request)
            if action:
                await run_in_threadpool(record, request, action, 500, "", noted)
            raise
        finally:
            noted = _note.get() or {}
            _note.reset(token)
        action = noted.get("force_action") or action_for(request)
        if action:
            await run_in_threadpool(record, request, action, response.status_code, response.headers.get("location", ""), noted)
        return response
