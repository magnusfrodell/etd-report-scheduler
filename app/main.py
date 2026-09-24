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
"""Application entry point: ``uvicorn app.main:app``."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.config import get_config
from app.crypto import init_secret_box
from app.db import init_engine, run_migrations, session_scope
from app.logging_config import setup_logging
from app.quality import encryption_key_problem
from app.scheduler import scheduler
from app.services import recover_interrupted_runs
from app.web import routes_api, routes_ui
from app.web.auth import bootstrap_admin
from app.web.security import SecurityMiddleware

log = logging.getLogger(__name__)


def create_app() -> FastAPI:
    cfg = get_config()
    setup_logging(cfg.log_level)
    init_secret_box(cfg.encryption_key)
    init_engine(cfg.resolved_database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        run_migrations(cfg.resolved_database_url)
        with session_scope() as session:
            bootstrap_admin(session, cfg)
        _app.state.key_problem = encryption_key_problem()
        if _app.state.key_problem:
            log.error(_app.state.key_problem)
        interrupted = recover_interrupted_runs()
        if interrupted:
            log.warning("Marked %d report run(s) interrupted by a restart as failed", interrupted)
        if cfg.scheduler_enabled:
            scheduler.start()
        else:
            log.warning("Scheduler disabled (SCHEDULER_ENABLED=false) - nothing will run automatically")
        log.info("ETD Report Scheduler %s ready (data dir %s)", __version__, cfg.data_dir)
        try:
            yield
        finally:
            scheduler.shutdown()

    app = FastAPI(title="ETD Report Scheduler", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    app.add_middleware(SecurityMiddleware, trusted_origins=cfg.trusted_origins)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")
    app.include_router(routes_api.router)
    app.include_router(routes_ui.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 303 and exc.headers and "Location" in exc.headers:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        if exc.status_code == 403 and not request.url.path.startswith("/api/"):
            # Permission problems in the UI become a flash message, not a bare JSON error.
            return RedirectResponse(f"/?err={quote(str(exc.detail))}", status_code=303)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    return app


app = create_app()
