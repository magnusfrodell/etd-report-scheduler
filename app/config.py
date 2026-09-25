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
"""Process-level configuration.

Everything that must exist *before* the database is available lives here and
is read from environment variables (or a ``.env`` file). Everything that an
operator may change at runtime (SMTP, timezone, retention, ...) is stored in
the database instead - see :mod:`app.settings_store`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Environment-driven configuration.

    Required:
      SECRET_KEY       - signs the session cookie of the admin UI
      ENCRYPTION_KEY   - Fernet key used to encrypt tenant credentials at rest
      ADMIN_PASSWORD   - password for the single built-in admin user
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    secret_key: str = Field(..., min_length=16)
    encryption_key: str = Field(..., min_length=32)
    admin_password: str = Field(..., min_length=8)
    admin_username: str = "admin"

    data_dir: Path = Path("./data")
    database_url: str | None = None

    log_level: str = "INFO"
    http_timeout: float = 30.0
    scheduler_enabled: bool = True
    session_max_age_seconds: int = 12 * 3600
    cookie_secure: bool = False  # set true behind an HTTPS reverse proxy
    demo_mode: bool = False  # invented tenants from a simulated ETD API; e-mails go to DATA_DIR/demo-outbox
    trusted_origins: str = ""  # extra origins allowed to submit forms, e.g. behind a proxy that rewrites Host

    @field_validator("log_level")
    @classmethod
    def _upper(cls, value: str) -> str:
        return value.upper()

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'etd.db').as_posix()}"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    cfg = AppConfig()  # type: ignore[call-arg]
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    return cfg


def reset_config_cache() -> None:
    """Used by the test-suite when environment variables change."""
    get_config.cache_clear()
