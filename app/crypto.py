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
"""Encrypt tenant credentials and SMTP passwords before they touch the database.

Generate a key once and keep it out of the image::

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:"


class SecretBox:
    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:  # pragma: no cover - configuration error
            raise ValueError("ENCRYPTION_KEY is not a valid Fernet key") from exc

    def encrypt(self, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return _PREFIX + self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not value.startswith(_PREFIX):
            # Tolerate legacy/plaintext values so an operator can fix them from the UI.
            return value
        try:
            return self._fernet.decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Stored secret cannot be decrypted with the current ENCRYPTION_KEY") from exc


_box: SecretBox | None = None


def init_secret_box(key: str) -> SecretBox:
    global _box
    _box = SecretBox(key)
    return _box


def secret_box() -> SecretBox:
    if _box is None:
        raise RuntimeError("SecretBox not initialised - call init_secret_box() first")
    return _box
