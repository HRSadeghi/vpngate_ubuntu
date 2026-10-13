"""Secrets storage (port of Keychain.swift) — the Secret Service via secretstorage when
available, otherwise a 0600-permission file (documented fallback).

Passwords, certificates, private keys and proxy passwords are stored here only, never in
accounts.json.
"""

from __future__ import annotations

import base64
import json
import os
import threading

SERVICE = "com.yazdanifar.vpngate.linux"


class Keyring:
    """Minimal wrapper for account secrets; `service` is overridable to keep tests out of the
    user's real secret store."""

    def __init__(self, service: str = SERVICE) -> None:
        self.service = service
        self._secretstorage = None
        self._fallback_path = os.path.expanduser("~/.local/share/vpngate/secrets.json")
        self._lock = threading.Lock()
        try:
            import secretstorage  # type: ignore
            self._secretstorage = secretstorage
        except Exception:
            self._secretstorage = None

    # MARK: Secret Service backend

    def _collection(self):
        if self._secretstorage is None:
            return None
        try:
            bus = self._secretstorage.dbus_init()
            collection = self._secretstorage.get_default_collection(bus)
            if collection.is_locked():
                if not collection.unlock():
                    return None
            return collection
        except Exception:
            return None

    def _ss_search(self, account: str):
        collection = self._collection()
        if collection is None:
            return None
        try:
            for item in collection.get_all_items():
                attrs = item.get_attributes()
                if attrs.get("service") == self.service and attrs.get("account") == account:
                    return item
        except Exception:
            return None
        return None

    def _ss_get(self, account: str) -> bytes | None:
        item = self._ss_search(account)
        if item is None:
            return None
        try:
            return item.get_secret()
        except Exception:
            return None

    def _ss_set(self, account: str, data: bytes) -> bool:
        try:
            collection = self._collection()
            if collection is None:
                return False
            existing = self._ss_search(account)
            attributes = {"service": self.service, "account": account}
            if existing is not None:
                existing.set_secret(data)
            else:
                collection.create_item(account, attributes, data)
            return True
        except Exception:
            return False

    def _ss_delete(self, account: str) -> bool:
        item = self._ss_search(account)
        if item is None:
            return False
        try:
            item.delete()
            return True
        except Exception:
            return False

    # MARK: file fallback backend

    def _file_read(self) -> dict:
        try:
            with open(self._fallback_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _file_write(self, values: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self._fallback_path), exist_ok=True)
            fd = os.open(self._fallback_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(values, f)
            os.chmod(self._fallback_path, 0o600)
        except OSError:
            pass

    # MARK: public API

    def get_data(self, account: str) -> bytes | None:
        with self._lock:
            if self._secretstorage is not None:
                data = self._ss_get(account)
                if data is not None:
                    return data
            values = self._file_read()
            raw = values.get(account)
            if raw is not None:
                try:
                    return base64.b64decode(raw)
                except Exception:
                    return None
        return None

    def set_data(self, account: str, data: bytes) -> None:
        with self._lock:
            stored = False
            if self._secretstorage is not None and data:
                stored = self._ss_set(account, data)
            if not stored:
                values = self._file_read()
                if data:
                    values[account] = base64.b64encode(data).decode()
                else:
                    values.pop(account, None)
                self._file_write(values)

    def get(self, account: str) -> str | None:
        data = self.get_data(account)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def set(self, account: str, value: str) -> None:
        if value:
            self.set_data(account, value.encode("utf-8"))
        else:
            self.delete(account)

    def delete(self, account: str) -> None:
        with self._lock:
            if self._secretstorage is not None:
                self._ss_delete(account)
            values = self._file_read()
            if account in values:
                values.pop(account, None)
                self._file_write(values)


_default = Keyring()


def get(account: str) -> str | None:
    return _default.get(account)


def set(account: str, value: str) -> None:
    _default.set(account, value)


def get_data(account: str) -> bytes | None:
    return _default.get_data(account)


def set_data(account: str, data: bytes) -> None:
    _default.set_data(account, data)


def delete(account: str) -> None:
    _default.delete(account)