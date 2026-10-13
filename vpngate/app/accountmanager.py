"""Persistence and secrets for custom SoftEther accounts (port of AccountManager.swift).

Secrets (password, certificate, private key, proxy password) live in the keyring only, never in
accounts.json. A damaged or newer accounts.json is never overwritten (kept as
accounts.json.corrupt-<date>).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime

from ..core.clientaccount import ClientAccount
from . import keyring
from .events import Event
from .paths import support_file


def _keychain_key(account: ClientAccount, suffix: str) -> str:
    return f"account-{account.id}-{suffix}"


class AccountManager:
    def __init__(self, file_url: str | None = None) -> None:
        self.fileURL = file_url or support_file("accounts.json")
        self.accounts: list[ClientAccount] = []
        self.load_notice: str | None = None
        self.changed = Event()
        self.load_accounts()

    def _notify(self) -> None:
        self.changed.emit()

    def load_accounts(self) -> None:
        """Never overwrites what it cannot read: an unreadable file is set aside first."""
        self.load_notice = None
        try:
            with open(self.fileURL) as f:
                data = f.read()
        except OSError:
            self.accounts = []
            self._notify()
            return
        try:
            records = json.loads(data)
        except ValueError:
            kept = self._set_aside(move=True)
            self.accounts = []
            self.load_notice = ("The saved connection settings could not be read"
                                + (f" (kept as {kept})." if kept else "."))
            self._notify()
            return
        if not isinstance(records, list):
            kept = self._set_aside(move=True)
            self.accounts = []
            self.load_notice = ("The saved connection settings could not be read"
                                + (f" (kept as {kept})." if kept else "."))
            self._notify()
            return
        accounts: list[ClientAccount] = []
        for record in records:
            try:
                accounts.append(ClientAccount.from_json(record))
            except Exception:
                continue  # a bad record never fails the whole list
        if len(accounts) < len(records):
            kept = self._set_aside(move=False)
            skipped = len(records) - len(accounts)
            self.load_notice = (f"{skipped} saved connection setting(s) could not be read and "
                                f"were skipped" + (f" (original kept as {kept})." if kept else "."))
        self.accounts = accounts
        self._migrate_proxy_passwords()
        self._notify()

    def _set_aside(self, move: bool) -> str | None:
        stamp = datetime.now().isoformat(timespec="seconds").replace(":", "-")
        dest = self.fileURL + f".corrupt-{stamp}"
        try:
            if os.path.exists(dest):
                os.remove(dest)
            if move:
                os.replace(self.fileURL, dest)
            else:
                with open(self.fileURL) as src, open(dest, "w") as dst:
                    dst.write(src.read())
            return os.path.basename(dest)
        except OSError:
            return None

    def _migrate_proxy_passwords(self) -> None:
        """An older file may still hold a proxy password in clear text: move it to the keyring."""
        changed = False
        for acc in self.accounts:
            pw = acc.proxy.password
            if pw:
                keyring.set(_keychain_key(acc, "proxypw"), pw)
                acc.proxy.password = None
                changed = True
        if changed:
            self.save_accounts()

    def save_accounts(self) -> None:
        try:
            data = json.dumps([a.to_json() for a in self.accounts], indent=1)
            tmp = self.fileURL + ".tmp"
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, self.fileURL)
        except OSError:
            pass

    def add(self, account: ClientAccount, password: str | None = None,
            cert_der: bytes | None = None, private_key_der: bytes | None = None) -> None:
        stored = account
        self._save_secrets(stored, password, cert_der, private_key_der)
        self.accounts.append(stored)
        self.save_accounts()
        self._notify()

    def update(self, account: ClientAccount, password: str | None = None,
               cert_der: bytes | None = None, private_key_der: bytes | None = None) -> None:
        for idx, existing in enumerate(self.accounts):
            if existing.id == account.id:
                updated = account
                updated.updatedAt = time.time()
                self._save_secrets(updated, password, cert_der, private_key_der)
                self.accounts[idx] = updated
                self.save_accounts()
                self._notify()
                return

    def duplicate(self, account: ClientAccount) -> None:
        copy = ClientAccount.from_json(account.to_json())
        copy.id = str(uuid.uuid4())
        copy.name = f"{account.name} (Copy)"
        copy.createdAt = time.time()
        copy.updatedAt = time.time()
        copy.proxy.password = self.proxy_password(account)
        self._save_secrets(copy, self.password(account), self.certificate(account),
                           self.private_key(account))
        self.accounts.append(copy)
        self.save_accounts()
        self._notify()

    def delete(self, account: ClientAccount) -> None:
        self.accounts = [a for a in self.accounts if a.id != account.id]
        self._clear_secrets(account)
        self.save_accounts()
        self._notify()

    # MARK: keyring secrets

    def password(self, account: ClientAccount) -> str | None:
        return keyring.get(_keychain_key(account, "pw"))

    def certificate(self, account: ClientAccount) -> bytes | None:
        return keyring.get_data(_keychain_key(account, "cert"))

    def private_key(self, account: ClientAccount) -> bytes | None:
        return keyring.get_data(_keychain_key(account, "key"))

    def proxy_password(self, account: ClientAccount) -> str | None:
        return keyring.get(_keychain_key(account, "proxypw"))

    def has_certificate_identity(self, account: ClientAccount) -> bool:
        return self.certificate(account) is not None and self.private_key(account) is not None

    def _save_secrets(self, account: ClientAccount, password: str | None,
                      cert_der: bytes | None, private_key_der: bytes | None) -> None:
        if password:
            keyring.set(_keychain_key(account, "pw"), password)
        if cert_der:
            keyring.set_data(_keychain_key(account, "cert"), cert_der)
        if private_key_der:
            keyring.set_data(_keychain_key(account, "key"), private_key_der)
        if account.proxy.password:
            keyring.set(_keychain_key(account, "proxypw"), account.proxy.password)
        account.proxy.password = None
        if account.authType != "User Certificate":  # no stale key material for password accounts
            keyring.delete(_keychain_key(account, "cert"))
            keyring.delete(_keychain_key(account, "key"))

    def _clear_secrets(self, account: ClientAccount) -> None:
        for suffix in ("pw", "cert", "key", "proxypw"):
            keyring.delete(_keychain_key(account, suffix))